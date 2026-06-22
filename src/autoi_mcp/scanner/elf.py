"""ELF 二进制扫描 — 解析、识别、规则匹配、批量扫描。"""

import fnmatch
import os
import json
import sys
from pathlib import Path
from pwn import ELF, context

from ..models.binary import (
    BinaryInfo, FileHeader, SecurityInfo, SectionInfo, SegmentInfo, ELFSummary,
)

# ============================================================
# 规则加载
# ============================================================
# load_sinks / load_sources 已提取到 autoi_mcp.data.loader，此处保留别名以兼容旧 import。

from autoi_mcp.data.loader import load_sinks, load_sources, load_system_filters


# ============================================================
# 单文件
# ============================================================

def identify_elf(filepath: str) -> bool:
    """读取前 4 字节魔数，判断文件是否为 ELF。

    Args:
        filepath: 文件路径

    Returns:
        True 表示 ELF 文件，False 表示非 ELF
    """
    try:
        with open(filepath, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except (OSError, PermissionError):
        return False


def parse_elf(elf_path: str) -> BinaryInfo:
    """解析单个 ELF 文件，返回 BinaryInfo。

    不含规则匹配 — 规则匹配由 match_rules() 单独做。

    Args:
        elf_path: ELF 文件路径

    Returns:
        BinaryInfo — 含文件头、节、段、符号表、安全保护信息，
        dangerous_sinks 和 input_sources 为空，需调用 match_rules() 填充
    """

    # 抑制 pwntools 日志
    context.log_level = "error"
    elf = ELF(elf_path, checksec=True)

    # 文件头
    file_header = FileHeader(
        arch=elf.arch,
        bits=elf.bits,
        endian="little" if elf.endian == "little" else "big",
        entry=elf.entry,
        elf_type="DYN" if elf.elftype == "DYN" else (
            "EXEC" if elf.elftype == "EXEC" else elf.elftype
        ),
    )

    # 节表
    sections = []
    for sec in elf.sections:
        if sec is None:
            continue
        flags = sec.header.sh_flags
        perm = "".join(
            p for flag, p in [(1, "W"), (2, "A"), (4, "E")] if flags & flag
        ) or "---"
        sections.append(SectionInfo(
            name=sec.name, addr=sec.header.sh_addr,
            size=sec.header.sh_size, perm=perm,
        ))

    # 段表
    # MIPS/ARM 等有架构特有 PT_* 类型（如 PT_MIPS_REGINFO=0x70000000），
    # pwntools 的 P_TYPE 映射表中不存在，返回 int 而非 str → 统一转为字符串
    segments = []
    for seg in elf.segments:
        p_type = seg.header.p_type
        if isinstance(p_type, int):
            p_type = f"PT_UNKNOWN_0x{p_type:08x}"
        segments.append(SegmentInfo(
            type=p_type, vaddr=seg.header.p_vaddr,
            memsz=seg.header.p_memsz, offset=seg.header.p_offset,
            align=seg.header.p_align,
        ))

    # 安全缓解措施
    # MIPS 等架构没有 NX bit 概念（无 PT_GNU_STACK），pwntools 返回 None
    # → None 视为 False（无法验证 NX 保护 = 无此保护）
    security = SecurityInfo(
        relro=elf.relro if elf.relro else "none",
        canary=elf.canary if elf.canary is not None else False,
        nx=elf.nx if elf.nx is not None else False,
        pie=elf.pie if elf.pie is not None else False,
        rpath=elf.rpath if elf.rpath else None,
        runpath=elf.runpath if elf.runpath else None,
    )

    return BinaryInfo(
        path=elf_path,
        file_header=file_header,
        security=security,
        symbols=dict(elf.symbols),
        dangerous_sinks=[],
        input_sources=[],
        sections=sections,
        segments=segments,
    )


# ============================================================
# 规则匹配
# ============================================================

def match_rules(
    binary: BinaryInfo,
    sinks: dict,
    sources: list,
) -> BinaryInfo:
    """符号 vs 规则交叉比对，原地更新 dangerous_sinks 和 input_sources。

    Args:
        binary: 待匹配的 BinaryInfo（symbols 字段已有值）
        sinks: 危险函数字典，key 为函数名
        sources: 输入源函数名列表

    Returns:
        更新后的 BinaryInfo（dangerous_sinks 和 input_sources 已填充）
    """

    lower_names = [s.lower() for s in binary.symbols.keys()]

    binary.dangerous_sinks = [n for n in sinks if n in lower_names]
    binary.input_sources = [n for n in sources if n in lower_names]

    return binary


def _should_skip(filepath: str, skip_patterns: tuple[str, ...]) -> bool:
    """检查文件路径是否匹配任一跳过模式。

    同时跳过符号链接（所有 busybox applet 都是 symlink）。
    """
    if os.path.islink(filepath):
        return True
    for pattern in skip_patterns:
        if fnmatch.fnmatch(filepath, pattern):
            return True
    return False


# ============================================================
# 风险架构检测（pwntools 在某些 MIPS 变体上会段错误）
# ============================================================

def _is_risky_elf(filepath: str) -> bool:
    """快速读取 ELF header 判断是否为 pwntools 高风险架构。

    已知问题: pwntools 在 MIPS big-endian 上解析 GOT 时会 SIGSEGV。
    """
    try:
        with open(filepath, "rb") as f:
            hdr = f.read(20)
            if hdr[:4] != b"\x7fELF":
                return False
            ei_data = hdr[5]          # 1=little, 2=big
            byte_order = "little" if ei_data == 1 else "big"
            e_machine = int.from_bytes(hdr[18:20], byte_order)
            return ei_data == 2 and e_machine == 8  # big-endian MIPS
    except OSError:
        return False


# ============================================================
# 批量扫描
# ============================================================

def scan_directory(
    dirpath: str,
    sinks: dict | None = None,
    sources: list | None = None,
    recursive: bool = True,
    max_workers: int = 4,
) -> ELFSummary:
    """批量扫描目录下的 ELF 文件，并行解析 + 规则匹配。

    Args:
        - dirpath: 要扫描的目录路径
        - sinks: 危险函数字典，None 则自动从 data/ 加载
        - sources: 输入源列表，None 则自动加载
        - recursive: 是否递归子目录
        - max_workers: 并行线程数

    Returns:
        ELFSummary — 含扫描总数、ELF 数量、解析结果、错误列表
    """

    if sinks is None:
        sinks = load_sinks()
    if sources is None:
        sources = load_sources()

    # 构建系统文件过滤模式（符号链接 + busybox + 系统库 + init）
    filters = load_system_filters()
    skip_patterns: list[str] = []
    if filters.get("skip_system_libs", True):
        skip_patterns.extend(filters.get("system_lib_patterns", ()))
    if filters.get("skip_system_binaries", True):
        skip_patterns.extend(filters.get("system_binary_patterns", ()))

    # 收集 ELF 文件
    elf_files: list[str] = []
    non_elf = 0
    skipped_system = 0

    if recursive:
        for root, dirs, files in os.walk(dirpath, followlinks=False):
            for name in files:
                fpath = os.path.join(root, name)
                if _should_skip(fpath, tuple(skip_patterns)):
                    skipped_system += 1
                    continue
                if identify_elf(fpath):
                    elf_files.append(fpath)
                else:
                    non_elf += 1
    else:
        with os.scandir(dirpath) as it:
            for entry in it:
                if entry.is_file(follow_symlinks=False):
                    fpath = os.path.join(dirpath, entry.name)
                    if _should_skip(fpath, tuple(skip_patterns)):
                        skipped_system += 1
                        continue
                    if identify_elf(fpath):
                        elf_files.append(fpath)
                    else:
                        non_elf += 1

    # 拆分安全文件（线程）与风险文件（子进程隔离）
    safe_files: list[str] = []
    risky_files: list[str] = []
    for f in elf_files:
        if _is_risky_elf(f):
            risky_files.append(f)
        else:
            safe_files.append(f)

    # 并行解析
    binaries: list[BinaryInfo] = []
    errors: list[dict] = []

    def process_one(fpath: str) -> None:
        try:
            info = parse_elf(fpath)
            info = match_rules(info, sinks, sources)
            binaries.append(info)
        except Exception as e:
            errors.append({"file": fpath, "error": str(e)})

    # 安全文件 → 线程池（低开销，大多数文件走这条路径）
    if safe_files:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = [pool.submit(process_one, f) for f in safe_files]
            for _ in as_completed(futures):
                pass

    # 风险文件（如 MIPS big-endian） → 独立子进程解析（隔离段错误）
    if risky_files:
        import subprocess as sp
        for fpath in risky_files:
            try:
                code = f'''
import sys, json
from autoi_mcp.scanner.elf import parse_elf, match_rules
try:
    info = parse_elf({fpath!r})
    info = match_rules(info, json.loads({json.dumps(sinks)!r}), json.loads({json.dumps(sources)!r}))
    print("OK", json.dumps(info.model_dump()))
except Exception as e:
    print("ERR", json.dumps({{"file": {fpath!r}, "error": str(e)}}))
'''
                r = sp.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120)
                if r.returncode == 0 and r.stdout.startswith("OK "):
                    from ..models.binary import BinaryInfo
                    data = json.loads(r.stdout[3:])
                    binaries.append(BinaryInfo.model_validate(data))
                elif r.stdout.startswith("ERR "):
                    errors.append(json.loads(r.stdout[4:]))
                else:
                    stderr = (r.stderr or "")[:200]
                    errors.append({"file": fpath, "error": f"subprocess failed (rc={r.returncode}): {stderr}"})
            except sp.TimeoutExpired:
                errors.append({"file": fpath, "error": "subprocess timeout"})
            except Exception as e:
                errors.append({"file": fpath, "error": f"subprocess error: {e}"})

    return ELFSummary(
        total_scanned=len(elf_files) + non_elf + skipped_system,
        total_elf=len(binaries),
        skipped_system=skipped_system,
        binaries=binaries,
        errors=errors,
    )
