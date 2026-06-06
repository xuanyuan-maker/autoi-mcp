"""ELF 二进制扫描 — 解析、识别、规则匹配、批量扫描。"""

import os
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from pwn import ELF, context

from ..models.binary import (
    BinaryInfo, FileHeader, SecurityInfo, SectionInfo, SegmentInfo, ELFSummary,
)

# ============================================================
# 规则加载
# ============================================================

def _data_path(filename: str) -> str:
    """从项目根目录的 data/ 下读取 JSON 文件。"""
    return str(Path(__file__).parent.parent.parent.parent / "data" / filename)


def load_sinks(path: str | None = None) -> dict:
    """加载危险函数字典。

    Args:
        path: JSON 文件路径，None 则使用默认 data/dangerous_sinks.json

    Returns:
        dict — 危险函数名到属性的映射
    """
    with open(path or _data_path("dangerous_sinks.json")) as f:
        return json.load(f)


def load_sources(path: str | None = None) -> list:
    """加载 CGI 输入源列表。

    Args:
        path: JSON 文件路径，None 则使用默认 data/cgi_sources.json

    Returns:
        list[str] — 输入源函数名列表
    """
    with open(path or _data_path("cgi_sources.json")) as f:
        return json.load(f)


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
    segments = []
    for seg in elf.segments:
        segments.append(SegmentInfo(
            type=seg.header.p_type, vaddr=seg.header.p_vaddr,
            memsz=seg.header.p_memsz, offset=seg.header.p_offset,
            align=seg.header.p_align,
        ))

    # 安全缓解措施
    security = SecurityInfo(
        relro=elf.relro if elf.relro else "none",
        canary=elf.canary,
        nx=elf.nx,
        pie=elf.pie,
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

    # 收集 ELF 文件
    elf_files: list[str] = []
    non_elf = 0

    if recursive:
        for root, dirs, files in os.walk(dirpath, followlinks=False):
            for name in files:
                fpath = os.path.join(root, name)
                if identify_elf(fpath):
                    elf_files.append(fpath)
                else:
                    non_elf += 1
    else:
        with os.scandir(dirpath) as it:
            for entry in it:
                if entry.is_file(follow_symlinks=False) and not entry.is_symlink():
                    fpath = os.path.join(dirpath, entry.name)
                    if identify_elf(fpath):
                        elf_files.append(fpath)
                    else:
                        non_elf += 1

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

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(process_one, f) for f in elf_files]
        for _ in as_completed(futures):
            pass

    return ELFSummary(
        total_scanned=len(elf_files) + non_elf,
        total_elf=len(binaries),
        binaries=binaries,
        errors=errors,
    )
