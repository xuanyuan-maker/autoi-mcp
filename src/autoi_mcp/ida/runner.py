"""
IDARunner - 异步 headless IDA 调用，含自动探测

负责：
    1. IDA 路径自动探测 + 持久化
    2. 为 triage_script.py 准备输入
    3. asyncio.subprocess 调起 headless IDA
    4. 解析输出 JSON -> Pydantic TriageReport
    5. 并发批量入口 run_triage_batch

自包含，不依赖于 autoi_mcp 以外的第三方包
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import tempfile
import time

from autoi_mcp import config
from autoi_mcp.models.triage import TriageReport
from autoi_mcp.scanner.elf import parse_elf, match_rules
from autoi_mcp.data.loader import load_sinks, load_sources, data_path

# ============================================
# IDA 路径自动探测
# ============================================
# 仅 headless 文本模式可执行文件（idat/idat64）；
# GUI 版 ida/ida64 在 -A 模式下仍可能弹窗卡住，不可用于自动化分析。
_IDA_CANDIDATES: list[str] = [
    "idat64", "idat"
]

_IDA_COMMON_DIRS: list[str] = [
    "/opt/ida-pro/",
    "/opt/idapro",
    "/opt/ida",
    os.path.expanduser("~/ida-pro"),
    os.path.expanduser("~/idapro"),
    os.path.expanduser("~/ida")
]

def _find_ida_binary() -> str|None:
    """
    按照如下优先级自动探测 IDA headless 可执行文件路径：
        1. 从 config.json 中读取已经持久化的路径
        2. 从 PATH 中搜索 idat64 | idat
        3. 从常见安装目录中搜索 idat64 | idat

    注意：只探测 headless 文本模式（idat/idat64），不使用 GUI 版 ida/ida64。

    Returns:
        可执行程序的绝对路径，如果找不到返回 None
    """

    # 1. config.json 持久化路径
    cached = config.get_ida_path()
    # 如果可在 config.json 中读取到，且该文件可执行
    if cached and os.path.isfile(cached) and os.access(cached, os.X_OK):
        return cached

    # 2. PATH 搜索
    for name in _IDA_CANDIDATES:
        found = shutil.which(name)
        if found:
            return found

    # 3. 常见安装目录搜索
    for dir in _IDA_COMMON_DIRS:
        if not os.path.isdir(dir):
            continue

        for name in _IDA_CANDIDATES:
            candidate = os.path.join(dir, name)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate

    return None

def detect_and_persist_ida_path() -> str:
    """
    自动探测 IDA headless 路径，命中后持久化到 config.json

    Returns:
        IDA headless 可执行程序的绝对路径

    Raises:
        FileNotFoundError：未找到 IDA 安装
    """

    path = _find_ida_binary()

    if not path:
        raise FileNotFoundError(
            "未找到 IDA headless 安装。请在 config.json 中手动设置 ida.path "
            "指向 idat / idat64，或确保 idat64 / idat 在 PATH 中"
            "（不支持 GUI 版 ida / ida64）。"
            f"已经搜索：PATH + {_IDA_COMMON_DIRS}"
        )

    config.set_ida_path(path)
    logging.getLogger(__name__).info(f"IDA path detected and persisted: {path}")
    return path

# ============================================================
# 输入准备 — 将 Tier 1 产物 + 规则打包为 triage_script 所需 JSON
# ============================================================

def _prepare_inputs(
        binary_path: str,
        tmpdir: str,
) -> tuple[str, str, str]:
    """
    准备 triage_script.py 所需的 3 个 JSON 输入路径。

    - binary_info.json: 运行时产物，现场 parse_elf + match_rules 生产，写入 tmpdir
    - sinks.json / sources.json: 静态规则，直接返回 data/ 内的真实路径，不复制

    Args:
        binary_path: 待分析 ELF 路径
        tmpdir: 临时目录路径

    Returns:
        (sinks_json_path, sources_json_path, binary_info_json_path)
    """

    info = parse_elf(binary_path)
    info = match_rules(info, load_sinks(), load_sources())

    binary_info_path = os.path.join(tmpdir, "binary_info.json")
    with open(binary_info_path, "w") as f:
        json.dump(info.model_dump(), f, indent=2, ensure_ascii=False)

    sinks_path = data_path("dangerous_sinks.json")
    sources_path = data_path("cgi_sources.json")

    return sinks_path, sources_path, binary_info_path

def _locate_triage_script() -> str:
    """返回 triage_script.py 的绝对路径（源码和 pip 安装均可使用）"""
    import importlib.resources

    return str(
        importlib.resources.files("autoi_mcp.ida").joinpath("triage_script.py")
    )

# ============================================================
# 异步 headless IDA 调用
# ============================================================
async def run_triage(
    binary_path: str,
    *,
    output_path: str | None = None,
    timeout: int | None = None,
) -> TriageReport:
    """
    对单个 ELF 二进制文件执行 IDA headless 深度分析。

    流程：
        1. 探测/确认 IDA 路径
        2. 生成 Tier 1 BinaryInfo + 定位规则 JSON
        3. asyncio.subprocess 调起 idat -A -S"triage_script.py ..."
        4. 超时保护（默认从 config.get_ida_timeout() 取）
        5. 读取输出 JSON → Pydantic TriageReport
        6. 清理临时目录（指定了 output_path 时保留产物）

    Args:
        binary_path: ELF 文件绝对路径
        output_path: 输出 JSON 路径，None 则写入临时目录内并在结束后清理；
                     指定时保留临时目录产物便于排查
        timeout:     超时时间。None 则从 config 读取

    Returns:
        TriageReport — error 字段为 None 表示分析成功。
    """

    if not os.path.isfile(binary_path):
        raise FileNotFoundError(f"Binary not found: {binary_path}")

    ida_path = detect_and_persist_ida_path()

    if timeout is None:
        timeout = config.get_ida_timeout()

    triage_script = _locate_triage_script()
    logger = logging.getLogger(__name__)

    # 临时工作目录固定在 /tmp 下
    tmpdir = tempfile.mkdtemp(prefix="autoi_triage_", dir="/tmp")
    try:
        sinks_path, sources_path, binary_info_path = _prepare_inputs(
            binary_path, tmpdir
        )

        result_json = output_path or os.path.join(tmpdir, "triage_result.json")
        ida_log = os.path.join(tmpdir, "ida_triage.log")

        # 命令行格式与 tests/test_triage_script.py 一致
        s_arg = (
            f"{triage_script} {result_json} {sinks_path} "
            f"{sources_path} {binary_info_path}"
        )
        cmd = [
            ida_path,
            "-A",
            f"-S{s_arg}",
            f"-L{ida_log}",
            binary_path,
        ]

        logger.info(
            "Launching IDA: %s -S\"...\" -L%s %s",
            ida_path, ida_log, binary_path,
        )
        t0 = time.monotonic()

        # 异步子进程执行
        proc: asyncio.subprocess.Process | None = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            logger.error("IDA timeout after %ds for %s", timeout, binary_path)
            if proc is not None:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
            return TriageReport(
                info=parse_elf(binary_path),
                error=f"IDA analysis timed out after {timeout}s",
                analyzed_time=timeout,
            )

        elapsed = time.monotonic() - t0
        logger.info(
            "IDA finished: rc=%d, elapsed=%.1fs", proc.returncode, elapsed
        )

        # 读取并解析输出
        if not os.path.isfile(result_json):
            error_detail = "No output JSON produced by IDA"
            if os.path.isfile(ida_log):
                with open(ida_log) as f:
                    tail = "".join(f.readlines()[-20:])
                error_detail += f"\nIDA log tail:\n{tail}"
            if stderr:
                stderr_tail = stderr.decode("utf-8", errors="replace")[-2000:]
                error_detail += f"\nstderr:\n{stderr_tail}"

            return TriageReport(
                info=parse_elf(binary_path),
                error=error_detail,
                analyzed_time=round(elapsed, 2),
            )

        with open(result_json) as f:
            raw = json.load(f)

        try:
            report = TriageReport.model_validate(raw)
        except Exception as e:
            raise ValueError(
                f"Triage output validation failed for {binary_path}: {e}\n"
                f"Raw keys: {list(raw.keys())}"
            ) from e

        logger.info(
            "Triage done: %d funcs, %d sinks, %d sources, %d paths, error=%s",
            report.total_functions,
            len(report.sink),
            len(report.source),
            len(report.source_sink_path),
            report.error,
        )
        return report

    finally:
        # 未指定 output_path 时清理临时目录；指定时保留产物便于排查
        if output_path is None:
            shutil.rmtree(tmpdir, ignore_errors=True)
        else:
            logger.info("Triage artifacts kept in: %s", tmpdir)


# ============================================================
# 并发批量入口
# ============================================================

async def run_triage_batch(
    paths: list[str],
    max_workers: int | None = None,
    timeout: int | None = None,
) -> dict[str, TriageReport]:
    """
    对多个 ELF 二进制并发执行 IDA 深度分析。

    Args:
        paths: ELF 文件路径列表
        max_workers: 最大并行数，None 则从 config 读取
        timeout: 单个文件超时秒数，None 则从 config 读取

    Returns:
        {filepath: TriageReport} — 无论成功或失败每条都有结果；
        失败的 TriageReport.error 非空。
    """
    if max_workers is None:
        max_workers = config.get_max_workers()

    semaphore = asyncio.Semaphore(max_workers)
    logger = logging.getLogger(__name__)

    async def _run_one(path: str) -> tuple[str, TriageReport]:
        async with semaphore:
            try:
                report = await run_triage(path, timeout=timeout)
            except Exception as e:
                report = TriageReport(
                    info=parse_elf(path),
                    error=f"Unhandled exception: {e}",
                )
            return path, report

    tasks = [_run_one(p) for p in paths]
    results: dict[str, TriageReport] = {}
    for coro in asyncio.as_completed(tasks):
        path, report = await coro
        results[path] = report
        status = "OK" if report.error is None else f"ERROR: {report.error[:80]}"
        logger.info("[batch] %s: %s", path, status)

    return results



