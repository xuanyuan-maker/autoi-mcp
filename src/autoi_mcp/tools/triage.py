"""Tier 2 IDA 深度分析工具 — triage_single_binary / triage_batch / triage_firmware_top20

负责对高风险二进制执行 IDA headless 深度分析，返回 source-to-sink 路径。
"""

from autoi_mcp import config
from autoi_mcp.analysis.risk import RiskScorer
from autoi_mcp.scanner.elf import scan_directory
from autoi_mcp.ida.runner import run_triage, run_triage_batch


def register(mcp):
    """向 FastMCP 注册 Tier 2 triage 工具"""

    @mcp.tool()
    async def triage_single_binary(binary_path: str) -> dict:
        """对单个 ELF 文件执行 IDA headless 深度分析。

        检测危险函数（sinks）、输入源（sources）、以及从输入到危险函数的
        调用路径，用于确认漏洞的实际可利用性。

        Args:
            binary_path: ELF 文件的绝对路径

        Returns:
            dict:
                - info: BinaryInfo (Tier 1 产物)
                - sink: list[SinkInfo] - 检测到的危险函数及调用点
                - source: list[SourceInfo] - 检测到的输入源及调用点
                - source_sink_path: list[SourceSinkPath] - source→sink 路径
                  * source: str - 输入函数名
                  * sink: str - 危险函数名
                  * path: dict[str, int] - 调用路径 {func_name: address}
                  * confidence: str - 路径置信度 ('high'/'medium'/'low')
                - total_functions: int
                - analyzed_functions: int
                - analyzed_time: float
                - error: str | None
        """
        report = await run_triage(binary_path)
        return report.model_dump()

    @mcp.tool()
    async def triage_batch(
        binary_paths: list[str],
        max_workers: int | None = None,
        timeout: int | None = None,
    ) -> dict:
        """批量对多个 ELF 文件执行 IDA 深度分析（并发）。

        用于在 Tier 1 高风险过滤后，并发分析多个目标。

        Args:
            binary_paths: ELF 文件路径列表
            max_workers: 最大并行数，None 则从 config 读取（默认 8）
            timeout: 单个文件超时秒数，None 则从 config 读取（默认 300）

        Returns:
            dict: {filepath: TriageReport}
                每个文件都会有一条记录，无论成功或失败。
                失败时 TriageReport.error 非空。
        """
        if max_workers is None:
            max_workers = config.get_max_workers()
        if timeout is None:
            timeout = config.get_ida_timeout()

        results = await run_triage_batch(
            binary_paths, max_workers=max_workers, timeout=timeout
        )
        return {k: v.model_dump() for k, v in results.items()}

    @mcp.tool()
    async def triage_firmware_top20(
        firmware_dirpath: str,
        recursive: bool = True,
        max_workers_tier2: int | None = None,
    ) -> dict:
        """一键深度分析：Tier 1 扫描 → 高风险过滤 → Tier 2 IDA 分析（Top 20）。

        自动执行完整管道：
          1. 扫描固件目录所有 ELF 文件
          2. 风险评分并过滤高风险二进制
          3. 对 Top 20 高风险目标执行 IDA 深度分析

        Args:
            firmware_dirpath: 固件解压后的根目录路径
            recursive: 是否递归子目录，默认 True
            max_workers_tier2: Tier 2 IDA 分析的最大并行数，None 则从 config 读取

        Returns:
            dict:
                - tier1_summary: dict - Tier 1 扫描摘要
                  * total_scanned: int
                  * total_elf: int
                  * high_risk_count: int
                - tier1_high_risk: list - 高风险二进制列表（Top 20）
                  * path: str
                  * total_score: int
                  * security_flags: list
                  * top_sinks: list[str]
                - tier2_results: dict[str, TriageReport] - 深度分析结果
                  * 每个二进制一条记录，失败时 error 字段非空
                - tier2_summary: dict - 汇总统计
                  * total_analyzed: int
                  * success_count: int
                  * fail_count: int
                  * total_paths_found: int
                  * high_confidence_paths: int
        """
        if max_workers_tier2 is None:
            max_workers_tier2 = config.get_max_workers()

        # ===== PHASE 1: Tier 1 扫描 + 风险评分 =====
        elf_summary = scan_directory(
            firmware_dirpath, recursive=recursive, max_workers=config.get_max_workers()
        )

        scorer = RiskScorer()
        batch_report = scorer.score_batch(elf_summary.binaries)

        # 获取 Top 20 高风险二进制
        top20_high_risk = batch_report.high_risk[:20]
        tier1_high_risk_list = [
            {
                "path": r.path,
                "total_score": r.total_score,
                "security_flags": r.security_flags,
                "top_sinks": [s.name for s in r.sinks_found[:5]],
            }
            for r in top20_high_risk
        ]

        # ===== PHASE 2: Tier 2 深度分析 =====
        target_paths = [r.path for r in top20_high_risk]

        if target_paths:
            triage_results = await run_triage_batch(
                target_paths, max_workers=max_workers_tier2
            )
        else:
            triage_results = {}

        # ===== 统计与汇总 =====
        success_count = sum(1 for r in triage_results.values() if r.error is None)
        fail_count = len(triage_results) - success_count
        total_paths_found = sum(
            len(r.source_sink_path) for r in triage_results.values() if r.error is None
        )
        high_confidence_paths = sum(
            sum(1 for p in r.source_sink_path if p.confidence == "high")
            for r in triage_results.values()
            if r.error is None
        )

        return {
            "tier1_summary": {
                "total_scanned": elf_summary.total_scanned,
                "total_elf": elf_summary.total_elf,
                "high_risk_count": batch_report.high_risk_count,
            },
            "tier1_high_risk": tier1_high_risk_list,
            "tier2_results": {k: v.model_dump() for k, v in triage_results.items()},
            "tier2_summary": {
                "total_analyzed": len(triage_results),
                "success_count": success_count,
                "fail_count": fail_count,
                "total_paths_found": total_paths_found,
                "high_confidence_paths": high_confidence_paths,
            },
        }
