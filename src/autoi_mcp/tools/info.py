"""Tier 1 固件信息收集 — 一键扫描目录，返回完整 Tier 1 报告。"""

from autoi_mcp.analysis.risk import RiskScorer
from autoi_mcp.config import FirmwareAuditConfig
from autoi_mcp.scanner.elf import scan_directory


def register(mcp):

    @mcp.tool()
    def scan_firmware(
        dirpath: str,
        recursive: bool = True,
        max_workers: int = 4,
    ) -> dict:
        """扫描固件目录下所有 ELF，解析 + 规则匹配 + 风险评分，一次性返回完整 Tier 1 报告。

        内部流程：
        1. 遍历目录识别所有 ELF 文件
        2. 并行解析每个 ELF（文件头、节/段表、符号表、checksec）
        3. 符号 vs 危险函数/输入源规则交叉比对
        4. RiskScorer 打分并分类为 high / medium / low

        Args:
            dirpath: 固件解压后的根目录路径
            recursive: 是否递归子目录，默认 True
            max_workers: 并行线程数，默认 4
        """
        # 1. 扫描 + 解析 + 规则匹配
        summary = scan_directory(
            dirpath, recursive=recursive, max_workers=max_workers
        )

        # 2. 风险评分（系统库和系统二进制自动跳过）
        config = FirmwareAuditConfig()
        skip = ()
        if config.skip_system_libs:
            skip += config.system_lib_patterns
        if config.skip_system_binaries:
            skip += config.system_binary_patterns
        scorer = RiskScorer(skip_patterns=skip)
        batch = scorer.score_batch(summary.binaries)
        skipped = summary.total_elf - batch.total

        # 3. 格式化输出
        def _fmt(report):
            return {
                "path": report.path,
                "total_score": report.total_score,
                "security_score": report.security_score,
                "sink_score": report.sink_score,
                "source_score": report.source_score,
                "pattern_score": report.pattern_score,
                "security_flags": report.security_flags,
                "sinks_found": [s.model_dump() for s in report.sinks_found],
                "sources_found": report.sources_found,
                "patterns_found": report.patterns_found,
                "recommendation": report.recommendation,
            }

        return {
            "scan_summary": {
                "total_scanned": summary.total_scanned,
                "total_elf": summary.total_elf,
                "skipped_system_libs": skipped,
                "total_errors": len(summary.errors),
            },
            "risk_summary": {
                "total": batch.total,
                "high_risk": batch.high_risk_count,
                "medium_risk": batch.medium_risk_count,
                "low_risk": batch.low_risk_count,
            },
            "high_risk": [_fmt(r) for r in batch.high_risk],
            "medium_risk": [_fmt(r) for r in batch.medium_risk],
            "low_risk": [_fmt(r) for r in batch.low_risk],
            "errors": summary.errors,
        }
