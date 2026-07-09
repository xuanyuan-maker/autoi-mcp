"""Tier 1 固件信息收集 — 一键扫描目录，返回完整 Tier 1 报告。"""

from autoi_mcp import config
from autoi_mcp.analysis.risk import RiskScorer
from autoi_mcp.scanner.elf import scan_directory
from autoi_mcp.output import write_stage_output


def register(mcp):

    @mcp.tool()
    def scan_firmware(
        dirpath: str,
        recursive: bool = True,
        max_workers: int = config.get_max_workers(),
        verbose: bool = False,
        top_n: int = 20,
        output_dir: str | None = None,
    ) -> dict:
        """扫描固件目录下所有 ELF，解析 + 规则匹配 + 风险评分。

        默认只返回统计摘要 + Top N 高风险详情，控制输出大小。
        设置 verbose=True 返回全部明细。

        Args:
            dirpath: 固件解压后的根目录路径
            recursive: 是否递归子目录，默认 True
            max_workers: 并行线程数，默认 4
            verbose: 是否输出全部明细，默认 False（仅摘要+Top N）
            top_n: 非 verbose 模式下返回的高/中风险 Top N 数量，默认 20
        """
        # 1. 扫描 + 解析 + 规则匹配
        summary = scan_directory(
            dirpath, recursive=recursive, max_workers=max_workers
        )

        # 2. 风险评分（系统库/二进制已在 scan_directory 中过滤跳过）
        scorer = RiskScorer()
        batch = scorer.score_batch(summary.binaries)

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

        def _fmt_short(report):
            """精简格式：仅路径 + 评分 + 关键风险信号。"""
            return {
                "path": report.path,
                "total_score": report.total_score,
                "security_flags": report.security_flags,
                "top_sinks": [s.name for s in report.sinks_found[:5]],
            }

        # 3. 构建返回结果
        scan_summary = {
            "total_scanned": summary.total_scanned,
            "total_elf": summary.total_elf,
            "skipped_system_libs": summary.skipped_system,
            "total_errors": len(summary.errors),
        }
        risk_summary = {
            "total": batch.total,
            "high_risk": batch.high_risk_count,
            "medium_risk": batch.medium_risk_count,
            "low_risk": batch.low_risk_count,
            "no_symbols": batch.no_symbols_count,
            "_no_symbols_hint": "Symbol table stripped — Tier 2 IDA deep analysis recommended.",
        }

        # 3a. 传入 output_dir 时,全量明细落盘为 tier1_scan.json
        output_file = None
        if output_dir:
            full_payload = {
                "scan_summary": scan_summary,
                "risk_summary": risk_summary,
                "high_risk": [_fmt(r) for r in batch.high_risk],
                "medium_risk": [_fmt(r) for r in batch.medium_risk],
                "low_risk": [_fmt(r) for r in batch.low_risk],
                "no_symbols": [_fmt(r) for r in batch.no_symbols_risk],
                "errors": summary.errors,
            }
            output_file = write_stage_output(output_dir, "tier1_scan", full_payload)

        # 3b. 精简响应
        result: dict = {
            "scan_summary": scan_summary,
            "risk_summary": risk_summary,
        }
        if output_file:
            result["output_file"] = output_file

        if verbose:
            result["high_risk"] = [_fmt(r) for r in batch.high_risk]
            result["medium_risk"] = [_fmt(r) for r in batch.medium_risk]
            result["low_risk"] = [_fmt(r) for r in batch.low_risk]
            result["no_symbols"] = [_fmt(r) for r in batch.no_symbols_risk]
        else:
            result["high_risk"] = [_fmt(r) for r in batch.high_risk[:top_n]]
            result["medium_risk"] = [_fmt_short(r) for r in batch.medium_risk[:top_n]]
            result["no_symbols"] = [_fmt_short(r) for r in batch.no_symbols_risk[:top_n]]
            # low_risk 默认不输出明细，仅保留计数
            if batch.high_risk_count > top_n:
                result["_truncated"] = {
                    "high_risk_showing": f"{min(top_n, batch.high_risk_count)}/{batch.high_risk_count}",
                    "medium_risk_showing": f"{min(top_n, batch.medium_risk_count)}/{batch.medium_risk_count}",
                    "hint": "Set verbose=True for full results, or increase top_n.",
                }

        result["errors"] = summary.errors
        return result
