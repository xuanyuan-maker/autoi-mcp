"""ELF 二进制风险评分 — 纯 Python，零外部依赖。

架构：
 - RiskScorer 一次性加载权重，批量评分多个二进制文件。
 - score_binary() 为主要入口函数。
 - 评分公式：安全惩罚 + 危险函数加权 + 输入源奖励 + 模式匹配加成。

可在 MCP 服务器（第一层过滤）和 IDA 脚本内部（第二层分析）中复用。
"""

import fnmatch
import json
import os
from pathlib import Path

from ..models.binary import BinaryInfo
from ..models.risk import BatchRiskReport, RiskReport, SinkFinding

# ============================================================
# 数据加载
# ============================================================

def _data_path(filename: str) -> str:
    """返回数据文件的路径字符串，源码和 pip install 均可用。"""
    import importlib.resources
    return str(importlib.resources.files("autoi_mcp.data").joinpath(filename))


def _load_sinks(path: str | None = None) -> dict:
    """加载 dangerous_sinks.json。"""
    with open(path or _data_path("dangerous_sinks.json")) as f:
        return json.load(f)


def _load_auth_keywords(path: str | None = None) -> list:
    """加载 auth_keywords.json。"""
    with open(path or _data_path("auth_keywords.json")) as f:
        return json.load(f)

# ============================================================
# RiskScorer
# ============================================================

class RiskScorer:
    """基于 JSON 可配置权重的 IoT 固件二进制风险评分器。

    用法::

        scorer = RiskScorer()
        report = scorer.score_binary(binary_info)
        batch  = scorer.score_batch(binaries)
        high   = scorer.filter_high_risk(binaries)  # 第一层过滤 → 第二层
    """

    def __init__(
        self,
        weights_path: str | None = None,
        sinks_dict: dict | None = None,
        auth_keywords: list | None = None,
        skip_patterns: tuple[str, ...] | None = None,
    ):
        """初始化评分器。

        Args:
            weights_path: risk_weights.json 路径，None 用默认
            sinks_dict:   dangerous_sinks 字典，None 自动加载
            auth_keywords: auth 关键词列表，None 自动加载
            skip_patterns: 系统库路径 glob pattern，匹配到的跳过评分
        """
        with open(weights_path or _data_path("risk_weights.json")) as f:
            self.weights = json.load(f)

        self.sinks = sinks_dict if sinks_dict is not None else _load_sinks()
        self.auth_keywords = auth_keywords if auth_keywords is not None else _load_auth_keywords()
        self.thresholds = self.weights.get("thresholds", {"high": 50, "medium": 30})
        self.skip_patterns = skip_patterns or ()

    # ----------------------------------------
    # 公开 API
    # ----------------------------------------

    def _is_system_lib(self, path: str) -> bool:
        """检查路径（含符号链接目标）是否匹配跳过 pattern。"""
        if any(fnmatch.fnmatch(path, p) for p in self.skip_patterns):
            return True
        try:
            real = os.path.realpath(path)
            if real != path:
                return any(fnmatch.fnmatch(real, p) for p in self.skip_patterns)
        except OSError:
            pass
        return False

    def score_binary(self, binary: BinaryInfo) -> RiskReport | None:
        """对单个 BinaryInfo 打分，系统库返回 None。"""
        if self._is_system_lib(binary.path):
            return None
        sec_score, sec_flags = self._score_security(binary)
        sink_score, sink_findings = self._score_sinks(binary)
        source_score = self._score_sources(binary, sink_score)
        pattern_score, patterns = self._score_patterns(binary)

        total = sec_score + sink_score + source_score + pattern_score
        level = self._classify(total)

        return RiskReport(
            path=binary.path,
            total_score=total,
            level=level,
            security_score=sec_score,
            sink_score=sink_score,
            source_score=source_score,
            pattern_score=pattern_score,
            security_flags=sec_flags,
            sinks_found=sink_findings,
            sources_found=list(binary.input_sources),
            patterns_found=patterns,
            recommendation=self._recommend(level, total),
        )

    def score_batch(self, binaries: list[BinaryInfo]) -> BatchRiskReport:
        """批量评分，系统库自动跳过。

        符号表被 strip 的 ELF 进入 no_symbols_risk，
        不参与高/中/低风险分档，但仍建议进入 Tier 2 IDA 深度分析。
        """
        # 分离无符号表的 ELF（被 strip，仅能做安全+模式评分）
        with_syms: list[BinaryInfo] = []
        no_syms: list[BinaryInfo] = []
        for b in binaries:
            if b.symbols:
                with_syms.append(b)
            else:
                no_syms.append(b)

        # 有符号表 → 正常评分分档
        reports = [self.score_binary(b) for b in with_syms]
        reports = [r for r in reports if r is not None]

        high = sorted(
            [r for r in reports if r.level == "high"],
            key=lambda r: r.total_score, reverse=True,
        )
        medium = sorted(
            [r for r in reports if r.level == "medium"],
            key=lambda r: r.total_score, reverse=True,
        )
        low = sorted(
            [r for r in reports if r.level == "low"],
            key=lambda r: r.total_score, reverse=True,
        )

        # 无符号表 → 独立列表，级别标记为 "no_symbols"，建议 Tier 2
        no_sym_reports: list[RiskReport] = []
        for b in no_syms:
            if self._is_system_lib(b.path):
                continue
            r = self.score_binary(b)
            if r is not None:
                r.level = "no_symbols"
                r.recommendation = (
                    f"Symbol table stripped (partial score={r.total_score}): "
                    "Strongly recommend Tier 2 IDA deep analysis — "
                    "no symbol-based sink/source matching possible in Tier 1."
                )
                no_sym_reports.append(r)
        no_sym_reports.sort(key=lambda r: r.total_score, reverse=True)

        return BatchRiskReport(
            total=len(reports) + len(no_sym_reports),
            high_risk=high,
            medium_risk=medium,
            low_risk=low,
            no_symbols_risk=no_sym_reports,
        )

    def filter_high_risk(self, binaries: list[BinaryInfo]) -> list[RiskReport]:
        """第一层 → 第二层过滤：只返回高风险目标。"""
        return self.score_batch(binaries).high_risk

    # ----------------------------------------
    # 评分子方法
    # ----------------------------------------

    def _score_security(self, binary: BinaryInfo) -> tuple[int, list[str]]:
        """安全缓解措施缺失评分。"""
        score = 0
        flags: list[str] = []
        sec = binary.security
        w = self.weights["security"]

        if not sec.nx:
            score += w["nx_disabled"]
            flags.append("NX disabled — executable stack")
        if not sec.canary:
            score += w["canary_disabled"]
            flags.append("No stack canary")
        if not sec.pie:
            score += w["pie_disabled"]
            flags.append("PIE disabled — no ASLR")
        if sec.relro == "none":
            score += w.get("relro_disabled", 10)
            flags.append("RELRO disabled — writable GOT")
        elif sec.relro == "Partial":
            score += w.get("relro_partial", 5)
            flags.append("Partial RELRO")

        return score, flags

    def _score_sinks(self, binary: BinaryInfo) -> tuple[int, list[SinkFinding]]:
        """危险函数符号评分 — 仅 tier1_score > 0 的函数计入总分。

        tier1_score == 0 的函数（如 printf/strcpy/memcpy）会在 sinks_found
        中记录，但不参与 Tier 1 评分 — 它们需要 Tier 2 IDA 确认调用形式。
        """
        score = 0
        findings: list[SinkFinding] = []

        for name in binary.dangerous_sinks:
            info = self.sinks.get(name, {})
            s = info.get("tier1_score", 0)
            score += s
            findings.append(SinkFinding(
                name=name,
                vuln_type=info.get("vuln_type", "unknown"),
                category=info.get("category", "unknown"),
                score=s,
            ))

        return score, findings

    def _score_sources(self, binary: BinaryInfo, sink_score: int) -> int:
        """输入源评分 — 同时存在输入源和危险函数时触发额外加分。"""
        w = self.weights.get("source_bonus", {})
        if binary.input_sources and sink_score > 0:
            return w.get("has_sources_and_sinks", 10)
        return 0

    def _score_patterns(self, binary: BinaryInfo) -> tuple[int, list[str]]:
        """启发式模式评分 — CGI 入口、auth 符号、RPATH/RUNPATH。"""
        score = 0
        patterns: list[str] = []
        w = self.weights.get("patterns", {})

        # RPATH / RUNPATH 检查
        if binary.security.rpath:
            score += w.get("rpath_set", 5)
            patterns.append(f"RPATH set: {binary.security.rpath}")
        if binary.security.runpath:
            score += w.get("runpath_set", 5)
            patterns.append(f"RUNPATH set: {binary.security.runpath}")

        # CGI handler 入口模式
        sym_lower = [s.lower() for s in binary.symbols]
        if any(s.startswith("cgi_") or s.startswith("handle_") for s in sym_lower):
            score += w.get("cgi_handler", 10)
            patterns.append("CGI handler entry point detected")

        # Auth 相关符号
        if any(kw in s for s in sym_lower for kw in self.auth_keywords):
            score += w.get("auth_symbol", 5)
            patterns.append("Auth-related symbols found")

        return score, patterns

    # ----------------------------------------
    # 辅助方法
    # ----------------------------------------

    def _classify(self, total: int) -> str:
        """按总分判定风险等级。"""
        if total >= self.thresholds.get("high", 50):
            return "high"
        elif total >= self.thresholds.get("medium", 30):
            return "medium"
        return "low"

    def _recommend(self, level: str, total: int) -> str:
        """根据风险等级生成建议。"""
        if level == "high":
            return (
                f"High risk (score={total}): Recommend deep IDA analysis — "
                "check for auth bypass, command injection, and memory corruption."
            )
        elif level == "medium":
            return (
                f"Medium risk (score={total}): Consider IDA analysis "
                "if resources permit."
            )
        return f"Low risk (score={total}): Skip IDA analysis."


# ============================================================
# 模块级便捷函数（懒加载单例）
# ============================================================

_default_scorer: RiskScorer | None = None


def _get_scorer() -> RiskScorer:
    """获取默认 RiskScorer 单例。"""
    global _default_scorer
    if _default_scorer is None:
        _default_scorer = RiskScorer()
    return _default_scorer


def score_binary(binary: BinaryInfo) -> RiskReport:
    """便捷函数：对单个 BinaryInfo 评分（使用默认评分器）。"""
    return _get_scorer().score_binary(binary)


def score_batch(binaries: list[BinaryInfo]) -> BatchRiskReport:
    """便捷函数：批量评分（使用默认评分器）。"""
    return _get_scorer().score_batch(binaries)
