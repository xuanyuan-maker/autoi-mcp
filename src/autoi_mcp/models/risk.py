"""风险评估数据模型"""

from pydantic import BaseModel

class SinkFinding(BaseModel):
    """单个危险函数发现"""
    name: str           # 函数名，比如 "system"
    vuln_type: str      # 漏洞类型： cmd_injection | stack_overflow | format_string | buffer_overflow | path_traversal | integer_overflow
    category: str       # 分类： rce | memory | fs
    score: int          # 分数

class RiskReport(BaseModel):
    """单个二进制的风险评估报告"""
    path: str
    total_score: int
    level: str          # "high" | "medium" | "low"

    # 分类得分
    security_score: int
    sink_score: int
    source_score: int
    pattern_score: int

    # 详情
    security_flags: list[str]       # e.g. ["NX disableed", "No stack canary"]
    sinks_found: list[SinkFinding]
    sources_found: list[str]        # e.g. ["getenv". "recv"]
    patterns_found: list[str]       # e.g. ["CGI handler detected", "RPATH ser: /lib"]

    recommendation: str             # 人类可读建议

class BatchRiskReport(BaseModel):
    """批量风险评估报告，按 High / medium / low 分组，各组按分数降序。

    符号表被 strip 的 ELF 进入 no_symbols_risk，不参与高/中/低分档，
    但仍建议进入 Tier 2 IDA 深度分析。
    """
    total: int
    high_risk: list[RiskReport]
    medium_risk: list[RiskReport]
    low_risk: list[RiskReport]
    no_symbols_risk: list[RiskReport] = []

    @property
    def high_risk_count(self) -> int:
        return len(self.high_risk)

    @property
    def medium_risk_count(self) -> int:
        return len(self.medium_risk)

    @property
    def low_risk_count(self) -> int:
        return len(self.low_risk)

    @property
    def no_symbols_count(self) -> int:
        return len(self.no_symbols_risk)

