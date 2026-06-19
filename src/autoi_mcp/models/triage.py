"""
Tier 2 IDA 深度分析数据模型 - TriageReport | SinkInfo | SourceInfo | SourceSinkPath
"""

from pydantic import BaseModel
from autoi_mcp.models.binary import BinaryInfo

class SinkInfo(BaseModel):
    """
    单个危险函数调用点（sink）信息数据模型
    """
    name: str                       # 函数名
    vuln_type: str                  # 漏洞类型
    category: str                   # 分类
    locations: dict[str, list[int]] # 调用位置

class SourceInfo(BaseModel):
    """
    单个危险输入函数信息数据模型
    """
    name: str
    source_type: str
    locations: dict[str, list[int]]

class SourceSinkPath(BaseModel):
    """
    一条 source to sink 的数据流路径
    """
    source: str                     # 起始 source 函数名
    sink: str                       # 终止 sink 函数名
    path: dict[str, int]            # 途径函数
    confidence: str                 # 置信度

class TriageReport(BaseModel):
    """
    单个二进制的 IDA 深度分析报告
    """
    info: BinaryInfo
    sink: list[SinkInfo] = []
    source: list[SourceInfo] = []
    source_sink_path: list[SourceSinkPath] = []

    total_functions: int = 0
    analyzed_functions: int = 0
    analyzed_time: float = 0.0
    error: str | None = None



