"""JSON 规则数据加载器 — 集中管理 data/ 目录下所有 JSON 文件的读取。

所有加载函数统一通过 importlib.resources 定位数据文件，源码和 pip install 均可用。
"""

from __future__ import annotations

import json
import importlib.resources


def data_path(filename: str) -> str:
    """返回 data/ 目录下指定文件的绝对路径字符串。

    Args:
        filename: 数据文件名，如 "dangerous_sinks.json"

    Returns:
        文件绝对路径字符串
    """
    return str(importlib.resources.files("autoi_mcp.data").joinpath(filename))


# ============================================================
# 危险函数 / 输入源
# ============================================================

def load_sinks(path: str | None = None) -> dict:
    """加载危险函数字典。

    Args:
        path: JSON 文件路径，None 则使用默认 data/dangerous_sinks.json

    Returns:
        dict — 危险函数名到属性的映射
    """
    with open(path or data_path("dangerous_sinks.json")) as f:
        return json.load(f)


def load_sources(path: str | None = None) -> list:
    """加载 CGI 输入源列表。

    Args:
        path: JSON 文件路径，None 则使用默认 data/cgi_sources.json

    Returns:
        list[str] — 输入源函数名列表
    """
    with open(path or data_path("cgi_sources.json")) as f:
        return json.load(f)


# ============================================================
# 认证关键词 / 系统过滤 / 风险权重
# ============================================================

def load_auth_keywords(path: str | None = None) -> list:
    """加载认证相关关键词列表。

    Args:
        path: JSON 文件路径，None 则使用默认 data/auth_keywords.json

    Returns:
        list[str] — 认证关键词
    """
    with open(path or data_path("auth_keywords.json")) as f:
        return json.load(f)


def load_system_filters(path: str | None = None) -> dict:
    """加载系统库/二进制过滤规则。

    Args:
        path: JSON 文件路径，None 则使用默认 data/system_filters.json

    Returns:
        dict — 含 skip_system_libs, system_lib_patterns 等字段
    """
    with open(path or data_path("system_filters.json")) as f:
        return json.load(f)


def load_risk_weights(path: str | None = None) -> dict:
    """加载风险评分权重。

    Args:
        path: JSON 文件路径，None 则使用默认 data/risk_weights.json

    Returns:
        dict — 含 security, patterns, source_bonus, thresholds 等字段
    """
    with open(path or data_path("risk_weights.json")) as f:
        return json.load(f)
