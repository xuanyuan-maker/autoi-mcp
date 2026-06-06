"""运行配置加载器 — 从 autoi_mcp.data 包内读取 config.json。"""

import json
import importlib.resources
from typing import Any


def _load() -> dict[str, Any]:
    with importlib.resources.open_text("autoi_mcp.data", "config.json") as f:
        return json.load(f)


def get_ida_path() -> str | None:
    """返回 IDA 安装路径，null 表示自动探测。"""
    return _load()["ida"]["path"]


def get_ida_timeout() -> int:
    """返回单个文件 IDA 分析超时秒数。"""
    return _load()["ida"]["timeout"]


def get_max_workers() -> int:
    """返回批量扫描/分析的最大并行数。"""
    return _load()["concurrency"]["max_workers"]
