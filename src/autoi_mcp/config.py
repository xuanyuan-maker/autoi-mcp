"""运行配置加载器 — 从 data/config.json 读取 IDA 路径、并发上限等。"""

import json
from pathlib import Path
from typing import Any


_CONFIG_PATH = Path(__file__).parent.parent.parent / "data" / "config.json"


def load() -> dict[str, Any]:
    """读取完整配置字典。"""
    with open(_CONFIG_PATH) as f:
        return json.load(f)


def get_ida_path() -> str | None:
    """返回 IDA 安装路径，null 表示自动探测。"""
    return load()["ida"]["path"]


def get_ida_timeout() -> int:
    """返回单个文件 IDA 分析超时秒数。"""
    return load()["ida"]["timeout"]


def get_max_workers() -> int:
    """返回批量扫描/分析的最大并行数。"""
    return load()["concurrency"]["max_workers"]
