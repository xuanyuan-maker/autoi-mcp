"""运行配置加载器 — 从 autoi_mcp.data 包内读取 config.json。"""

import json
import importlib.resources
from typing import Any


def _load() -> dict[str, Any]:
    with importlib.resources.open_text("autoi_mcp.data", "config.json") as f:
        return json.load(f)


# 内存缓存，优先级高于json
_ida_path_cache: str | None = None

def set_ida_path(path: str) -> None:
    """
    写入内存缓存并持久化到 data/config.json

    自动探测成功后调用，后续get_ida_path() 优先返回缓存值
    """
    global _ida_path_cache
    _ida_path_cache = path

    # 持久化
    config_path = str(
        importlib.resources.files("autoi_mcp.data").joinpath("config.json")
    )
    with open(config_path) as f:
        cfg = json.load(f)
    cfg["ida"]["path"] = path
    with open(config_path, "w") as f:
        json.dump(cfg, f, indent=4, ensure_ascii=False)

def get_ida_path() -> str | None:
    """返回 IDA 路径——内存缓存优先，其次 JSON 配置。"""
    global _ida_path_cache
    if _ida_path_cache is not None:
        return _ida_path_cache
    return _load()["ida"]["path"]


def get_ida_timeout() -> int:
    """返回单个文件 IDA 分析超时秒数。"""
    return _load()["ida"]["timeout"]


def get_max_workers() -> int:
    """返回批量扫描/分析的最大并行数。"""
    return _load()["concurrency"]["max_workers"]
