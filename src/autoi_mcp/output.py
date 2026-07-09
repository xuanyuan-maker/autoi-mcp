"""持久化输出层 — 工作区初始化 + 各阶段结果落盘。

职责:
  - init_workspace(): 在工作目录下创建 workspace/output_json/,供各工具持久化 JSON
  - write_stage_output(): 把某阶段完整结果写入固定契约文件名,返回绝对路径

设计:
  - 完整明细落盘(规避 agent 上下文上限),响应仅回摘要 + 文件指针
  - 三个阶段产物使用固定契约文件名,供后续 generate_report 统一读取
  - 与工具解耦:工具只依赖一个 output_dir 路径(由 init_workspace 返回)
"""

import json
from pathlib import Path
from typing import Any

# 工作区目录结构
WORKSPACE_DIRNAME = "workspace"
OUTPUT_SUBDIR = "output_json"

# 各阶段产物的规范文件名(供 generate_report 统一读取)
STAGE_FILENAMES: dict[str, str] = {
    "tier1_scan": "tier1_scan.json",
    "web_context": "web_context.json",
    "tier2_triage": "tier2_triage.json",
}


def init_workspace(base_dir: str | None = None) -> dict[str, str]:
    """在工作目录下初始化审计工作区。

    创建 <base_dir>/workspace/output_json/ 目录(已存在则复用)。

    Args:
        base_dir: 工作区根目录,默认当前工作目录(agent 的 cwd)

    Returns:
        dict:
            - workspace_dir: 工作区根目录绝对路径
            - output_dir: JSON 持久化目录绝对路径(传给各工具的 output_dir)
    """
    base = Path(base_dir).expanduser().resolve() if base_dir else Path.cwd()
    workspace_dir = base / WORKSPACE_DIRNAME
    output_dir = workspace_dir / OUTPUT_SUBDIR
    output_dir.mkdir(parents=True, exist_ok=True)
    return {
        "workspace_dir": str(workspace_dir),
        "output_dir": str(output_dir),
    }


def write_stage_output(output_dir: str, stage: str, payload: dict[str, Any]) -> str:
    """把某阶段完整结果写入 <output_dir>/<stage>.json,返回绝对路径。

    Args:
        output_dir: 输出目录(init_workspace 返回的 output_dir),不存在则自动创建
        stage: 阶段名,须在 STAGE_FILENAMES 中
        payload: 完整结果 dict(全量序列化到磁盘)

    Returns:
        写入文件的绝对路径字符串
    """
    if stage not in STAGE_FILENAMES:
        raise ValueError(f"未知阶段名: {stage},可选: {list(STAGE_FILENAMES)}")

    out_dir = Path(output_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / STAGE_FILENAMES[stage]

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    return str(out_path)
