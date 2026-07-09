"""Phase 0 工作区初始化 — init_workspace。

在 agent 工作目录下创建 workspace/output_json/,返回 output_dir,
供后续 scan_firmware / scan_web_context / triage_* 工具持久化 JSON。
"""

from autoi_mcp.output import init_workspace as _init_workspace


def register(mcp):
    """向 FastMCP 注册工作区初始化工具。"""

    @mcp.tool()
    def init_workspace(base_dir: str | None = None) -> dict:
        """初始化审计工作区,返回后续工具持久化输出所需的 output_dir。

        在工作目录下创建 workspace/output_json/ 目录结构。之后调用
        scan_firmware / scan_web_context / triage_firmware_top20 时,把返回的
        output_dir 作为它们的 output_dir 参数传入,即可把完整结果落盘。

        Args:
            base_dir: 工作区根目录,默认当前工作目录(agent 的 cwd)

        Returns:
            dict:
                - workspace_dir: 工作区根目录绝对路径
                - output_dir: JSON 持久化目录绝对路径(传给各工具的 output_dir)
                - hint: 使用提示
        """
        paths = _init_workspace(base_dir)
        paths["hint"] = (
            "把 output_dir 作为 scan_firmware / scan_web_context / "
            "triage_firmware_top20 的 output_dir 参数传入以持久化完整结果。"
        )
        return paths
