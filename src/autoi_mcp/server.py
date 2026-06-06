"""autoi-mcp — IoT 固件二进制自动化安全审计 MCP Server.

Tier 1 (no IDA): ELF 批量扫描 → 风险评分 → 过滤高风险目标
Tier 2 (IDA):    高风险目标深度分析

启动方式:
    python -m autoi_mcp.server
    uvx autoi-mcp
"""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("autoi-mcp")

from autoi_mcp.tools import info, verify

info.register(mcp)
verify.register(mcp)


def main():
    """Console entry point for uvx / pip installation."""
    mcp.run()


if __name__ == "__main__":
    main()
