"""autoi-mcp — IoT 固件二进制自动化安全审计 MCP Server.

Tier 1 (no IDA): ELF 批量扫描 → 风险评分 → 过滤高风险目标
Tier 2 (IDA):    高风险目标深度分析

启动方式:
    python server.py
    mcp dev server.py
"""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("autoi-mcp")

from autoi_mcp.tools import info, verify

info.register(mcp)
verify.register(mcp)

if __name__ == "__main__":
    mcp.run()
