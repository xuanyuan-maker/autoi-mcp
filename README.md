# autoi-mcp

![version](https://img.shields.io/badge/version-0.6.0-blue) ![license](https://img.shields.io/badge/license-MIT-green) ![python](https://img.shields.io/badge/python-%3E%3D3.12-blue)

基于 **Model Context Protocol (MCP)** 的 IoT 固件二进制自动化安全审计工具。

**参考文章**: [固件.二进制审计.claude+skils快速寻找可控点和定位漏洞点](https://mp.weixin.qq.com/s/5mKZ7D1qNoZ9BMDIlxnF6A)

## 核心特性

- **Tier 1 (秒级)**: 批量 ELF 扫描 + 风险评分 → 快速过滤高风险目标
- **Tier 2 (分钟级)**: IDA headless 深度分析 → source-to-sink 路径追踪 + 置信度分级
- **Web 上下文**: 静态关联二进制风险与 Web 入口（endpoint / 参数 / 认证边界）

## 安装

### 方式一：Claude Code CLI（推荐）

本项目已发布到 PyPI 并提供 `autoi-mcp` 命令入口，用 `uvx` 注册即可（自动拉取并运行，无需预先安装）。

**推荐：命令行一键注册**

```bash
claude mcp add autoi-mcp -- uvx autoi-mcp
```

可选参数：

- `-s user`：注册到用户级（对所有项目生效），默认 `local`（仅当前项目）。
- `-s project`：写入项目根目录 `.mcp.json`，便于团队共享。

**或：手动编辑配置文件**

编辑 `~/.claude.json`（用户级）或项目根目录 `.mcp.json`（项目级），在 `mcpServers` 中加入以下配置：

```json
{
  "mcpServers": {
    "autoi-mcp": {
      "type": "stdio",
      "command": "uvx",
      "args": ["autoi-mcp"]
    }
  }
}
```

**注册后验证与管理**

```bash
claude mcp list            # 查看已注册的 MCP server 及连接状态
claude mcp get autoi-mcp   # 查看单个 server 配置
claude mcp remove autoi-mcp
```

进入 `claude` 交互界面后，可用 `/mcp` 查看工具加载情况；工具会以 `scan_firmware`、`scan_web_context` 等名称自动可用。

> 从源码开发调试时，可改用 `claude mcp add autoi-mcp -- uv run --directory /path/to/autoi-mcp autoi-mcp`。

### 方式二：Claude Desktop

在配置文件 `~/.claude/claude_desktop_config.json` 中添加，然后重启 Claude Desktop：

```json
{
  "mcpServers": {
    "autoi-mcp": {
      "type": "stdio",
      "command": "uvx",
      "args": ["autoi-mcp"]
    }
  }
}
```

### 方式三：pip 安装

```bash
pip install autoi-mcp
```

配置同上，将 `command` 改为 `python`、`args` 改为 `["-m", "autoi_mcp.server"]` 即可。

### 方式四：源码开发

```bash
git clone <repo-url>
cd autoi-mcp
uv sync
uv run python -m autoi_mcp.server
```

---

## MCP 工具清单

### Tier 1 工具（无需 IDA）

| 工具 | 说明 |
|------|------|
| `scan_firmware` | 扫描固件目录下所有 ELF，解析 + 规则匹配 + 风险评分 + Top N 高风险 |
| `check_elf` | 单个 ELF 快速检查：安全缓解措施 + 危险符号 |

### Tier 2 工具（需要 IDA）

| 工具 | 说明 | 输入 |
|------|------|------|
| `triage_single_binary` | 单个 ELF 深度分析（source-to-sink 路径追踪） | 文件路径 |
| `triage_batch` | 批量深度分析（并发，可控 max_workers） | 文件路径列表 |
| `triage_firmware_top20` | 一键全自动：扫描 → 评分 → 深度分析 Top 20 | 固件目录 |

### Web 上下文工具（无需 IDA）

| 工具 | 说明 |
|------|------|
| `scan_web_context` | 扫描固件 Web 上下文：Web server、endpoint、参数、认证边界，并与二进制风险绑定 |

---

## 使用示例

### 1. 快速固件审计（Tier 1）

```python
# 在 Claude 中调用：
scan_firmware("/path/to/firmware/root")

# 输出示例：
{
  "scan_summary": {
    "total_scanned": 120,
    "total_elf": 95,
    "high_risk": 15
  },
  "high_risk": [
    {
      "path": "/bin/httpd",
      "total_score": 120,
      "sinks_found": ["strcpy", "sprintf", "system"]
    }
  ]
}
```

### 2. 深度漏洞分析（Tier 2）

```python
# 自动全流程分析固件高风险目标
result = await triage_firmware_top20("/path/to/firmware/root")

# 查看深度分析结果
for binary_path, triage_report in result["tier2_results"].items():
    print(f"{binary_path}: {len(triage_report['source_sink_path'])} 条路径")
    # 输出样本：
    # /bin/httpd: 92 条路径
    # /bin/pptpd: 28 条路径
    # /bin/dhcps: 50 条路径
```

---

## 架构设计

```
固件目录 → Tier 1 扫描 → 风险评分 → Tier 2 IDA 分析 → 漏洞报告
           (< 1秒)                    (~2-3分钟)
```

## 配置说明

编辑 `src/autoi_mcp/data/config.json`：

```json
{
  "ida": {
    "path": "/opt/ida-pro/idat",  // IDA headless 路径（自动探测或手动设置）
    "timeout": 300                 // 单个文件超时（秒）
  },
  "concurrency": {
    "max_workers": 8               // 并行线程数
  }
}
```

**IDA 路径自动探测**: 按优先级搜索 config.json → PATH → 常见安装目录（/opt/ida-pro、~/ida-pro 等）

**注意**: 仅支持 headless 版本 `idat`/`idat64`，不支持 GUI 版 `ida`/`ida64`。

---

## 技术栈

- **MCP 协议**: FastMCP (官方 Python SDK)
- **ELF 解析**: pwntools (跨架构 checksec 支持)
- **IDA 调用**: asyncio.subprocess (异步并发)
- **数据验证**: Pydantic v2 (类型安全)
- **规则配置**: JSON (无需代码改动)

## 目录结构

```
src/autoi_mcp/
├── tools/          # MCP 工具注册
├── scanner/        # ELF & Web 扫描器
├── analysis/       # 风险评分
├── ida/            # IDA headless 调用 + IDAPython 脚本
├── models/         # Pydantic 数据模型
└── data/           # JSON 规则配置
```

---

## 许可证

MIT

