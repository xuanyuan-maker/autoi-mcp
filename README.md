# autoi-mcp

`autoi-mcp` 是一个基于 **Model Context Protocol (MCP)** 的自动化安全审计扩展，该项目通过 MCP 服务调用底层脚本操控 **Idat (IDA Pro Python 自动化接口)**，旨在实现对 IoT 固件二进制程序的**批量静态分析、敏感函数挖掘、输入可控点追踪及潜在漏洞定位**。

---

## 安装

### 方式一：uvx（推荐，用于 Claude Code）

在项目的 `.mcp.json` 或全局 `~/.claude/claude_desktop_config.json` 中添加：

```json
{
  "mcpServers": {
    "autoi-mcp": {
      "command": "uvx",
      "args": ["autoi-mcp"]
    }
  }
}
```

`uvx` 会自动从 PyPI 下载并运行最新版本。

### 方式二：pip

```bash
pip install autoi-mcp
```

然后配置 Claude Code：

```json
{
  "mcpServers": {
    "autoi-mcp": {
      "command": "python",
      "args": ["-m", "autoi_mcp.server"]
    }
  }
}
```

### 方式三：源码开发

```bash
git clone <repo-url>
cd autoi-mcp
uv sync
uv run python -m autoi_mcp.server
```

---

## MCP 工具

| 工具 | 说明 | 需要 IDA |
|------|------|----------|
| `scan_firmware` | 批量扫描固件目录下所有 ELF，风险评分 + 过滤 | 否 |
| `check_elf` | 单文件快速检查：安全缓解措施 + 危险符号 | 否 |

---

## 核心思路

> 参考了如下文章
> https://mp.weixin.qq.com/s/5mKZ7D1qNoZ9BMDIlxnF6A

### 1. 自动搜索

自动搜索 system/popen/strcpy/sprintf/strcat/memcpy/gets 等函数的导入和交叉引用

### 2. 定位输入

定位输入 Source — 搜索 cgi_param/getenv/fgets/fread 等 CGI 输入源

### 3. 追踪 Source-to-Sink 路径

同一函数内同时调用了输入源和危险函数 = 高风险路径

### 4. 识别认证函数

识别认证函数 — 函数名含 auth/login/session/check 的全部标记

### 5. 风险评分排名

有 system/popen 得 30 分，有 strcpy/sprintf 得 25 分，有高危路径再加 30 分

---

## 开发说明

本项目使用 **DeepSeek** 辅助 vibe coding 开发，部分代码由 AI 生成并经人工审查后合入。

