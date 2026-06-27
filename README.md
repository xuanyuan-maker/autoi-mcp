# autoi-mcp

![version](https://img.shields.io/badge/version-0.6.0-blue) ![license](https://img.shields.io/badge/license-MIT-green) ![python](https://img.shields.io/badge/python-%3E%3D3.12-blue)

`autoi-mcp` 是一个基于 **Model Context Protocol (MCP)** 的 IoT 固件二进制自动化安全审计工具，通过 **两层分析管道** 快速定位漏洞：

- **Tier 1 (秒级)**: 批量 ELF 扫描 + 风险评分，快速过滤高风险目标
- **Tier 2 (分钟级)**: IDA headless 深度分析，source-to-sink 路径追踪 + 置信度分级
- **Web 上下文**: 静态关联二进制风险与 Web 入口（server / endpoint / 参数 / 认证边界）

---

## 功能概览

### Tier 1：快速风险评分（不需要 IDA）
- ✅ 批量 ELF 解析 + checksec 安全缓解检查
- ✅ 符号表规则匹配（危险函数 + 输入源）
- ✅ 多维度风险评分（安全保护缺失 + 危险函数 + 认证信号）
- ✅ 高效系统库过滤（busybox、symlink、系统二进制）

### Tier 2：深度漏洞分析（需要 IDA）
- ✅ IDA headless 自动调用 + 路径自动探测 + 超时保护
- ✅ 完整 call graph 构建（整个二进制的函数调用关系）
- ✅ Source-to-Sink 路径追踪（BFS，最大 5 跳）
- ✅ 置信度自动分级
  - **高 (High)**: 同一函数内直接调用 source → sink
  - **中 (Medium)**: 跨一层函数调用
  - **低 (Low)**: 跨多层调用（可能误报）

### Web 上下文关联（不需要 IDA）
- ✅ Web server 识别（httpd / goahead / lighttpd 等）+ 配置/监听端口/CGI 路径解析
- ✅ Endpoint、参数、认证边界静态提取
- ✅ 二进制风险 ↔ Web 入口绑定（回答"哪个 URL/参数触发哪个风险"）
- ✅ 纯静态解析，不访问真实设备、不发起网络请求

---

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
输入（固件） → [Tier 1: ELF 扫描] → [高风险过滤] → [Tier 2: IDA 分析] → 输出（漏洞报告）
              < 1秒                                    ~2分钟(3个目标)
```

### 数据流

1. **Tier 1 输入**
   - ELF 文件（直接或目录递归）
   - 风险评分规则（JSON 配置）

2. **Tier 1 处理**
   - pwntools ELF 解析（符号表 + 段表 + checksec）
   - 规则匹配（dangerous_sinks.json + cgi_sources.json）
   - 风险评分（多维加权）

3. **Tier 2 输入**
   - Tier 1 二进制信息（BinaryInfo）
   - 规则集（sinks + sources）
   - IDA 路径（自动探测或配置）

4. **Tier 2 处理**
   - IDA headless 调用（idat -A -S"triage_script.py ..."）
   - IDAPython 脚本运行
     - 符号交叉引用解析
     - Call Graph 构建
     - BFS 路径追踪
   - 置信度分级

5. **输出**
   - TriageReport：包含所有发现的 sources、sinks、paths

---

## 性能指标（测试数据）

基于 IoT 固件测试（真实固件目录，120+ ELF）：

| 阶段 | 时间 | 产出 |
|------|------|------|
| Tier 1 扫描 | < 1s | 25 个高风险目标 |
| Tier 2 分析 Top 20 | ~2-3min | 493 条 source-sink 路径 |
| **总计** | **~3-4min** | **276 条高置信漏洞路径** |

---

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

### IDA 路径自动探测

工具会按优先级搜索：
1. config.json 中的持久化路径
2. PATH 环境变量（idat64 / idat）
3. 常见安装目录（/opt/ida-pro、~/ida-pro 等）

**注意**：仅支持 headless 版本 `idat`/`idat64`，不支持 GUI 版 `ida`/`ida64`。

---

## 核心算法

### Source-to-Sink 路径追踪

```
1. 定位所有 source 调用点（fgets、recv 等）
   → 收集调用这些函数的函数集合 S

2. 定位所有 sink 调用点（strcpy、system 等）
   → 收集调用这些函数的函数集合 K

3. 对于每个 source 函数 s ∈ S
   BFS(from=s, targets=K, max_depth=5)
   → 找到从 s 到 K 中任意函数的最短路径

4. 根据路径长度分级置信度
   • 长度 1（同函数）→ High
   • 长度 2（一跳）→ Medium
   • 长度 ≥ 3（多跳）→ Low
```

---

## 项目状态

- **Phase 1** ✅ 完成
  - Tier 1 快速扫描 + 风险评分
  - Tier 2 IDA 深度分析
  - 5 个 MCP 工具
  - 端到端测试验证

- **Phase 2** 🚧 计划中
  - Auth pattern matching（认证绕过检测）
  - Constant propagation（常量跟踪，减少误报）
  - Stripped symbol recovery（符号恢复）

- **Phase 3** 📋 未来
  - HTML/PDF 审计报告生成
  - CVSS 自动评分
  - PoC 代码生成

---

## 开发说明

本项目使用 **Claude AI** 辅助开发，架构设计、测试验证由人工主导。

### 技术栈

| 组件 | 选择 | 原因 |
|------|------|------|
| MCP 协议 | mcp (官方 Python SDK) | 装饰器便利，FastMCP 轻量 |
| ELF 解析 | pwntools (pwn.ELF) | checksec 内置，跨架构支持 |
| IDA 调用 | asyncio.subprocess | 异步 headless，并发控制 |
| 数据验证 | Pydantic v2 | 类型安全，自动 JSON Schema |
| 规则数据 | JSON | 易编辑，无需代码改动 |

### 目录结构

```
src/autoi_mcp/
├── server.py              # MCP 服务入口
├── config.py              # 配置加载（IDA路径、超时等）
├── tools/
│   ├── info.py            # scan_firmware
│   ├── verify.py          # check_elf
│   ├── triage.py          # triage_single_binary / triage_batch / triage_firmware_top20
│   └── web.py             # scan_web_context
├── scanner/
│   ├── elf.py             # ELF 解析、规则匹配、批量扫描
│   └── web.py             # Web 上下文扫描（server / endpoint / 参数）
├── analysis/
│   └── risk.py            # 风险评分器
├── ida/
│   ├── runner.py          # IDA headless 异步调用
│   └── triage_script.py   # IDAPython 脚本（路径追踪）
├── models/
│   ├── binary.py          # BinaryInfo 等 Pydantic 模型
│   ├── risk.py            # RiskReport 等
│   └── triage.py          # TriageReport 等
└── data/
    ├── config.json        # 运行配置
    ├── dangerous_sinks.json
    ├── cgi_sources.json
    ├── auth_keywords.json
    ├── risk_weights.json
    └── system_filters.json
```

---

## 许可证

MIT

