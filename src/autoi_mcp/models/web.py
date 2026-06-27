"""
Web 上下文数据模型 - WebServerConfig | WebParam | WebEndpoint | BinaryEndpointLink | WebContextReport

Phase 0：把二进制风险与 URL、参数、认证边界关联起来，
回答"哪个入口触发哪个风险"。所有字段均来自静态解析，不访问真实设备。
"""

from pydantic import BaseModel


class WebServerConfig(BaseModel):
    """单个 Web server 的配置信息（来自 httpd.conf/lighttpd.conf/boa.conf 或 init 脚本）。"""
    server_type: str                    # "httpd" | "lighttpd" | "boa" | "goahead" | "uhttpd" | "unknown"
    binary_path: str | None = None      # Web server 可执行文件路径（如果定位到）
    config_path: str | None = None      # 配置文件路径
    document_root: str | None = None    # Web 根目录（webroot/www/htdocs）
    listen_ports: list[int] = []        # 监听端口
    cgi_paths: list[str] = []           # cgi-bin 等 CGI 目录
    start_args: list[str] = []          # init 脚本中的启动参数
    evidence: dict[str, str] = {}       # 关键配置片段：{配置项: 原始行}


class WebParam(BaseModel):
    """前端请求中出现的单个参数。"""
    name: str                           # 参数名，如 "ddnsEn"
    origin: str = "unknown"             # "form" | "ajax_body" | "query" | "url" | "unknown"
    sample_value: str | None = None     # 静态可见的样例值（如有）


class WebEndpoint(BaseModel):
    """前端 HTML/JS 中提取到的单个请求入口。"""
    url: str                            # 相对/绝对 URL，如 "goform/SetDDNSCfg"
    method: str = "UNKNOWN"             # "GET" | "POST" | "UNKNOWN"
    ref_type: str = "unknown"           # "form_action" | "ajax_post" | "ajax_getjson" | "ajax_get" | "ajax" | "unknown"
    source_file: str                    # 引用该 endpoint 的 HTML/JS 文件路径
    params: list[WebParam] = []         # 关联到的参数


class BinaryEndpointLink(BaseModel):
    """endpoint 与处理二进制之间的启发式关联。"""
    url: str                            # endpoint URL
    binary_path: str                    # 疑似处理该 endpoint 的二进制
    confidence: str = "low"             # "high" | "medium" | "low"
    evidence: list[str] = []            # 关联依据，如 ["string match: goform/SetDDNSCfg", "handler symbol: formSetDDNS"]


class WebContextReport(BaseModel):
    """固件 Web 上下文汇总报告。"""
    firmware_dirpath: str
    servers: list[WebServerConfig] = []
    endpoints: list[WebEndpoint] = []
    bindings: list[BinaryEndpointLink] = []

    total_html: int = 0                 # 扫描的 HTML 文件数
    total_js: int = 0                   # 扫描的 JS 文件数
    errors: list[dict] = []

    @property
    def endpoint_count(self) -> int:
        return len(self.endpoints)

    @property
    def server_count(self) -> int:
        return len(self.servers)

    @property
    def binding_count(self) -> int:
        return len(self.bindings)
