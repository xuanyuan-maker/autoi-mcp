"""Web 上下文扫描 — Web server 配置、前端 endpoint/参数、endpoint↔binary 关联。

Phase 0：把二进制风险与 URL、参数、认证边界关联起来。
全部为静态解析，不访问真实设备、不发起网络请求（PLAN.md 关键约定第 6 条）。

公开函数：
    scan_webserver_config(dirpath)        -> list[WebServerConfig]
    scan_frontend_js(dirpath)             -> (list[WebEndpoint], int html_cnt, int js_cnt)
    correlate_endpoints_binaries(eps, bins) -> list[BinaryEndpointLink]
    scan_web_context(dirpath)             -> WebContextReport   # 编排以上三步
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
from pathlib import PurePosixPath

from autoi_mcp.data.loader import data_path
from autoi_mcp.models.web import (
    WebServerConfig, WebParam, WebEndpoint, BinaryEndpointLink, WebContextReport,
)


# ============================================================
# 规则加载
# ============================================================

def _load_json(filename: str) -> dict:
    with open(data_path(filename)) as f:
        return json.load(f)


def load_web_server_patterns() -> dict:
    """加载 Web server 探测规则（server_binaries / config_filenames / webroot_globs ...）。"""
    return _load_json("web_server_patterns.json")


def load_web_endpoint_patterns() -> dict:
    """加载前端 endpoint 提取正则规则。"""
    return _load_json("web_endpoint_patterns.json")


def load_web_keywords() -> dict:
    """加载 endpoint↔binary 关联关键词。"""
    return _load_json("web_keywords.json")


# ============================================================
# 工具函数
# ============================================================

def _is_elf(filepath: str) -> bool:
    """读取魔数判断是否 ELF（用于排除 httpd.pid / httpd.i64 等同名非 ELF 文件）。"""
    try:
        with open(filepath, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except (OSError, PermissionError):
        return False


def _normalize_url(url: str) -> str:
    """归一化 URL：去掉前导 ./ 与 /，剥离查询串和锚点，便于比对路由。"""
    url = url.strip().split("#", 1)[0]
    url = url.split("?", 1)[0]
    while url.startswith(("./", "/")):
        url = url[2:] if url.startswith("./") else url[1:]
    return url


def _route_tail(url: str) -> str:
    """取 URL 的最后一段作为 handler 名，如 goform/SetDDNSCfg -> SetDDNSCfg。"""
    norm = _normalize_url(url)
    return PurePosixPath(norm).name if norm else ""


def _looks_like_endpoint(url: str, markers: list[str]) -> bool:
    """判断 URL 是否像后端路由（含 goform/cgi-bin 等标记），过滤掉 css/js/img 静态资源。"""
    low = url.lower()
    if any(m in low for m in markers):
        return True
    # 含 .cgi/.asp 等动态扩展也算
    return low.endswith((".cgi", ".asp"))


# ============================================================
# 1) Web server 配置扫描
# ============================================================

def scan_webserver_config(dirpath: str) -> list[WebServerConfig]:
    """扫描固件目录，定位 Web server 二进制、配置文件、webroot 目录和启动参数。

    Args:
        dirpath: 固件解压后的根目录

    Returns:
        list[WebServerConfig] — 每个识别到的 Web server 一条记录
    """
    pat = load_web_server_patterns()
    server_names: set[str] = {n.lower() for n in pat.get("server_binaries", [])}
    config_names: set[str] = {n.lower() for n in pat.get("config_filenames", [])}
    webroot_globs: list[str] = pat.get("webroot_globs", [])
    init_globs: list[str] = pat.get("init_script_globs", [])
    doc_root_keys: list[str] = pat.get("doc_root_keys", [])
    port_keys: list[str] = pat.get("port_keys", [])

    server_bins: dict[str, str] = {}   # server_type -> binary_path
    config_files: list[str] = []
    webroot_dirs: list[str] = []
    init_scripts: list[str] = []

    for root, dirs, files in os.walk(dirpath, followlinks=False):
        # webroot 目录（按目录名匹配 glob）
        for d in dirs:
            for g in webroot_globs:
                if fnmatch.fnmatch(d.lower(), g.lower()):
                    webroot_dirs.append(os.path.join(root, d))
                    break
        for name in files:
            fpath = os.path.join(root, name)
            low = name.lower()
            # Web server 二进制（同名且确为 ELF）
            if low in server_names and _is_elf(fpath):
                server_bins.setdefault(low, fpath)
            # 配置文件
            if low in config_names:
                config_files.append(fpath)
            # init 脚本
            rel = os.path.relpath(fpath, dirpath)
            if any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(fpath, g) for g in init_globs):
                init_scripts.append(fpath)

    # 选一个最浅的 webroot 作为默认根目录
    default_root = min(webroot_dirs, key=lambda p: len(p)) if webroot_dirs else None

    servers: list[WebServerConfig] = []

    # 为每个识别到的 server 二进制建一条记录；没有二进制但有配置时也建一条 unknown
    targets = list(server_bins.items())
    if not targets and config_files:
        targets = [("unknown", None)]
    if not targets and default_root:
        # 只发现了 webroot，仍记录一条，便于后续前端扫描定位
        targets = [("unknown", None)]

    for stype, bpath in targets:
        cfg = WebServerConfig(
            server_type=stype,
            binary_path=bpath,
            document_root=default_root,
        )
        # 匹配同类型的配置文件，解析 document_root / port / cgi
        for cf in config_files:
            cfg.config_path = cf
            _parse_config_file(cf, cfg, doc_root_keys, port_keys)
        # init 脚本里找该 server 的启动行与参数
        for sc in init_scripts:
            _parse_init_script(sc, stype, cfg, doc_root_keys, port_keys)
        servers.append(cfg)

    return servers


def _parse_config_file(
    cfg_path: str, cfg: WebServerConfig, doc_root_keys: list[str], port_keys: list[str]
) -> None:
    """从 httpd/lighttpd/boa 配置文件提取 document_root、端口、cgi 路径，写入 cfg。"""
    try:
        with open(cfg_path, errors="ignore") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                low = s.lower()
                for k in doc_root_keys:
                    if low.startswith(k.lower()):
                        val = s[len(k):].strip(" =\t\"'")
                        if val:
                            cfg.document_root = cfg.document_root or val
                            cfg.evidence[k] = s
                for k in port_keys:
                    if low.startswith(k.lower()):
                        m = re.search(r"(\d{2,5})", s)
                        if m:
                            port = int(m.group(1))
                            if port not in cfg.listen_ports:
                                cfg.listen_ports.append(port)
                            cfg.evidence[k] = s
                if "cgi" in low:
                    m = re.search(r"(/\S*cgi\S*)", s)
                    if m and m.group(1) not in cfg.cgi_paths:
                        cfg.cgi_paths.append(m.group(1))
    except OSError:
        pass


def _parse_init_script(
    script_path: str, stype: str, cfg: WebServerConfig,
    doc_root_keys: list[str], port_keys: list[str],
) -> None:
    """从 init 脚本（rcS 等）提取 Web server 启动行的参数（-h webroot / -p port）。"""
    if stype == "unknown":
        return
    try:
        with open(script_path, errors="ignore") as f:
            for line in f:
                s = line.strip()
                if stype not in s.lower():
                    continue
                if s.startswith("#"):
                    continue
                # 记录启动参数
                tokens = s.split()
                cfg.start_args = tokens
                cfg.evidence.setdefault("init", s)
                # -h <webroot>
                for i, tok in enumerate(tokens):
                    if tok in ("-h", "-d") and i + 1 < len(tokens):
                        cfg.document_root = cfg.document_root or tokens[i + 1]
                    if tok == "-p" and i + 1 < len(tokens):
                        m = re.search(r"(\d{2,5})", tokens[i + 1])
                        if m and int(m.group(1)) not in cfg.listen_ports:
                            cfg.listen_ports.append(int(m.group(1)))
    except OSError:
        pass


# ============================================================
# 2) 前端 endpoint / 参数扫描
# ============================================================

def scan_frontend_js(dirpath: str) -> tuple[list[WebEndpoint], int, int]:
    """扫描 webroot 下的 HTML/JS/ASP，提取 endpoint、form action、AJAX URL 和参数。

    Args:
        dirpath: 固件根目录或 webroot 目录

    Returns:
        (endpoints, html_count, js_count)
    """
    ep_pat = load_web_endpoint_patterns()
    kw = load_web_keywords()
    markers: list[str] = ep_pat.get("url_keep_markers", []) or kw.get("endpoint_markers", [])
    html_exts = tuple(kw.get("html_extensions", [".html", ".htm", ".asp", ".js"]))
    js_exts = tuple(kw.get("js_extensions", [".js"]))

    compiled = [
        (p["ref_type"], p["method"], re.compile(p["regex"], re.IGNORECASE))
        for p in ep_pat.get("patterns", [])
    ]
    param_re = re.compile(ep_pat["param_attr_regex"], re.IGNORECASE) if ep_pat.get("param_attr_regex") else None

    endpoints: list[WebEndpoint] = []
    seen: set[tuple[str, str, str]] = set()   # (url, ref_type, source_file) 去重
    html_count = 0
    js_count = 0

    for root, _dirs, files in os.walk(dirpath, followlinks=False):
        for name in files:
            low = name.lower()
            if not low.endswith(html_exts):
                continue
            fpath = os.path.join(root, name)
            try:
                text = open(fpath, errors="ignore").read()
            except OSError:
                continue

            if low.endswith(js_exts):
                js_count += 1
            else:
                html_count += 1

            # 文件级参数（HTML 表单 input/select/textarea 的 name）
            file_params: list[str] = []
            if param_re is not None and not low.endswith(js_exts):
                file_params = list(dict.fromkeys(param_re.findall(text)))

            for ref_type, method, rx in compiled:
                for m in rx.finditer(text):
                    raw_url = m.group(1)
                    if not _looks_like_endpoint(raw_url, markers):
                        continue
                    url = _normalize_url(raw_url)
                    if not url:
                        continue
                    key = (url, ref_type, fpath)
                    if key in seen:
                        continue
                    seen.add(key)

                    params = _extract_params(raw_url, ref_type, file_params)
                    endpoints.append(WebEndpoint(
                        url=url, method=method, ref_type=ref_type,
                        source_file=fpath, params=params,
                    ))

    return endpoints, html_count, js_count


def _extract_params(raw_url: str, ref_type: str, file_params: list[str]) -> list[WebParam]:
    """从 URL 查询串和文件级表单字段提取参数。"""
    params: list[WebParam] = []
    seen: set[str] = set()

    # URL 内联查询串 ?a=1&b=2
    if "?" in raw_url:
        query = raw_url.split("?", 1)[1]
        for pair in re.split(r"[&;]", query):
            pair = pair.strip()
            if not pair:
                continue
            key = pair.split("=", 1)[0].strip()
            # 仅保留合法标识符，过滤 JS 拼接产生的噪声（如 "+Math.random()）
            if key and re.fullmatch(r"[\w.\-]+", key) and key not in seen:
                seen.add(key)
                params.append(WebParam(name=key, origin="query"))

    # 表单字段（仅 form_action 关联文件级 input 名）
    if ref_type == "form_action":
        for name in file_params:
            if name not in seen:
                seen.add(name)
                params.append(WebParam(name=name, origin="form"))

    return params


# ============================================================
# 3) endpoint ↔ binary 关联
# ============================================================

def correlate_endpoints_binaries(
    endpoints: list[WebEndpoint],
    binary_paths: list[str],
) -> list[BinaryEndpointLink]:
    """把 endpoint 路由名与二进制内的字符串做启发式关联。

    策略：对每个 binary 读取原始字节，搜索 endpoint 的完整路由或末段 handler 名。
      - 完整路由命中（如 b"goform/SetDDNSCfg") -> confidence=high
      - 仅末段命中（如 b"SetDDNSCfg")          -> confidence=medium

    Args:
        endpoints: 前端提取到的 endpoint
        binary_paths: 候选处理二进制路径（通常是 Web server 二进制）

    Returns:
        list[BinaryEndpointLink]
    """
    # 预先收集需要搜索的路由 -> (full, tail)
    routes: dict[str, tuple[str, str]] = {}
    for ep in endpoints:
        full = _normalize_url(ep.url)
        tail = _route_tail(ep.url)
        if full and tail:
            routes[ep.url] = (full, tail)

    links: list[BinaryEndpointLink] = []
    for bpath in binary_paths:
        if not bpath or not _is_elf(bpath):
            continue
        try:
            with open(bpath, "rb") as f:
                blob = f.read()
        except OSError:
            continue

        for url, (full, tail) in routes.items():
            full_b = full.encode(errors="ignore")
            tail_b = tail.encode(errors="ignore")
            if full_b and full_b in blob:
                links.append(BinaryEndpointLink(
                    url=url, binary_path=bpath, confidence="high",
                    evidence=[f"string match: {full}"],
                ))
            elif len(tail) >= 4 and tail_b in blob:
                links.append(BinaryEndpointLink(
                    url=url, binary_path=bpath, confidence="medium",
                    evidence=[f"handler string: {tail}"],
                ))

    return links


# ============================================================
# 4) 编排
# ============================================================

def scan_web_context(dirpath: str) -> WebContextReport:
    """完整 Web 上下文扫描：server 配置 + 前端 endpoint + endpoint↔binary 关联。

    Args:
        dirpath: 固件解压后的根目录

    Returns:
        WebContextReport
    """
    errors: list[dict] = []

    try:
        servers = scan_webserver_config(dirpath)
    except Exception as e:
        servers = []
        errors.append({"stage": "webserver_config", "error": str(e)})

    try:
        endpoints, html_cnt, js_cnt = scan_frontend_js(dirpath)
    except Exception as e:
        endpoints, html_cnt, js_cnt = [], 0, 0
        errors.append({"stage": "frontend_js", "error": str(e)})

    # 候选二进制：已识别的 Web server 二进制
    binary_paths = [s.binary_path for s in servers if s.binary_path]
    try:
        bindings = correlate_endpoints_binaries(endpoints, binary_paths)
    except Exception as e:
        bindings = []
        errors.append({"stage": "correlate", "error": str(e)})

    return WebContextReport(
        firmware_dirpath=dirpath,
        servers=servers,
        endpoints=endpoints,
        bindings=bindings,
        total_html=html_cnt,
        total_js=js_cnt,
        errors=errors,
    )
