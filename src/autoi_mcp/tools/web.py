"""Phase 0 Web 上下文收集 — 扫描 Web server 配置、前端 endpoint、endpoint↔binary 关联。"""

from autoi_mcp.scanner import web as web_scanner
from autoi_mcp.output import write_stage_output


def register(mcp):

    @mcp.tool()
    def scan_web_context(
        dirpath: str,
        verbose: bool = False,
        top_n: int = 50,
        output_dir: str | None = None,
    ) -> dict:
        """扫描固件目录的 Web 上下文：Web server、endpoint、参数、疑似处理二进制。

        把二进制风险与 URL、参数、认证边界关联起来，回答"哪个入口触发哪个风险"。
        全部为静态解析，不访问真实设备、不发起网络请求。

        默认只返回统计摘要 + Top N endpoint/binding 详情，控制输出大小。
        设置 verbose=True 返回全部明细。

        Args:
            dirpath: 固件解压后的根目录路径
            verbose: 是否输出全部 endpoint/binding 明细，默认 False（仅摘要+Top N）
            top_n: 非 verbose 模式下返回的 endpoint/binding Top N 数量，默认 50
        """
        report = web_scanner.scan_web_context(dirpath)

        def _fmt_server(s):
            return {
                "server_type": s.server_type,
                "binary_path": s.binary_path,
                "config_path": s.config_path,
                "document_root": s.document_root,
                "listen_ports": s.listen_ports,
                "cgi_paths": s.cgi_paths,
                "start_args": s.start_args,
                "evidence": s.evidence,
            }

        def _fmt_endpoint(e):
            return {
                "url": e.url,
                "method": e.method,
                "ref_type": e.ref_type,
                "source_file": e.source_file,
                "params": [{"name": p.name, "origin": p.origin} for p in e.params],
            }

        def _fmt_binding(b):
            return {
                "url": b.url,
                "binary_path": b.binary_path,
                "confidence": b.confidence,
                "evidence": b.evidence,
            }

        # ref_type / confidence 分布统计
        ref_type_counts: dict[str, int] = {}
        for e in report.endpoints:
            ref_type_counts[e.ref_type] = ref_type_counts.get(e.ref_type, 0) + 1
        conf_counts: dict[str, int] = {}
        for b in report.bindings:
            conf_counts[b.confidence] = conf_counts.get(b.confidence, 0) + 1

        web_summary = {
            "firmware_dirpath": report.firmware_dirpath,
            "servers": report.server_count,
            "endpoints": report.endpoint_count,
            "bindings": report.binding_count,
            "total_html": report.total_html,
            "total_js": report.total_js,
            "ref_type_distribution": ref_type_counts,
            "binding_confidence_distribution": conf_counts,
            "total_errors": len(report.errors),
        }
        servers_fmt = [_fmt_server(s) for s in report.servers]

        # 传入 output_dir 时,全量明细落盘为 web_context.json
        output_file = None
        if output_dir:
            full_payload = {
                "web_summary": web_summary,
                "servers": servers_fmt,
                "endpoints": [_fmt_endpoint(e) for e in report.endpoints],
                "bindings": [_fmt_binding(b) for b in report.bindings],
                "errors": report.errors,
            }
            output_file = write_stage_output(output_dir, "web_context", full_payload)

        result: dict = {
            "web_summary": web_summary,
            "servers": servers_fmt,
        }
        if output_file:
            result["output_file"] = output_file

        if verbose:
            result["endpoints"] = [_fmt_endpoint(e) for e in report.endpoints]
            result["bindings"] = [_fmt_binding(b) for b in report.bindings]
        else:
            # binding 优先按置信度排序（high > medium > low）后取 Top N
            conf_rank = {"high": 0, "medium": 1, "low": 2}
            sorted_bindings = sorted(
                report.bindings, key=lambda b: conf_rank.get(b.confidence, 9)
            )
            result["endpoints"] = [_fmt_endpoint(e) for e in report.endpoints[:top_n]]
            result["bindings"] = [_fmt_binding(b) for b in sorted_bindings[:top_n]]
            if report.endpoint_count > top_n or report.binding_count > top_n:
                result["_truncated"] = {
                    "endpoints_showing": f"{min(top_n, report.endpoint_count)}/{report.endpoint_count}",
                    "bindings_showing": f"{min(top_n, report.binding_count)}/{report.binding_count}",
                    "hint": "Set verbose=True for full results, or increase top_n.",
                }

        result["errors"] = report.errors
        return result
