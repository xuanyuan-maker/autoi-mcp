"""
IDA python Triage 脚本 - 在 headless IDA 内执行，自包含，不依赖 autoi_mcp 包。

用法：
    idat -A \
         -S"triage_script.py <output.json> <sinks.json> <sources.json> <binary_info.json>" \
         -L/tmp/ida.log ./squashfs-root/bin/httpd

参数(sys.argv)：
    [1] output.json         - 分析结果输出路径
    [2] sinks.json          - dangerous_sinks.json 路径
    [3] sources.json        - cgi_sources.json 路径
    [4] binary_info.json    - Tier 1 BinaryInfo.model_dump.json 产物（只读，可直接复用）

输出 JSON 结构 — 字段名严格对齐 TriageReport / SinkInfo / SourceInfo / SourceSinkPath 模型：
      {
          "info":              { ... BinaryInfo 原样透传 ... },
          "sink":              [ SinkInfo, ... ],
          "source":            [ SourceInfo, ... ],
          "source_sink_path":  [ SourceSinkPath, ... ],
          "total_functions":   int,
          "analyzed_functions": int,
          "analyzed_time":     float,
          "error":             null | str
      }
注意事项：
    - 本脚本在 IDA 进程内运行，只能使用 IDAPython + Python 标准库
    - 不可 import autoi_mcp（IDA 的 Python 环境不包含该包）
    - JSON 字段名严格对齐 TriageReport / SinkInfo / SourceInfo / SourceSinkPath 模型字段
"""

import json
import sys
import time
from collections import deque

def log(msg: str) -> None:
    """
    打印带时间戳的日志到 stderr

    IDA headless 模式中 stdout 会被 IDA 本身占用，故将所有诊断信息统一输出到 stderr。
    最终写入 -L 指定的 log 文件
    """
    print(f"[triage] {time.time():.0f} {msg}", file=sys.stderr)

# ========================================================
# 参数解析 & 数据加载
# ========================================================

def parse_args():
    """
    解析 sys.argv 与 加载所有 JSON 文件

    Returns:
        (output_path, sinks_dict, sources_list, binary_info_dict)
    """
    if len(sys.argv) < 5:
        print(
            f"Usage: {sys.argv[0]} <output.json> <sinks.json> <sources.json> <binary_info.json> "
        )
        sys.exit(1)

    output_path         = sys.argv[1]
    sinks_path          = sys.argv[2]
    sources_path        = sys.argv[3]
    binary_info_path    = sys.argv[4]

    with open(sinks_path) as f:
        sinks_raw = json.load(f)
    with open(sources_path) as f:
        sources_list = json.load(f)
    with open(binary_info_path) as f:
        binary_info = json.load(f)

    # 去除 sinks 中以 _ 开头的元数据
    sinks_dict = {k: v for k, v in sinks_raw.items() if not k.startswith("_")}

    log(f"Loaded rules: {len(sinks_dict)} sinks, {len(sources_list)} sources")
    log(f"Loaded Binary Info from Tier 1 : {binary_info.get('path', '?')}")
    return output_path, sinks_dict, sources_list, binary_info

# ==========================================================
# 交叉引用查找 - 获取某个符号的全部调用点
# ==========================================================

def get_call_sites(func_name: str) -> list[dict]:
    """
    获取指定函数名的所有代码交叉引用

    步骤：
        1. 遍历符号名在 IDA name table 中查找地址
        2. 遍历该地址的全部交叉引用，仅保留 call/jmp 类型的代码引用
        3. 对每个引用点，定位其所在的外层函数

    Args:
        - func_name: 符号名，如 "system", "recv", "sprintf", ...

    Returns:
        list[dict]:
            - func: str     - 调用者函数名（无符号函数识别为"sub_xxxxxxxx")
            - addr: int     - 调用指令的地址
        若符号不存在或者未被引用，返回空列表
    """

    import ida_xref
    import idaapi
    import idautils
    import idc

    ea = idc.get_name_ea_simple(func_name)
    if ea == idc.BADADDR:
        return []

    sites = []
    for xref in idautils.XrefsTo(ea):
        if xref.type not in (
            ida_xref.fl_CN, ida_xref.fl_CF,
            ida_xref.fl_JN, ida_xref.fl_JF,
        ):
            continue

        caller = idaapi.get_func(xref.frm)
        caller_name = (
            idc.get_func_name(caller.start_ea)
            if caller
            else f"sub_{xref.frm:X}"
        )

        sites.append({
            "func": caller_name,
            "addr": xref.frm
        })

    return sites

# =======================================================
# Sink 定位
# =======================================================

def locate_sinks(sinks_dict: dict) -> list[dict]:
    """
    遍历 sinks_dict 中的每个危险函数符号，通过交叉引用找到所有调用点，
    按调用者函数聚合位置信息.

    Args:
        - sinks_dict

    Returns:
        - list[dict] - 每个 dict 对应这一个 SinkInfo
    """
    results = []
    for sink_name, sink_meta in sinks_dict.items():
        sites = get_call_sites(sink_name)
        if not sites:
            continue

        # 按照调用者函数聚合地址
        locations: dict[str, list[int]] ={}
        for site in sites:
            locations.setdefault(site["func"], []).append(site["addr"])

        results.append({
            "name": sink_name,
            "vuln_type": sink_meta["vuln_type"],
            "category": sink_meta["category"],
            "locations": locations
        })

    log(f" Located {len(results)} sinks with call sites")
    return results

# ===========================================================
# Source 定位
# ===========================================================

def locate_sources(sources_list: list[str]) -> list[dict]:
    """
    遍历 sources_list 中每个输入函数信号，通过交叉引用找到所有调用点，
    按照调用者函数聚合地址

    Args:
        - sources_list: ["recv", "fgets", "getenv", ...]

    Returns:
        - list[dict] 每个 dict 对应着一个SourceInfo
    """
    results = []
    for source_name in sources_list:
        sites = get_call_sites(source_name)
        if not sites:
            continue

        locations: dict[str, list[int]] = {}
        for site in sites:
            locations.setdefault(site["func"], []).append(site["addr"])

        results.append({
            "name": source_name,
            "source_type": "input",
            "locations": locations
        })

    log(f"located {len(results)} sources with call sites")
    return results

# =============================================================
# Call Graph 辅助函数
# =============================================================

def get_callees(func_ea: int) -> set[int]:
    """
    返回指定函数所有被调用者（callee）地址集合
    遍历函数体内所有指令，找出 call 指令的目标地址
    """
    import ida_xref
    import idaapi
    import idautils

    callees = set()
    func = idaapi.get_func(func_ea)
    if not func:
        return callees
    
    for head in idautils.FuncItems(func_ea):
        # 遍历函数中所有指令，找出交叉引用，筛选出 call 类型
        for xref in idautils.XrefsFrom(head):
            if xref.type in (ida_xref.fl_CN, ida_xref.fl_CF):
                callees.add(xref.to)

    return callees

def get_function_name(ea: int) -> str:
    """安全获取函数名，无名函数返回 sub_XXXXXXXX"""
    import idc

    name = idc.get_func_name(ea)
    return name if name else f"sub_{ea:x}"

def build_call_graph() -> dict[str, set[str]]:
    """
    构建整个二进制程序的调用图

    Returns:
        - { caller_name : {callee_name, ...}}
    """
    import idautils

    graph: dict[str, set[str]] = {}
    for ea in idautils.Functions():
        caller_name = get_function_name(ea)
        callee_names = {get_function_name(c) for c in get_callees(ea)}
        graph[caller_name] = callee_names

    return graph


# ========================================================
# Source-to-Sink 路径追踪 — BFS 在调用图中查找路径
# ========================================================

def find_path(
    call_graph: dict[str, set[str]],
    start_func: str,
    target_funcs: set[str],
    max_depth: int = 5,
) -> list[str] | None:
    """
    在调用图中从 start_func 出发，BFS 搜索到达 target_funcs 中任一函数的路径。

    如果 start_func 本身就在 target_funcs 中，直接返回 [start_func]（同一函数内 source→sink）。

    Args:
        call_graph: 调用图 {caller: {callee, ...}}
        start_func: 起始函数名（source 的调用者）
        target_funcs: 目标函数名集合（sink 的调用者）
        max_depth: 最大搜索深度（跳数），默认 5

    Returns:
        路径列表 [start_func, ..., target_func] 或 None
    """
    if start_func in target_funcs:
        return [start_func]

    visited = {start_func}
    queue = deque([(start_func, [start_func])])

    while queue:
        current, path = queue.popleft()
        if len(path) > max_depth:
            continue

        for callee in call_graph.get(current, set()):
            if callee in visited:
                continue
            visited.add(callee)

            new_path = path + [callee]
            if callee in target_funcs:
                return new_path
            queue.append((callee, new_path))

    return None


def trace_source_to_sink(
    sinks: list[dict],
    sources: list[dict],
    call_graph: dict[str, set[str]],
) -> list[dict]:
    """
    对每一对 (source, sink) 尝试在调用图中找到从 source 调用者到 sink 调用者的路径。

    置信度规则：
        - 路径长度 == 1（同一函数）  → "high"
        - 路径长度 == 2（跨一次调用）→ "medium"
        - 路径长度 >= 3               → "low"

    Returns:
        list[dict] — 每个 dict 对应一个 SourceSinkPath：
            { source, sink, path: {func_name: address}, confidence }
    """
    # 构建函数名到地址的映射（用于填充 path 中的地址）
    import idautils

    func_to_addr: dict[str, int] = {}
    for ea in idautils.Functions():
        func_to_addr[get_function_name(ea)] = ea

    results = []
    seen_pairs = set()

    for src in sources:
        source_callers = set(src["locations"].keys())

        for snk in sinks:
            sink_callers = set(snk["locations"].keys())

            for src_caller in source_callers:
                path = find_path(call_graph, src_caller, sink_callers)
                if not path:
                    continue

                # 去重：同一 (source, sink, src_caller, target) 只记一条
                pair_key = (src["name"], snk["name"], src_caller, path[-1])
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)

                # 置信度分级
                path_len = len(path)
                if path_len == 1:
                    confidence = "high"
                elif path_len == 2:
                    confidence = "medium"
                else:
                    confidence = "low"

                # 构建 path 字典 {func_name: address}
                path_dict = {
                    func_name: func_to_addr.get(func_name, 0)
                    for func_name in path
                }

                results.append({
                    "source": src["name"],
                    "sink": snk["name"],
                    "path": path_dict,
                    "confidence": confidence,
                })

                # 每个 source_caller 只记录第一条（最短）路径，不重复搜索同一对
                break

    log(f"Traced {len(results)} source-to-sink paths")
    return results


# =======================================================
# 主入口
# =======================================================

def main() -> None:
    """
    IDA headless triage 主入口

    执行流程：
        1. 解析命令参数并加载 JSON 规则
        2. 等待IDA自动分析完成
        3. 定位 dangerous sinks
        4. 定位 input sources
        5. 构建调用图
        6. 执行 source-to-sink 路径追踪
        7. 写出TriageReport JSON
    """

    import traceback
    import idaapi
    import idautils

    t_start = time.time()
    
    output_path = None
    binary_info = {}
    sinks = []
    sources = []
    paths = []
    total_functions = 0
    analyzed_functions = set()
    error_msg = None

    try:
        output_path, sinks_dict, sources_list, binary_info = parse_args()

        log("Waiting for IDA auto-analysis...")
        idaapi.auto_wait()

        total_functions = len(list(idautils.Functions()))
        log(f"Total Functions: {total_functions}")

        sinks = locate_sinks(sinks_dict)
        sources = locate_sources(sources_list)

        call_graph = build_call_graph()
        log(f"Call graph built: {len(call_graph)} nodes")

        paths = trace_source_to_sink(
            sinks = sinks,
            sources = sources,
            call_graph=call_graph
        )

        for sink in sinks:
            analyzed_functions.update(sink["locations"].keys())

        for source in sources:
            analyzed_functions.update(source["locations"].keys())

        for path in paths:
            analyzed_functions.update(path["path"].keys())

    except Exception as e:
        error_msg = str(e)
        log(f"ERROR: {error_msg}")
        traceback.print_exc(file=sys.stderr)

    elapsed = time.time() - t_start    

    report = {
        "info": binary_info,
        "sink": sinks,
        "source": sources,
        "source_sink_path": paths,
        "total_functions": total_functions,
        "analyzed_functions": len(analyzed_functions),
        "analyzed_time": round(elapsed, 2),
        "error": error_msg,
    }

    if output_path is None:
        output_path = "triage_result.json"

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    log(f"Done. Output: {output_path}, elapsed={elapsed:.2f}s") 

if __name__ == "__main__":
    main()

