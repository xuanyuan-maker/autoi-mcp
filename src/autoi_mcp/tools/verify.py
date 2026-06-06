"""Tier 1 单文件快速检查 — checksec + 危险符号，不需要 IDA。"""

from autoi_mcp.scanner.elf import parse_elf, match_rules, load_sinks, load_sources


def register(mcp):

    @mcp.tool()
    def check_elf(filepath: str) -> dict:
        """检查单个 ELF 的安全缓解措施、危险函数和输入源。

        用于快速抽查某个二进制，不需要扫描整个目录。
        不包含风险评分——评分是 scan_firmware 的工作。

        Args:
            filepath: ELF 文件的绝对路径
        """
        binary = parse_elf(filepath)
        binary = match_rules(binary, load_sinks(), load_sources())

        return {
            "path": binary.path,
            "arch": binary.file_header.arch,
            "bits": binary.file_header.bits,
            "endian": binary.file_header.endian,
            "entry": hex(binary.file_header.entry),
            "elf_type": binary.file_header.elf_type,
            "security": {
                "nx": binary.security.nx,
                "canary": binary.security.canary,
                "pie": binary.security.pie,
                "relro": binary.security.relro,
                "rpath": binary.security.rpath,
                "runpath": binary.security.runpath,
            },
            "symbols_count": len(binary.symbols),
            "dangerous_sinks": binary.dangerous_sinks,
            "input_sources": binary.input_sources,
            "sections": [
                {"name": s.name, "addr": hex(s.addr), "size": s.size, "perm": s.perm}
                for s in binary.sections
            ],
        }
