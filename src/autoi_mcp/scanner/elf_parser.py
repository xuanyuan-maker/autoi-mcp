from typing import Any

from pwn import ELF, context
import os


def parse_elf(elf_path: str) -> dict[str, Any]:
    """
    解析 ELF 文件并返回详细信息。

    Args：
        elf_path: ELF 文件路径。

    Returns:
        包含以下键的字典：
         - file_header: 文件头信息（架构，端序，入口点、ELF类型）
         - sections：所有节（Sections Headers）的列表，每项含 name, addr, size, perm
         - segments: 所有段（Program Headers）的列表，每项含 type, vaddr, memsz, offset, align
         - symbols: 符号表，键为符号名，值为地址
         - security: 安全缓解措施 (relro, canary, nx, pie, rpath, runpath)
         若出错则返回 {"error": "错误信息"} 
    """
    if not os.path.exists(elf_path):
        return {"error": f"File not found: {elf_path}"}
        
    try:
        # 抑制 pwntools 的日志输出
        context.log_level = 'error'
        elf = ELF(elf_path, checksec=True)
    except Exception as e:
        return {"error": f"Failed to parse ELF: {str(e)}"}

    # === ELF 文件头 ===
    file_header = {
        "arch": elf.arch,
        "bits": elf.bits,
        "endian": "little" if elf.endian == 'little' else 'big',
        "entry": elf.entry,
        "elf_type": "DYN" if elf.elftype == 'DYN' else ("EXEC" if elf.elftype == 'EXEC' else elf.elftype), 
    }

    # === 节表 ===
    sections = []
    for sec in elf.sections:
        if sec is None:
            continue
        name = sec.name
        addr = sec.header.sh_addr
        size = sec.header.sh_size
        flags = sec.header.sh_flags

        # 获取节的权限
        perm_map = [(1, 'W'), (2, 'A'), (4, 'E')]
        perm = ''.join([p for flag, p in perm_map if flags & flag]) or '---'

        sections.append({
            "name": name,
            "addr": addr,
            "size": size,
            "perm": perm,
        })

    # === 段表 ===
    segments = []
    for seg in elf.segments:
        segments.append({
            "type": seg.header.p_type,
            "vaddr": seg.header.p_vaddr,
            "memsz": seg.header.p_memsz,
            "offset": seg.header.p_offset,
            "align": seg.header.p_align,
        })

    # === 符号表 ===
    symbols = dict(elf.symbols)

    # === 安全缓解措施 ===
    security = {
        "relro": elf.relro,
        "canary": elf.canary,
        "nx": elf.nx,
        "pie": elf.pie,
        "rpath": elf.rpath if elf.rpath else None,
        "runpath": elf.runpath if elf.runpath else None,
    }

    return {
        "file_header": file_header,
        "sections": sections,
        "segments": segments,
        "symbols": symbols,
        "security": security,
    }
