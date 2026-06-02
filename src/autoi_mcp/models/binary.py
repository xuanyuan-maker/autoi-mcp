""" ELF 二进制数据模型。"""
from pydantic import BaseModel

# === ELF header ===
class FileHeader(BaseModel):
    arch: str       # "mips" | "arm" | "i386" | "amd64" |...    
    bits: int       # 32 | 64
    endian: str     # "little" | "big"
    entry: int      # entry addr
    elf_type: str   # "DYN" | "EXEC"


class SectionInfo(BaseModel):
    name: str
    addr: int
    size: int
    perm: str       # "WAE"，分别代表 W=可写 A=可分配 E=可执行

class SegmentInfo(BaseModel):
    type: str       # "LOAD" | "DYNAMIC" | "GNU_STACK" | "GNU_RELRO" | ...
    vaddr: int
    memsz: int
    offset: int
    align: int

class SecurityInfo(BaseModel):
    relro: str
    canary: bool
    nx: bool
    pie: bool
    rpath: str | None
    runpath: str | None

class BinaryInfo(BaseModel):
    path: str
    file_header: FileHeader
    security: SecurityInfo
    symbols: dict[str, int]
    dangerous_sinks: list[str]      # 危险的函数名
    input_sources: list[str]        # 危险的输入源函数名
    sections: list[SectionInfo]
    segments: list[SegmentInfo]

class ELFSummary(BaseModel):
    total_scanned: int              # 总共扫描的文件数
    total_elf: int                  # 扫描的 ELF 文件数
    binaries: list[BinaryInfo]
    errors: list[dict]

