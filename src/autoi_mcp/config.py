"""全局配置。"""

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class FirmwareAuditConfig:
    # --- IDA（后期用）---
    ida_path: str | None = None      # IDA 安装路径，None 则自动探测
    ida_timeout: int = 300           # 单个文件超时（秒）

    # --- 默认目录 ---
    default_cgi_dir: str = "./cgi-bin"
    default_output_dir: str = "./audit_output"

    # --- 风险阈值 ---
    risk_high_threshold: int = 50    # >= 此分高风险，进 IDA
    risk_medium_threshold: int = 30  # >= 此分中风险

    # --- 并发 ---
    max_workers: int = 4

    # --- 系统库过滤 ---
    skip_system_libs: bool = True
    system_lib_patterns: tuple[str, ...] = (
        "*/lib/lib*.so*",          # libc, libpthread, libm, libdl, libgcc_s, libcrypt ...
        "*/lib/ld-*.so*",          # ld-linux, ld-uClibc ...
        "*/lib/lib*_nonshared.a",  # 静态存根
        "*/usr/lib/lib*.so*",      # /usr/lib 下的标准库
    )

    # --- 系统二进制过滤 ---
    skip_system_binaries: bool = True
    system_binary_patterns: tuple[str, ...] = (
        "*/bin/busybox",
        "*/bin/ash",
        "*/bin/sh",
        "*/bin/bash",
        "*/init",
        "*/sbin/init",
        "*/linuxrc",
        "*/.libs/*",               # autotools 中间产物
    )

    def detect_ida_path(self) -> Path | None:
        """跨平台探测 IDA 安装路径。"""
        import shutil
        candidates = [
            "idat64", "idat", "ida64", "ida",
        ]
        for name in candidates:
            found = shutil.which(name)
            if found:
                return Path(found)
        return None
