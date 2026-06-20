"""WUP 请求构造与有效性校验（与 C++ wup_cca2.cpp 一致）。

WUP 文本格式:
    WUP/1\\ncmd=sync\\nuid=10001\\nnonce=<nonce>\\nbody=browser-history-demo\\nEND\\n

valid_wup 规则（对应 C++ valid_wup）:
    以 "WUP/1\\n" 开头，含 "\\ncmd="，以 "END\\n" 结尾。
"""

from __future__ import annotations


def build_wup_request(nonce: str) -> bytes:
    text = (
        "WUP/1\n"
        "cmd=sync\n"
        "uid=10001\n"
        f"nonce={nonce}\n"
        "body=browser-history-demo\n"
        "END\n"
    )
    return text.encode("utf-8")


def valid_wup(plain: bytes) -> bool:
    return (
        plain.startswith(b"WUP/1\n")
        and b"\ncmd=" in plain
        and plain.endswith(b"END\n")
    )
