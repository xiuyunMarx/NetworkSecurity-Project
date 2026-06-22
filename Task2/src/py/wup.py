"""WUP request construction and validity verification (consistent with C++ wup_cca2.cpp).

WUP text format:
    WUP/1\ncmd=sync\nuid=10001\nnonce=<nonce>\nbody=browser-history-demo\nEND\n

valid_wup rules (corresponding to C++ valid_wup):
    Starts with "WUP/1\n", contains "\ncmd=", ends with "END\n".
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
