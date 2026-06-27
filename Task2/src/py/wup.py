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
