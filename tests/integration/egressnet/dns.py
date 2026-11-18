#!/usr/bin/env python3
"""Stand-in DNS. Every name has the A records listed in /answers/a, one address per line, read again on
every query. AAAA and everything else is answered with no records."""
import socket
import struct
from pathlib import Path

ANSWER = Path("/answers/a")
SOCK = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
SOCK.bind(("0.0.0.0", 53))


def question_end(query: bytes) -> int:
    offset = 12
    while query[offset] != 0:
        offset += 1 + query[offset]
    return offset + 5


def addresses() -> list:
    if not ANSWER.exists():
        return []
    found = []
    for line in ANSWER.read_text(encoding="utf-8").split():
        pieces = line.split(".")
        if len(pieces) == 4 and all(piece.isdigit() and int(piece) < 256 for piece in pieces):
            found.append(bytes(int(piece) for piece in pieces))
    return found


def reply(query: bytes) -> bytes:
    end = question_end(query)
    question = query[12:end]
    qtype = struct.unpack("!H", query[end - 4:end - 2])[0]
    flags = 0x8000 | (struct.unpack("!H", query[2:4])[0] & 0x0100) | 0x0080
    records = addresses() if qtype == 1 else []
    answer = b"".join(b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 1, 4) + address for address in records)
    return query[:2] + struct.pack("!HHHHH", flags, 1, len(records), 0, 0) + question + answer


while True:
    payload, peer = SOCK.recvfrom(512)
    try:
        SOCK.sendto(reply(payload), peer)
    except Exception:
        continue
