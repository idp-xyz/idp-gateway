#!/usr/bin/env python3
"""Stand-in DNS. Every name has the A records listed in /answers/a, one address per line, read again on
every query. AAAA and everything else is answered with no records.

/answers/mode, also read again on every query, changes how every name is answered. Absent or anything else:
as above. The others:
    nxdomain            the name does not exist; no authority section, so nothing says how long to remember that
    nxdomain-soa-<n>    the name does not exist, and an SOA record in the authority section (RFC 2308) gives
                        n seconds as the negative caching time (the record's TTL and its minimum are both n)
    servfail            the server failed
    drop                no answer at all
    closed              nothing listens on port 53: the socket is closed, and the host answers a query with ICMP
                        port unreachable. It is bound again when the mode changes, so the mode is looked at
                        every 0.2 s even when no query comes"""
import socket
import struct
import time
from pathlib import Path

ANSWER = Path("/answers/a")
MODE = Path("/answers/mode")


def listen() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 53))
    sock.settimeout(0.2)   # so the mode file is looked at now and then, with no query coming
    return sock


SOCK = listen()


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


def mode() -> str:
    return MODE.read_text(encoding="utf-8").strip() if MODE.exists() else ""


def soa(seconds: int) -> bytes:
    """An SOA record for the root zone, owner name the root, with this TTL and this minimum."""
    data = b"\x01a\x00\x01b\x00" + struct.pack("!IIIII", 1, 3600, 600, 86400, seconds)
    return b"\x00" + struct.pack("!HHIH", 6, 1, seconds, len(data)) + data


def reply(query: bytes) -> bytes:
    end = question_end(query)
    question = query[12:end]
    qtype = struct.unpack("!H", query[end - 4:end - 2])[0]
    flags = 0x8000 | (struct.unpack("!H", query[2:4])[0] & 0x0100) | 0x0080
    how = mode()
    if how == "servfail":
        return query[:2] + struct.pack("!HHHHH", flags | 2, 1, 0, 0, 0) + question
    if how == "nxdomain":
        return query[:2] + struct.pack("!HHHHH", flags | 3, 1, 0, 0, 0) + question
    if how.startswith("nxdomain-soa-") and how[len("nxdomain-soa-"):].isdigit():
        return query[:2] + struct.pack("!HHHHH", flags | 3, 1, 0, 1, 0) + question + soa(int(how[len("nxdomain-soa-"):]))
    records = addresses() if qtype == 1 else []
    answer = b"".join(b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 1, 4) + address for address in records)
    return query[:2] + struct.pack("!HHHHH", flags, 1, len(records), 0, 0) + question + answer


while True:
    if mode() == "closed":
        if SOCK is not None:
            SOCK.close()
            SOCK = None
        time.sleep(0.2)
        continue
    if SOCK is None:
        SOCK = listen()
    try:
        payload, peer = SOCK.recvfrom(512)
    except socket.timeout:
        continue
    if mode() == "drop":
        continue
    try:
        SOCK.sendto(reply(payload), peer)
    except Exception:
        continue
