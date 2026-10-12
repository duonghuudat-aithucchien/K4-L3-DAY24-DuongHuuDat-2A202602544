"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Nhận diện và che mờ PII tiếng Việt: CCCD, SĐT, STK, Email.
"""
from __future__ import annotations

import re

# Regex cho từng loại PII
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_BANK_RE = re.compile(
    r"(?i)(?:STK|số\s+tài\s+khoản|so\s+tai\s+khoan|tài\s+khoản|tai\s+khoan)\s*[:#]?\s*(\d{8,18})\b"
)
_CCCD_RE = re.compile(r"(?<!\d)(\d{12})(?!\d)")
_PHONE_RE = re.compile(r"(?<!\d)(0\d{9})(?!\d)")


def detect(text: str) -> list[dict]:
    """Phát hiện các thực thể PII trong văn bản: VN_CCCD, VN_PHONE, VN_BANK_ACCOUNT, EMAIL."""
    entities: list[dict] = []
    occupied: list[tuple[int, int]] = []

    def _is_overlapping(start: int, end: int) -> bool:
        return any(start < o_end and o_start < end for o_start, o_end in occupied)

    # 1. Nhận diện EMAIL
    for match in _EMAIL_RE.finditer(text):
        start, end = match.start(), match.end()
        entities.append({"type": "EMAIL", "start": start, "end": end})
        occupied.append((start, end))

    # 2. Nhận diện VN_BANK_ACCOUNT (ưu tiên trước vì STK có thể dài 10 hoặc 12 số trùng CCCD/SĐT)
    for match in _BANK_RE.finditer(text):
        start, end = match.start(1), match.end(1)
        if not _is_overlapping(start, end):
            entities.append({"type": "VN_BANK_ACCOUNT", "start": start, "end": end})
            occupied.append((start, end))

    # 3. Nhận diện VN_CCCD (12 chữ số)
    for match in _CCCD_RE.finditer(text):
        start, end = match.start(1), match.end(1)
        if not _is_overlapping(start, end):
            entities.append({"type": "VN_CCCD", "start": start, "end": end})
            occupied.append((start, end))

    # 4. Nhận diện VN_PHONE (10 chữ số bắt đầu bằng 0)
    for match in _PHONE_RE.finditer(text):
        start, end = match.start(1), match.end(1)
        if not _is_overlapping(start, end):
            entities.append({"type": "VN_PHONE", "start": start, "end": end})
            occupied.append((start, end))

    # Sắp xếp các entity theo start tăng dần
    entities.sort(key=lambda e: e["start"])
    return entities


def redact(text: str) -> str:
    """Thay thế các thực thể PII bằng [REDACTED_<TYPE>], thay từ cuối chuỗi lên đầu."""
    entities = detect(text)
    # Sắp xếp giảm dần theo vị trí start để không làm lệch offset các vùng trước
    entities.sort(key=lambda e: e["start"], reverse=True)
    res = text
    for ent in entities:
        res = res[: ent["start"]] + f"[REDACTED_{ent['type']}]" + res[ent["end"] :]
    return res
