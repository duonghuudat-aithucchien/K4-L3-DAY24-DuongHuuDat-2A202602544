"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

Ghi nhật ký kiểm toán JSONL với chuỗi băm sha256 (hash chain).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def append(entry: dict, path: Path) -> dict:
    """Thêm một entry vào ledger tại path, tự động gắn prev_hash và hash."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    prev_hash = "0" * 64
    if path.exists():
        content = path.read_text(encoding="utf-8").strip()
        if content:
            last_line = content.splitlines()[-1]
            try:
                last_entry = json.loads(last_line)
                prev_hash = last_entry.get("hash", "0" * 64)
            except Exception:
                pass

    record = dict(entry)
    record["prev_hash"] = prev_hash
    record.pop("hash", None)

    # Tính sha256 với sort_keys=True để thứ tự key không ảnh hưởng
    serialized = json.dumps(record, sort_keys=True, ensure_ascii=False)
    record["hash"] = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return record


def verify(path: Path) -> bool:
    """Xác minh toàn bộ file ledger: kiểm tra reason, prev_hash và hash từng dòng."""
    path = Path(path)
    if not path.exists():
        return True

    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        return True

    expected_prev = "0" * 64
    for line in lines:
        try:
            entry = json.loads(line)
        except Exception:
            return False

        # Kiểm tra reason không được rỗng
        if not entry.get("reason"):
            return False

        # Kiểm tra chuỗi băm liền trước
        if entry.get("prev_hash") != expected_prev:
            return False

        stored_hash = entry.get("hash")
        if not stored_hash:
            return False

        # Tính lại hash dòng này (không chứa trường hash)
        to_hash = {k: v for k, v in entry.items() if k != "hash"}
        calc_serialized = json.dumps(to_hash, sort_keys=True, ensure_ascii=False)
        calculated_hash = hashlib.sha256(calc_serialized.encode("utf-8")).hexdigest()

        if stored_hash != calculated_hash:
            return False

        expected_prev = stored_hash

    return True
