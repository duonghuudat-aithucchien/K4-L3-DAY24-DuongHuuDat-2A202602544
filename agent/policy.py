"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call.

Kiểm soát quyền truy cập, OBO (principal, scopes, purpose, TTL) và chặn rò rỉ egress.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PRINCIPALS_PATH = Path(__file__).resolve().parent.parent / "data" / "principals.json"


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _load_principals() -> dict:
    if PRINCIPALS_PATH.exists():
        try:
            return json.loads(PRINCIPALS_PATH.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def check(context: PolicyContext) -> tuple[bool, str]:
    """Kiểm tra chính sách bảo mật cho từng tool call (PEP).
    Trả về (allow: bool, reason: str). Lý do không bao giờ được để trống.
    """
    # 1. Kiểm tra tính hợp lệ của phân loại dữ liệu
    valid_classifications = {"public", "internal", "restricted"}
    if context.data_classification not in valid_classifications:
        return False, f"Phân loại dữ liệu không hợp lệ: '{context.data_classification}'"

    # 2. Rule tối thiểu: Dữ liệu restricted đi kèm egress_enabled=True BẮT BUỘC DENY
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "Egress bị từ chối: dữ liệu restricted không được phép gọi network/ra ngoài mạng"

    # 3. Kiểm tra danh tính principal và quyền OBO
    if context.principal_id:
        principals = _load_principals()
        if context.principal_id not in principals:
            return False, f"Danh tính người ra lệnh không xác định: '{context.principal_id}'"

        p_info = principals[context.principal_id]

        # Kiểm tra thời hạn hiệu lực (expires_at)
        if context.expires_at:
            try:
                exp_dt = datetime.fromisoformat(context.expires_at)
                if exp_dt.tzinfo is None:
                    exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) > exp_dt:
                    return False, f"Phiên làm việc đã hết hạn lúc {context.expires_at}"
            except Exception:
                return False, f"Định dạng thời gian expires_at không hợp lệ: '{context.expires_at}'"

        # Kiểm tra mục đích (purpose)
        allowed_purposes = p_info.get("purposes", [])
        if context.request_purpose and context.request_purpose not in allowed_purposes:
            return (
                False,
                f"Mục đích '{context.request_purpose}' không được phép đối với principal '{context.principal_id}'",
            )

        # Tính toán tập quyền công cụ hiệu lực
        principal_allowed_tools = set(p_info.get("allowed_tools", []))
        agent_scopes = set(context.agent_scopes) if context.agent_scopes else principal_allowed_tools
        effective_tools = principal_allowed_tools & agent_scopes

        # Nếu có ủy quyền (delegation_depth > 0), phải giao với parent_scopes
        if context.delegation_depth > 0:
            parent_scopes = set(context.parent_scopes)
            effective_tools = effective_tools & parent_scopes

        # Kiểm tra requested_tool
        if context.requested_tool and context.requested_tool not in effective_tools:
            return (
                False,
                f"Tool '{context.requested_tool}' không nằm trong quyền hạn hiệu lực của principal '{context.principal_id}'",
            )

    # 4. Khi tất cả điều kiện đều thỏa mãn
    return (
        True,
        f"Chấp thuận: principal '{context.principal_id or 'anonymous'}' được phép thực thi tool '{context.requested_tool or 'none'}' cho mục đích '{context.request_purpose}'",
    )
