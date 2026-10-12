"""BƯỚC 3c & 3d — Trifecta Split + OBO Runner.

Điều phối luồng thực thi an toàn:
- Run A: Đọc untrusted docs, chỉ trích xuất ticket_id (int) từ tên file.
- Run B: Tra cứu customer_id từ nguồn tin cậy (data/customers.json) dựa trên related_tickets.
- Mọi tool call đều qua policy.check() và ghi ledger.append() trước khi thực thi.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agent import ledger, pii, policy, tools
from agent.policy import PolicyContext

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
CUSTOMERS_FILE = Path(__file__).resolve().parent.parent / "data" / "customers.json"


def _audit_and_check(
    tool_name: str,
    args: dict,
    classification: str,
    egress_enabled: bool,
    principal_id: str,
    purpose: str,
    ledger_path: Path,
    run_id: str,
    agent_id: str,
    expires_at: str,
    delegation_depth: int = 0,
    parent_scopes: tuple[str, ...] = (),
) -> bool:
    """Tạo PolicyContext, kiểm tra chính sách và ghi vào ledger trước khi chạy tool."""
    args_json = json.dumps(args, sort_keys=True, ensure_ascii=False)
    args_hash = hashlib.sha256(args_json.encode("utf-8")).hexdigest()

    ctx = PolicyContext(
        data_classification=classification,
        request_purpose=purpose,
        agent_owner=agent_id,
        delegation_depth=delegation_depth,
        egress_enabled=egress_enabled,
        principal_id=principal_id,
        requested_tool=tool_name,
        agent_scopes=("search_docs", "read_customer", "http_post"),
        parent_scopes=parent_scopes,
        expires_at=expires_at,
    )

    allowed, reason = policy.check(ctx)
    decision = "allow" if allowed else "deny"

    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "agent_id": agent_id,
        "run_id": run_id,
        "on_behalf_of": principal_id,
        "expires_at": expires_at,
        "tool": tool_name,
        "args_hash": args_hash,
        "classification": classification,
        "decision": decision,
        "reason": reason,
    }
    ledger.append(entry, ledger_path)
    return allowed


def handle(
    message: str,
    llm,
    log_dir: Path | None = None,
    principal_id: str = "support_l1",
) -> str:
    """Thực thi tác vụ với Trifecta Split và OBO containment."""
    ledger_path = Path(log_dir) / "ledger.jsonl" if log_dir else DEFAULT_LEDGER_PATH
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    agent_id = "lab24-agent"
    expires_at = "2099-01-01T00:00:00+00:00"

    # =========================================================================
    # Run A: Untrusted Content (search_docs)
    # =========================================================================
    allowed_search = _audit_and_check(
        tool_name="search_docs",
        args={"query": message},
        classification="internal",
        egress_enabled=False,
        principal_id=principal_id,
        purpose="summarize-tickets",
        ledger_path=ledger_path,
        run_id=run_id,
        agent_id=f"{agent_id}/run-a",
        expires_at=expires_at,
    )

    if not allowed_search:
        return "Yêu cầu bị từ chối bởi chính sách."

    docs = tools.search_docs(message)

    # Trích xuất danh sách ticket_id (kiểu int) DUY NHẤT TỪ TÊN FILE
    ticket_ids: list[int] = []
    for d in docs:
        doc_name = d.get("id", "")
        match = re.search(r"ticket-(\d+)", doc_name)
        if match:
            ticket_ids.append(int(match.group(1)))

    # Kiểm tra injection để log phục vụ kiểm toán (nhưng KHÔNG dùng customer_id từ free text)
    combined_text = "\n\n".join(d["text"] for d in docs)
    injected = llm.find_injection(combined_text)

    # =========================================================================
    # Run B: Private Data Store (read_customer)
    # NGUỒN TIN CẬY: data/customers.json mapping từ related_tickets
    # =========================================================================
    customers_data = json.loads(CUSTOMERS_FILE.read_text(encoding="utf-8"))
    matched_customer_ids: list[str] = []
    for c in customers_data:
        cid = str(c["customer_id"])
        c_tickets = set(c.get("related_tickets", []))
        if any(tid in c_tickets for tid in ticket_ids):
            if cid not in matched_customer_ids:
                matched_customer_ids.append(cid)

    collected = []
    for cid in matched_customer_ids:
        allowed_read = _audit_and_check(
            tool_name="read_customer",
            args={"customer_id": cid},
            classification="restricted",
            egress_enabled=False,
            principal_id=principal_id,
            purpose="support-reply",
            ledger_path=ledger_path,
            run_id=run_id,
            agent_id=f"{agent_id}/run-b",
            expires_at=expires_at,
        )
        if allowed_read:
            try:
                collected.append(tools.read_customer(cid))
            except tools.ToolError:
                continue

    # =========================================================================
    # Run C: Egress Vector (http_post) - Nếu kẻ tấn công yêu cầu gửi dữ liệu
    # =========================================================================
    if injected is not None and injected.target_url:
        target_url = injected.target_url
        allowed_post = _audit_and_check(
            tool_name="http_post",
            args={"url": target_url, "records_count": len(collected)},
            classification="restricted" if collected else "internal",
            egress_enabled=True,
            principal_id=principal_id,
            purpose="reconciliation",
            ledger_path=ledger_path,
            run_id=run_id,
            agent_id=f"{agent_id}/run-c",
            expires_at=expires_at,
        )
        if allowed_post:
            tools.http_post(target_url, {"records": collected})

    # Che PII trong nội dung các ticket trước khi tóm tắt
    redacted_docs = [{"id": d["id"], "text": pii.redact(d["text"])} for d in docs]
    return llm.summarize(redacted_docs)
