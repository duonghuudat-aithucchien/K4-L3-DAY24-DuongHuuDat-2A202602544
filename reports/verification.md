# Verification — điền trước khi nộp

- OS / Python / Gitleaks version: Windows 11 / Python 3.14.6 / Gitleaks v8.30.1
- `python -m pytest tests/ -q`: 33 passed in 5.25s (100% tests pass, 0 failed, 0 skipped)
  - `tests/test_pii.py`: gold=118, pred=118, tp=118, precision=1.000, recall=1.000
  - `tests/test_policy.py`: 4 passed (rule tối thiểu chặn egress, data classification, PEP reason)
  - `tests/test_obo.py`: 5 passed (support_l1 deny, dpo allow, delegation scope check)
  - `tests/test_split.py`: 1 passed (KH-000777 không bao giờ bị đọc, khách hợp lệ được phục vụ)
  - `tests/test_injection.py`: 8 passed (4 biến thể x 2 vai trò đều bị chặn thành công)
  - `tests/test_ledger.py`: 3 passed (hash chain, tamper evidence, reason không rỗng)
  - `tests/test_supply_chain.py`: 3 passed (gitleaks pin v8.30.1, requirements.lock sha256 hashes, incident note)
- `pre-commit run --all-files`: Passed (Detect hardcoded secrets: Passed)
- Ledger verify: True (xác minh tính toàn vẹn `reports/ledger.jsonl` thành công)
- `reports/attack-after.log`: 0 bytes (không có dữ liệu nào lọt ra sink)
- Các lỗi còn lại: Không còn lỗi. Toàn bộ các yêu cầu bảo mật, OBO, audit ledger và supply chain đều hoạt động chính xác theo quy chuẩn.
