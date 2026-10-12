# Compliance mapping — điền trong checkpoint 5

| Nguồn / yêu cầu | Control đã làm | Evidence file:dòng | Giới hạn |
|---|---|---|---|
| Luật 91/2025/QH15 (Bảo vệ dữ liệu cá nhân) | Kiểm soát quyền truy cập PII theo vai trò (OBO) và mục đích; che mờ (redact) CCCD, STK, SĐT, email trước khi đưa vào tóm tắt | `agent/policy.py:46-95`, `agent/pii.py:18-70`, `agent/runner.py:87-124` | Dữ liệu giả lập (synthetic), danh tính mô phỏng qua fixtures chưa tích hợp IAM/SSO production |
| NĐ 356/2025/NĐ-CP (Nhật ký xử lý dữ liệu & kiểm toán) | Sổ cái kiểm toán bất biến (Audit Ledger) lưu băm tham số `args_hash`, liên kết chuỗi băm SHA-256 (`prev_hash`, `hash`), mọi quyết định đều có `reason` | `agent/ledger.py:13-79`, `agent/runner.py:27-60`, `reports/ledger.jsonl:1-4` | Hash chain lưu cục bộ trong file JSONL, chưa neo dấu thời gian ra dịch vụ tin cậy bên ngoài |
| Luật AI 134/2025/QH15 (An toàn hệ thống AI) | Phân tách ranh giới kiến trúc Trifecta Split; chặn đứng việc AI tự ý thực thi chỉ thị độc hại gửi dữ liệu ra bên ngoài | `agent/runner.py:63-145`, `agent/policy.py:42-45` | Thử nghiệm trên mô hình MockLLM xác định, chưa đánh giá độ bền vững trước jailbreak đa phương thức |
| OWASP ASI01, ASI03, ASI04 | ASI01 (Prompt Injection): Trifecta split không truyền free text sang Run B; ASI03 (Supply Chain): Pin Gitleaks v8.30.1 và hash lock dependencies; ASI04 (Exfiltration): Chặn cứng egress restricted tại PEP | `agent/runner.py:80-145`, `.pre-commit-config.yaml:1-6`, `requirements.lock:1-120`, `agent/policy.py:42-45` | Môi trường lab thử nghiệm cục bộ, cổng nhận sink chỉ trỏ localhost `127.0.0.1:10024` |

Chỉ ghi điều khoản cụ thể khi đã đối chiếu văn bản gốc. Mô phỏng kỹ thuật không tự chứng minh tuân thủ pháp luật.
