# DPIA-lite — điền trong checkpoint 5

1. Loại dữ liệu và phân loại:
- Dữ liệu phiếu hỗ trợ (`corpus/*.md`): Phân loại `internal`/`public`. Chứa nội dung câu hỏi, khiếu nại của người dùng và là bề mặt có thể bị kẻ tấn công cài mã độc prompt injection.
- Dữ liệu hồ sơ khách hàng (`data/customers.json`): Phân loại `restricted`. Chứa thông tin nhận dạng cá nhân và dữ liệu tài chính nhạy cảm (PII: CCCD 12 số, số điện thoại, số tài khoản ngân hàng, họ tên, email).

2. Mục đích xử lý và principal:
- Mục đích xử lý: `summarize-tickets` (tổng hợp nội dung các ticket tuần này) và `support-reply` (hỗ trợ xử lý thông tin đối soát cho khách hàng).
- Phân quyền theo Principal (OBO):
  - `support_l1`: Chỉ được cấp quyền tìm kiếm ticket (`search_docs`), tuyệt đối không được phép đọc hồ sơ khách hàng (`read_customer`).
  - `dpo`: Được quyền đọc hồ sơ khách hàng hợp lệ gắn với ticket để thực hiện nhiệm vụ đối soát và kiểm toán dữ liệu.

3. Dữ liệu đi qua những run/tool nào, endpoint nào:
- Run A: Gọi `tools.search_docs` nạp toàn văn ticket. Nội dung free text của kẻ tấn công được chặn lại tại Run A, chỉ có mảng số ticket (int) đã khử khuẩn được chuyển tiếp sang Run B.
- Run B: Dựa vào số ticket để tra cứu khách hàng liên quan trong `data/customers.json`, gọi `tools.read_customer` sau khi qua cổng kiểm tra PEP.
- Endpoint egress: Chỉ giới hạn duy nhất tại địa chỉ thử nghiệm nội bộ `http://127.0.0.1:10024/reconcile`. Toàn bộ yêu cầu POST ra ngoài chứa dữ liệu restricted đều bị chặn ngay tại PEP.

4. Bằng chứng deny/allow và giới hạn của mock:
- Bằng chứng: File `reports/attack-after.log` hoàn toàn rỗng (0 byte), không có PII nào lọt ra ngoài. Sổ cái `reports/ledger.jsonl` ghi rõ các bản ghi `decision="allow"` cho tác vụ hợp lệ và `decision="deny"` cho yêu cầu `http_post` trái phép kèm lý do cụ thể.
- Giới hạn của mock: Bài lab sử dụng MockLLM với các marker từ khóa cố định và dữ liệu giả lập (synthetic data). Đây là mô hình học tập, không thay thế cho hệ thống đánh giá tác động bảo vệ dữ liệu (DPIA) chính thức trên môi trường production.
