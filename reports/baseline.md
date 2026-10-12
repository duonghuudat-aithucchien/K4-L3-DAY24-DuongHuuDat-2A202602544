# Baseline — điền trong checkpoint 1

1. Agent có identity mỗi run chưa? Dẫn file/hàm:
Chưa có. Trong hàm `_naive_loop()` tại `agent/loop.py:27-30`, hàm chỉ nhận `message` và `llm`, hoàn toàn không khởi tạo `agent_id`, `run_id` hay kiểm tra danh tính người gọi (`principal_id`). Toàn bộ quá trình chạy không có cơ chế định danh hay phân quyền phiên làm việc.

2. Ai cho phép `http_post`? Dẫn file/hàm:
Không có policy hay cơ chế nào cho phép. Kẻ tấn công cài chỉ thị injection vào nội dung ticket (dữ liệu untrusted), `llm.find_injection()` ở `agent/loop.py:34` bóc tách chỉ thị và agent thực thi như một mệnh lệnh. Kẻ tấn công thông qua nội dung injection chính là bên quyết định gửi. Tại `agent/loop.py:44`, hàm gọi thẳng `tools.http_post(injected.target_url, {"records": collected})` mà không qua cổng kiểm soát nào. Trong `agent/tools.py:76-83`, hàm `http_post` chỉ kiểm tra cứng IP/port `127.0.0.1:10024`, không hề kiểm tra quyền hay loại dữ liệu.

3. Nếu gửi sai PII ra sink, bằng chứng ở đâu? Dẫn file/hàm:
Body chứa PII được đóng gói tại `agent/loop.py:44` (`{"records": collected}`, với dữ liệu khách đọc từ `tools.read_customer()` ở dòng 39). Bằng chứng việc sink nhận dữ liệu nằm ở file log `reports/sink.log`, do server `sink/sink.py` ghi lại tại dòng 46-47 (`sink/sink.py:46-47`).
