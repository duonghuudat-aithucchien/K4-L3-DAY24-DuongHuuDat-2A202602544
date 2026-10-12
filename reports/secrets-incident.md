# Secret giả trong lịch sử Git — điền trong checkpoint 4

- Scanner và phiên bản: Gitleaks v8.30.1
- Commit chứa token giả: `1bdd849` (commit `1bdd849922156c868a5ee9293d68f5b72e242d2c`)
- File, rule và kết quả quét lịch sử:
  - File: `lab-fake-secret.txt`
  - Rule: `lab24-synthetic-token` (cấu hình trong `.gitleaks.toml`)
  - Kết quả: Lệnh `gitleaks git --config .gitleaks.toml --redact .` phát hiện đúng 1 finding tại commit `1bdd849` với exit code 1 (kết quả mong đợi cho token giả).
- Kết quả quét file hiện tại:
  - Khi quét ban đầu với `gitleaks dir`, scanner phát hiện false positive trong thư mục môi trường ảo `.venv/`. Sau khi bổ sung `[allowlist]` cho đường dẫn `^\.venv/` trong `.gitleaks.toml`, quét lại file hiện tại hoàn toàn sạch (exit code 0, 0 finding) do `lab-fake-secret.txt` đã được xóa khỏi nhánh làm việc.
- Nếu đây là credential thật, cần xử lý thế nào:
  - Phải lập tức thu hồi (revoke) và thay thế/đổi mới (rotate) token tại nhà cung cấp dịch vụ phát hành token.
  - Kiểm tra và phân tích access log tại hệ thống để đánh giá xem token đã bị kẻ tấn công khai thác hay truy cập trái phép chưa.
  - Rà soát tất cả các bản sao repo (fork, clone cục bộ, bản backup, log CI/CD) để loại bỏ hoàn toàn credential lộ lọt.
- Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:
  - Xóa file khỏi HEAD (`git rm`) chỉ làm file biến mất ở commit mới nhất, nhưng toàn bộ nội dung và commit `1bdd849` vẫn nằm nguyên trong lịch sử Git (`.git/objects`). Bất kỳ ai clone repo đều có thể khôi phục lại secret bằng `git show 1bdd849` hoặc `git checkout`.
  - Ghim phụ thuộc (pin dependency/hash lock) và hook pre-commit chỉ là chốt chặn phòng ngừa lỗi ở tương lai, hoàn toàn không có khả năng tự động thu hồi hay vô hiệu hóa một credential đã phát tán ra bên ngoài trong quá khứ.
