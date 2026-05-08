"""05_path_traversal — 路径遍历测试（文件上传恶意文件名，60+ payload）"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.test_utils import *


def run():
    print_banner("05: 路径遍历 (60+ payloads)")
    reset_counters()
    s = requests.Session()
    payloads = load_payloads("traversal")

    info("登录获取会话")
    r = s.post(urljoin(BASE_URL, "/login"), data={"username": "test", "password": "test123"},
               timeout=TIMEOUT, allow_redirects=True)
    assert_status(r, 200, "登录成功")

    info("=== 路径遍历攻击 (POST /profile/upload) ===")
    for p in payloads:
        try:
            files = {"file": (p["payload"], b"malicious content for traversal test", "text/plain")}
            r = s.post(urljoin(BASE_URL, "/profile/upload"), files=files,
                       timeout=TIMEOUT, allow_redirects=False)
            if r.status_code in (302, 200):
                ok(f"[{p['category']}] {p['name']} → HTTP {r.status_code} ({p['payload'][:50]})")
            else:
                err(f"[{p['category']}] {p['name']} → HTTP {r.status_code}", "200/302", str(r.status_code))
        except requests.exceptions.Timeout:
            err(f"[{p['category']}] {p['name']} → 请求超时")
        except Exception as e:
            err(f"[{p['category']}] {p['name']} → 异常: {e}")

    info("=== 验证上传文件是否落在目标路径 ===")
    check_dirs = [
        os.path.join(os.path.dirname(__file__), "..", "..", "simple_html", "uploads"),
        os.path.join(os.path.dirname(__file__), "..", "..", "simple_html", "public"),
        os.path.join(os.path.dirname(__file__), "..", "..", "simple_html", "."),
    ]
    for check_dir in check_dirs:
        try:
            if os.path.exists(check_dir):
                files_found = [f for f in os.listdir(check_dir) if not f.startswith(".")]
                ok(f"目录 {os.path.basename(check_dir)} 含 {len(files_found)} 个文件")
                # 检查是否有敏感文件
                sensitive = [f for f in files_found if f in ("passwd", "shadow", "hosts", "id_rsa", "shell.php", "package.json", "server.js", ".env")]
                if sensitive:
                    err(f"发现敏感文件被写入: {sensitive}", "无", str(sensitive))
        except Exception:
            pass

    print_summary()
    save_results("05_path_traversal")
    return STATE["fail"]


if __name__ == "__main__":
    sys.exit(run())
