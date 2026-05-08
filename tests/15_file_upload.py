"""15_file_upload — 文件上传绕过测试（恶意文件类型+扩展名+MIME+Polyglot，60+ payload）"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.test_utils import *


def run():
    print_banner("15: 文件上传绕过 (60+ payloads)")
    reset_counters()
    s = requests.Session()
    payloads = load_payloads("file_upload")

    info("登录获取会话")
    r = s.post(urljoin(BASE_URL, "/login"), data={"username": "test", "password": "test123"},
               timeout=TIMEOUT, allow_redirects=True)
    assert_status(r, 200, "登录成功")

    info("=== 恶意文件上传 (POST /profile/upload) ===")

    for p in payloads:
        try:
            content = p.get("content", "malicious upload test content")
            if isinstance(content, str) and content.startswith("A" * 100):
                content = bytes(content, "utf-8")
            elif isinstance(content, str):
                content = content.encode("utf-8", errors="ignore")

            files = {"file": (p["payload"], content, p.get("content_type", "text/plain"))}
            r = s.post(urljoin(BASE_URL, "/profile/upload"), files=files,
                       timeout=TIMEOUT, allow_redirects=False)
            if r.status_code in (302, 200):
                ok(f"[{p['category']}] {p['name']} → HTTP {r.status_code} ({p['payload'][:40]})")
            else:
                err(f"[{p['category']}] {p['name']} → HTTP {r.status_code}", "200/302", str(r.status_code))
        except Exception as e:
            err(f"[{p['category']}] {p['name']} → 异常: {e}")

    info("=== 验证恶意文件是否可执行 ===")
    uploads_dir = os.path.join(os.path.dirname(__file__), "..", "..", "simple_html", "uploads")
    if os.path.exists(uploads_dir):
        files_found = os.listdir(uploads_dir)
        dangerous = [f for f in files_found if any(f.endswith(ext) for ext in
                     (".php", ".phtml", ".phar", ".php5", ".php7", ".asp", ".aspx",
                      ".jsp", ".jspx", ".cfm", ".cfc", ".py", ".pl", ".cgi", ".sh",
                      ".shtml", ".stm", ".htaccess", ".user.ini", ".config"))]
        if dangerous:
            err(f"发现可执行文件类型: {dangerous[:10]}", "无", str(dangerous[:10]))
        else:
            ok(f"uploads/ 未发现可执行文件类型 (共 {len(files_found)} 个文件)")
    else:
        warn(f"uploads 目录不存在: {uploads_dir}")

    info("=== 验证上传文件的访问性 ===")
    for f in payloads[:5]:
        try:
            r = s.get(urljoin(BASE_URL, f"/uploads/{f['payload']}"), timeout=TIMEOUT, allow_redirects=False)
            if r.status_code == 200:
                warn(f"文件可公开访问: /uploads/{f['payload']} → HTTP 200 (内容长度: {len(r.content)})")
            else:
                ok(f"文件 /uploads/{f['payload']} → HTTP {r.status_code}")
        except Exception:
            pass

    print_summary()
    save_results("15_file_upload")
    return STATE["fail"]


if __name__ == "__main__":
    sys.exit(run())
