"""05_path_traversal — 路径遍历测试（文件上传恶意文件名）"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.test_utils import *


TRAVERSAL_PAYLOADS = [
    ("基础遍历", "../../../etc/passwd"),
    ("URL编码", "..%2f..%2f..%2fetc%2fpasswd"),
    ("双写绕过", "....//....//....//etc/passwd"),
    ("Windows路径", "..\\..\\windows\\system32\\config\\sam"),
    ("Null截断", "../../etc/passwd%00.png"),
    ("绝对路径", "/etc/passwd"),
    ("超深遍历", "../../../../../../../../etc/passwd"),
    ("双重编码", "..%252f..%252f..%252fetc%252fpasswd"),
    ("PHPShell", "../../../var/www/html/shell.php"),
]


def run():
    print_banner("05: 路径遍历 (文件上传)")
    reset_counters()
    s = requests.Session()

    info("登录获取会话")
    r = s.post(urljoin(BASE_URL, "/login"), data={"username": "test", "password": "test123"},
               timeout=TIMEOUT, allow_redirects=True)
    assert_status(r, 200, "登录成功")

    info("路径遍历攻击 (POST /profile/upload)")
    for desc, filename in TRAVERSAL_PAYLOADS:
        try:
            files = {"file": (filename, b"malicious content", "text/plain")}
            r = s.post(urljoin(BASE_URL, "/profile/upload"), files=files,
                       timeout=TIMEOUT, allow_redirects=False)
            if r.status_code in (302, 200):
                ok(f"{desc} → HTTP {r.status_code} ({filename[:40]})")
            else:
                err(f"{desc} → HTTP {r.status_code} (期望: 200/302)", "200/302", str(r.status_code))
        except requests.exceptions.Timeout:
            err(f"{desc} → 请求超时")
        except Exception as e:
            err(f"{desc} → 异常: {e}")

    info("验证上传的文件是否存在于 uploads/ 目录")
    uploads_dir = os.path.join(BASE_URL.replace("http://", ""), "../../uploads")
    try:
        check_dir = os.path.join(os.path.dirname(__file__), "..", "..", "simple_html", "uploads")
        if os.path.exists(check_dir):
            files_found = os.listdir(check_dir)
            ok(f"uploads/ 目录含 {len(files_found)} 个文件")
        else:
            warn(f"uploads 目录不存在: {check_dir}")
    except Exception as e:
        warn(f"无法检查 uploads 目录: {e}")

    print_summary()
    save_results("05_path_traversal")
    return STATE["fail"]


if __name__ == "__main__":
    sys.exit(run())
