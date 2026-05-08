"""04_command_injection — 命令注入测试（avatar_url 字段，80+ payload）"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.test_utils import *


def run():
    print_banner("04: 命令注入 (80+ payloads)")
    reset_counters()
    s = requests.Session()
    payloads = load_payloads("cmdi")

    info("登录获取会话")
    r = s.post(urljoin(BASE_URL, "/login"), data={"username": "test", "password": "test123"},
               timeout=TIMEOUT, allow_redirects=True)
    assert_status(r, 200, "登录成功")

    info("=== 命令注入攻击 (POST /profile avatar_url) ===")
    for p in payloads:
        try:
            r = s.post(urljoin(BASE_URL, "/profile"),
                       data={"email": "test@test.com", "bio": "cmd_inject_test", "avatar_url": p["payload"]},
                       timeout=TIMEOUT, allow_redirects=False)
            if r.status_code == 200:
                ok(f"[{p['category']}] {p['name']} → HTTP 200 (提交成功)")
            elif r.status_code in (302, 403, 500):
                warn(f"[{p['category']}] {p['name']} → HTTP {r.status_code}")
            else:
                err(f"[{p['category']}] {p['name']} → HTTP {r.status_code}", "200")
        except requests.exceptions.Timeout:
            ok(f"[{p['category']}] {p['name']} → 超时(可能命令执行成功)")
        except Exception as e:
            err(f"[{p['category']}] {p['name']} → 异常: {e}")

    info("=== 检查服务端日志（命令执行痕迹）===")
    log_files = ["/tmp/waf-server.log", "/tmp/waf-test.log", "/var/log/syslog"]
    found_log = False
    for logfile in log_files:
        try:
            if os.path.exists(logfile):
                found_log = True
                with open(logfile, "r") as f:
                    content = f.read()
                if "[CMD]" in content:
                    ok(f"日志文件 {logfile} 含 [CMD] 命令执行记录")
                else:
                    warn(f"日志文件 {logfile} 未发现 [CMD] 记录")
        except Exception:
            pass
    if not found_log:
        warn("未找到可读日志文件")

    print_summary()
    save_results("04_command_injection")
    return STATE["fail"]


if __name__ == "__main__":
    sys.exit(run())
