"""08_api_fuzzing — API 模糊测试（参数变异 + 关键字扫描 + 方法探测）"""

import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.test_utils import *


def run():
    print_banner("08: API 模糊测试")
    reset_counters()
    s = requests.Session()

    # ── 8.1 参数变异 ──
    info("参数变异 (GET /api/users?name=)")
    variants = [
        ("空值", ""),
        ("超长值(4096)", "A" * 4096),
        ("特殊字符", '<>&\'"{}[]|;:'),
        ("SQL关键字", "SELECT 1 FROM users"),
        ("负数", "-1"),
        ("NULL字面量", "NULL"),
    ]
    for desc, val in variants:
        try:
            r = s.get(urljoin(BASE_URL, f"/api/users?name={val}"),
                      timeout=TIMEOUT)
            ok(f"参数变异 {desc} → HTTP {r.status_code}")
        except Exception as e:
            err(f"参数变异 {desc} → {e}")

    # ── 8.2 SQL 关键字扫描 ──
    info("SQL 关键字扫描")
    keywords = ["SELECT", "UNION", "DROP", "INSERT", "DELETE", "UPDATE",
                "EXEC", "SLEEP", "WAITFOR", "DELAY", "BENCHMARK"]
    for kw in keywords:
        try:
            r = s.get(urljoin(BASE_URL, f"/api/users?name={kw}"),
                      timeout=TIMEOUT)
            ok(f"关键字 '{kw}' → HTTP {r.status_code}")
        except Exception as e:
            err(f"关键字 '{kw}' → {e}")

    # ── 8.3 HTTP 方法探测 ──
    info("HTTP 方法探测")
    methods = {
        "GET": "/api/users?name=test",
        "POST": "/api/users",
        "PUT": "/api/users",
        "DELETE": "/api/users",
        "OPTIONS": "/api/users",
        "PATCH": "/api/users",
        "HEAD": "/api/users",
    }
    for method, path in methods.items():
        try:
            if method == "GET":
                r = requests.get(urljoin(BASE_URL, path), timeout=TIMEOUT)
            elif method == "POST":
                r = requests.post(urljoin(BASE_URL, path), timeout=TIMEOUT)
            elif method == "PUT":
                r = requests.put(urljoin(BASE_URL, path), timeout=TIMEOUT)
            elif method == "DELETE":
                r = requests.delete(urljoin(BASE_URL, path), timeout=TIMEOUT)
            elif method == "OPTIONS":
                r = requests.options(urljoin(BASE_URL, path), timeout=TIMEOUT)
            elif method == "PATCH":
                r = requests.patch(urljoin(BASE_URL, path), timeout=TIMEOUT)
            elif method == "HEAD":
                r = requests.head(urljoin(BASE_URL, path), timeout=TIMEOUT)
            else:
                continue
            ok(f"{method:8s} {path} → HTTP {r.status_code}")
        except Exception as e:
            warn(f"{method:8s} {path} → {e}")

    # ── 8.4 Content-Type 变体 ──
    info("Content-Type 变体")
    content_types = [
        "application/x-www-form-urlencoded",
        "application/json",
        "text/plain",
        "multipart/form-data",
    ]
    for ct in content_types:
        try:
            r = requests.post(urljoin(BASE_URL, "/login"),
                              headers={"Content-Type": ct},
                              data="username=test&password=test" if "form" in ct else '{"username":"test","password":"test"}',
                              timeout=TIMEOUT, allow_redirects=False)
            ok(f"Content-Type: {ct} → HTTP {r.status_code}")
        except Exception as e:
            warn(f"Content-Type: {ct} → {e}")

    # ── 8.5 混合攻击 payloads ──
    info("混合攻击 payloads")
    mixed_payloads = [
        ("SQL+XSS", "'; <script>alert(1)</script> --"),
        ("SQL+HTML", "<div>' OR 1=1 --</div>"),
        ("路径+命令", "../../../tmp;id"),
    ]
    for desc, payload in mixed_payloads:
        try:
            r = s.get(urljoin(BASE_URL, f"/api/users?name={payload}"),
                      timeout=TIMEOUT)
            ok(f"混合攻击 {desc} → HTTP {r.status_code}")
        except Exception as e:
            err(f"混合攻击 {desc} → {e}")

    print_summary()
    save_results("08_api_fuzzing")
    return STATE["fail"]


if __name__ == "__main__":
    sys.exit(run())
