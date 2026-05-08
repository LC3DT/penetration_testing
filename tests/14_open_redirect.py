"""14_open_redirect — 开放重定向测试（URL 重定向参数，40+ payload）"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.test_utils import *


def run():
    print_banner("14: 开放重定向 (40+ payloads)")
    reset_counters()
    s = requests.Session()
    payloads = load_payloads("open_redirect")

    info("=== 重定向参数测试 (GET /login?redirect=) ===")

    for p in payloads:
        try:
            r = s.get(urljoin(BASE_URL, f"/login?redirect={p['payload']}"), timeout=TIMEOUT, allow_redirects=False)
            location = r.headers.get("Location", "")

            if r.status_code in (301, 302, 303, 307, 308):
                # 有重定向，检查目标
                is_external = any(evil in location for evil in
                                  ["evil.com", "phishing", "attacker", "javascript:", "data:", "vbscript:", "file://"])
                if is_external:
                    err(f"[{p['category']}] {p['name']} → 重定向到恶意URL: {location[:60]}")
                else:
                    ok(f"[{p['category']}] {p['name']} → 重定向到 {location[:50]}")
            else:
                ok(f"[{p['category']}] {p['name']} → HTTP {r.status_code} (无重定向)")
        except Exception as e:
            err(f"[{p['category']}] {p['name']} → 异常: {e}")

    info("=== 重定向参数测试: 其他可能的重定向点 ===")
    redirect_endpoints = ["/register?redirect=", "/products?redirect=", "/contact?redirect="]
    for endpoint in redirect_endpoints:
        for p in payloads[:10]:
            try:
                r = s.get(urljoin(BASE_URL, f"{endpoint}{p['payload']}"), timeout=TIMEOUT, allow_redirects=False)
                ok(f"[{endpoint}] {p['name']} → HTTP {r.status_code}")
            except Exception as e:
                err(f"[{endpoint}] {p['name']} → 异常: {e}")

    info("=== 检查 Referer 头泄露 ===")
    s2 = requests.Session()
    s2.post(urljoin(BASE_URL, "/login"), data={"username": "test", "password": "test123"},
            timeout=TIMEOUT, allow_redirects=True)
    for p in payloads[:5]:
        try:
            r = s2.get(urljoin(BASE_URL, "/products"), headers={"Referer": f"{p['payload']}"},
                       timeout=TIMEOUT, allow_redirects=False)
            ok(f"[referer_leak] {p['name']} → HTTP {r.status_code}")
        except Exception as e:
            err(f"[referer_leak] {p['name']} → 异常: {e}")

    print_summary()
    save_results("14_open_redirect")
    return STATE["fail"]


if __name__ == "__main__":
    sys.exit(run())
