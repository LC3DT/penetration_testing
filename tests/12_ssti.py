"""12_ssti — SSTI 模板注入测试（EJS + 多引擎探针，60+ payload）"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.test_utils import *


def run():
    print_banner("12: SSTI 模板注入 (60+ payloads)")
    reset_counters()
    s = requests.Session()
    payloads = load_payloads("ssti")

    info("=== SSTI 注入点: 留言板评论 (POST /products/1/comment) ===")
    for p in payloads:
        try:
            r = s.post(urljoin(BASE_URL, "/products/1/comment"),
                       data={"username": "ssti_test", "content": p["payload"]},
                       timeout=TIMEOUT, allow_redirects=False)
            ok(f"[{p['category']}] {p['name']} → HTTP {r.status_code}")
        except Exception as e:
            err(f"[{p['category']}] {p['name']} → 异常: {e}")

    info("=== 验证模板注入结果 (GET /products/1) ===")
    r = s.get(urljoin(BASE_URL, "/products/1"), timeout=TIMEOUT, allow_redirects=False)

    # 检查 EJS 执行特征
    ejs_indicators = ["49", "7777777", "uid=", "root:", "daemon:", "require",
                      "process", "Buffer", "child_process", "readFileSync"]
    found = [ind for ind in ejs_indicators if ind in r.text]
    if found:
        ok(f"EJS 模板注入确认 → 发现执行痕迹: {found}")
    else:
        warn("EJS 模板注入 → 未发现执行特征（可能已被转义或拦截）")

    info("=== SSTI 注入点: 留言板 (POST /contact) ===")
    for p in payloads[:25]:
        try:
            r = s.post(urljoin(BASE_URL, "/contact"),
                       data={"name": "ssti_guest", "email": "ssti@test.com", "message": p["payload"]},
                       timeout=TIMEOUT, allow_redirects=False)
            ok(f"[contact] {p['name']} → HTTP {r.status_code}")
        except Exception as e:
            err(f"[contact] {p['name']} → 异常: {e}")

    r2 = s.get(urljoin(BASE_URL, "/contact"), timeout=TIMEOUT, allow_redirects=False)
    found2 = [ind for ind in ejs_indicators if ind in r2.text]
    if found2:
        ok(f"留言板 SSTI 确认 → 发现执行痕迹: {found2}")
    else:
        warn("留言板 SSTI → 未发现执行特征")

    info("=== SSTI 注入点: 资料更新 (POST /profile) ===")
    s2 = requests.Session()
    s2.post(urljoin(BASE_URL, "/login"), data={"username": "test", "password": "test123"},
            timeout=TIMEOUT, allow_redirects=True)
    for p in payloads[:10]:
        try:
            r = s2.post(urljoin(BASE_URL, "/profile"),
                        data={"email": "ssti@test.com", "bio": p["payload"], "avatar_url": "http://x.com"},
                        timeout=TIMEOUT, allow_redirects=False)
            ok(f"[profile] {p['name']} → HTTP {r.status_code}")
        except Exception as e:
            err(f"[profile] {p['name']} → 异常: {e}")

    print_summary()
    save_results("12_ssti")
    return STATE["fail"]


if __name__ == "__main__":
    sys.exit(run())
