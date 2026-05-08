"""16_nosql — NoSQL 注入测试（MongoDB/CouchDB/Redis 注入探针，50+ payload）"""

import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.test_utils import *


def run():
    print_banner("16: NoSQL 注入 (50+ payloads)")
    reset_counters()
    s = requests.Session()
    payloads = load_payloads("nosql")

    info("=== NoSQL 注入: JSON 请求体 (POST /login) ===")
    json_payloads = [p for p in payloads if p["category"] in ("json_body", "login_bypass") or "json" in p.get("category", "")]
    for p in json_payloads:
        try:
            r = requests.post(urljoin(BASE_URL, "/login"),
                              headers={"Content-Type": "application/json"},
                              data=json.dumps(p["payload"]) if isinstance(p["payload"], dict) else p["payload"],
                              timeout=TIMEOUT, allow_redirects=False)
            ok(f"[json] {p['name']} → HTTP {r.status_code}")
        except Exception as e:
            err(f"[json] {p['name']} → 异常: {e}")

    info("=== NoSQL 注入: URL 参数编码 (GET /api/users) ===")
    url_payloads = [p for p in payloads if p["category"] in ("url_encode", "comparison", "regex")]
    for p in url_payloads:
        try:
            if isinstance(p["payload"], str) and "[" in p["payload"]:
                r = s.get(urljoin(BASE_URL, f"/api/users?{p['payload']}"), timeout=TIMEOUT)
            elif isinstance(p["payload"], str) and p["payload"].startswith("{"):
                # JSON in URL query
                r = s.get(urljoin(BASE_URL, f"/api/users?name={p['payload']}"), timeout=TIMEOUT)
            else:
                r = s.get(urljoin(BASE_URL, f"/api/users?name={p['payload']}"), timeout=TIMEOUT)
            ok(f"[url] {p['name']} → HTTP {r.status_code}")
        except Exception as e:
            err(f"[url] {p['name']} → 异常: {e}")

    info("=== NoSQL 注入: JSON POST (POST /register) ===")
    for p in payloads[:10]:
        try:
            r = requests.post(urljoin(BASE_URL, "/register"),
                              headers={"Content-Type": "application/json"},
                              data=json.dumps({"username": f"nosql_{p['name'][:5]}",
                                                "password": "test123",
                                                "email": f"nosql@test.com",
                                                "bio": p["payload"]} if isinstance(p["payload"], str) else p["payload"]),
                              timeout=TIMEOUT, allow_redirects=False)
            ok(f"[register] {p['name']} → HTTP {r.status_code}")
        except Exception as e:
            err(f"[register] {p['name']} → 异常: {e}")

    info("=== NoSQL 盲注测试 (CouchDB/Redis 协议) ===")
    couch_payloads = [p for p in payloads if p["category"] in ("couchdb", "redis")]
    for p in couch_payloads:
        try:
            r = requests.post(urljoin(BASE_URL, "/login"),
                              headers={"Content-Type": "application/json"},
                              data=json.dumps(p["payload"]) if isinstance(p["payload"], dict) else p["payload"],
                              timeout=TIMEOUT, allow_redirects=False)
            ok(f"[{p['category']}] {p['name']} → HTTP {r.status_code}")
        except Exception as e:
            err(f"[{p['category']}] {p['name']} → 异常: {e}")

    info("=== NoSQL 逻辑操作符注入 ===")
    logical_payloads = [p for p in payloads if p["category"] in ("logical", "expr", "eval")]
    for p in logical_payloads:
        try:
            r = requests.post(urljoin(BASE_URL, "/login"),
                              headers={"Content-Type": "application/json"},
                              data=json.dumps({"username": p["payload"]}) if isinstance(p["payload"], dict) else p["payload"],
                              timeout=TIMEOUT, allow_redirects=False)
            ok(f"[logical] {p['name']} → HTTP {r.status_code}")
        except Exception as e:
            err(f"[logical] {p['name']} → 异常: {e}")

    print_summary()
    save_results("16_nosql")
    return STATE["fail"]


if __name__ == "__main__":
    sys.exit(run())
