"""08_api_fuzzing — API 模糊测试（参数变异+关键字扫描+方法探测+Header fuzzing+混合攻击，100+ payload）"""

import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.test_utils import *


def run():
    print_banner("08: API 模糊测试 (100+ payloads)")
    reset_counters()
    s = requests.Session()
    data = load_payloads("api_fuzzing")

    # ── 8.1 参数变异 ──
    info("=== 参数变异 (GET /api/users?name=) ===")
    for variant in data.get("parameter_variants", []):
        try:
            val = variant["value"]
            if variant["name"] == "超长值 4096":
                val = "A" * 4096
            elif variant["name"] == "超长值 8192":
                val = "B" * 8192
            elif variant["name"] == "超长值 16384":
                val = "C" * 16384
            r = s.get(urljoin(BASE_URL, f"/api/users?name={val}"), timeout=TIMEOUT)
            ok(f"参数变异 [{variant['name']}] → HTTP {r.status_code}")
        except Exception as e:
            err(f"参数变异 [{variant['name']}] → {e}")

    # ── 8.2 SQL 关键字扫描 ──
    info("=== SQL 关键字扫描 ===")
    for kw in data.get("sql_keywords", []):
        try:
            r = s.get(urljoin(BASE_URL, f"/api/users?name={kw}"), timeout=TIMEOUT)
            ok(f"关键字 '{kw}' → HTTP {r.status_code}")
        except Exception as e:
            err(f"关键字 '{kw}' → {e}")

    # ── 8.3 HTTP 方法探测 ──
    info("=== HTTP 方法探测 ===")
    for method, path in data.get("http_methods", {}).items():
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
                r = requests.request(method, urljoin(BASE_URL, path), timeout=TIMEOUT)
            ok(f"{method:10s} {path} → HTTP {r.status_code}")
        except Exception as e:
            warn(f"{method:10s} {path} → {e}")

    # ── 8.4 Content-Type 变体 ──
    info("=== Content-Type 变体 ===")
    for ct in data.get("content_types", []):
        try:
            if "json" in ct["value"]:
                body = ct["body"]
                headers = {"Content-Type": ct["value"]}
            elif "xml" in ct["value"]:
                body = ct["body"]
                headers = {"Content-Type": ct["value"]}
            else:
                body = ct["body"]
                headers = {"Content-Type": ct["value"]}
            r = requests.post(urljoin(BASE_URL, "/login"),
                              headers=headers, data=body if "form" not in ct["value"] else body,
                              timeout=TIMEOUT, allow_redirects=False)
            ok(f"Content-Type: {ct['name']} → HTTP {r.status_code}")
        except Exception as e:
            warn(f"Content-Type: {ct['name']} → {e}")

    # ── 8.5 Header 测试 ──
    info("=== HTTP Header 测试 ===")
    for ht in data.get("header_tests", []):
        try:
            headers = {ht["header"]: ht["value"]}
            r = s.get(urljoin(BASE_URL, "/api/users?name=test"), headers=headers, timeout=TIMEOUT)
            ok(f"Header '{ht['header']}: {ht['value'][:30]}' → HTTP {r.status_code}")
        except Exception as e:
            err(f"Header '{ht['header']}' → {e}")

    # ── 8.6 混合攻击 payloads ──
    info("=== 混合攻击 payloads ===")
    for mp in data.get("mixed_attack_payloads", []):
        try:
            if "HPP" in mp["name"]:
                r = s.get(urljoin(BASE_URL, f"/api/users?{mp['payload']}"), timeout=TIMEOUT)
            else:
                r = s.get(urljoin(BASE_URL, f"/api/users?name={mp['payload']}"), timeout=TIMEOUT)
            ok(f"混合攻击 [{mp['name']}] → HTTP {r.status_code}")
        except Exception as e:
            err(f"混合攻击 [{mp['name']}] → {e}")

    print_summary()
    save_results("08_api_fuzzing")
    return STATE["fail"]


if __name__ == "__main__":
    sys.exit(run())
