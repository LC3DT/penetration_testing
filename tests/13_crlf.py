"""13_crlf — CRLF 注入测试（HTTP 头注入 + 响应拆分 + 表单注入，40+ payload）"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.test_utils import *


def run():
    print_banner("13: CRLF 注入 (40+ payloads)")
    reset_counters()
    s = requests.Session()
    payloads = load_payloads("crlf")

    info("=== CRLF 注入: URL 参数 ===")
    url_payloads = [p for p in payloads if p["injection_point"] in ("url", "redirect")]
    for p in url_payloads:
        try:
            if p["injection_point"] == "redirect":
                r = s.get(urljoin(BASE_URL, f"/login?redirect={p['payload']}"), timeout=TIMEOUT, allow_redirects=False)
            else:
                r = s.get(urljoin(BASE_URL, f"/products?q={p['payload']}"), timeout=TIMEOUT, allow_redirects=False)
            # 检查响应头是否含有注入特征
            injected_headers = any(h for h in ["Set-Cookie", "Location", "X-Injected", "Content-Location",
                                                "X-XSS-Protection", "X-Frame", "Referrer-Policy"]
                                   if h in r.headers or h.lower() in str(r.headers).lower())
            if injected_headers:
                err(f"[url] {p['name']} → 发现注入响应头!")
            else:
                ok(f"[url] {p['name']} → HTTP {r.status_code}")
        except Exception as e:
            err(f"[url] {p['name']} → 异常: {e}")

    # ── Header 注入 ──
    info("=== CRLF 注入: HTTP Header 字段 ===")
    header_payloads = [p for p in payloads if p["injection_point"] == "header"]
    for p in header_payloads:
        try:
            # 注入到 User-Agent
            r = s.get(urljoin(BASE_URL, "/"), headers={"User-Agent": p["payload"]}, timeout=TIMEOUT, allow_redirects=False)
            ok(f"[header/UA] {p['name']} → HTTP {r.status_code}")
        except Exception as e:
            err(f"[header/UA] {p['name']} → 异常: {e}")

    for p in header_payloads[:15]:
        try:
            # 注入到 Referer
            r = s.get(urljoin(BASE_URL, "/products"),
                      headers={"Referer": p["payload"]},
                      timeout=TIMEOUT, allow_redirects=False)
            ok(f"[header/Referer] {p['name']} → HTTP {r.status_code}")
        except Exception as e:
            err(f"[header/Referer] {p['name']} → 异常: {e}")

    # ── 表单注入 ──
    info("=== CRLF 注入: 表单字段 ===")
    form_payloads = [p for p in payloads if p["injection_point"] in ("form_name", "form_email", "comment_name", "comment_content")]
    for p in form_payloads:
        try:
            data = {"name": p["payload"] if "name" in p["injection_point"] else "crlf_test",
                    "email": p["payload"] if "email" in p["injection_point"] else "crlf@test.com",
                    "message": p["payload"] if "content" in p["injection_point"] else "crlf injection test"}
            r = s.post(urljoin(BASE_URL, "/contact"), data=data, timeout=TIMEOUT, allow_redirects=False)
            ok(f"[form] {p['name']} → HTTP {r.status_code}")
        except Exception as e:
            err(f"[form] {p['name']} → 异常: {e}")

    # ── Referer/UA 日志注入 ──
    info("=== CRLF 注入: 日志注入尝试 ===")
    log_payloads = [p for p in payloads if p["injection_point"] in ("log", "referer", "user_agent")]
    for p in log_payloads:
        try:
            r = s.get(urljoin(BASE_URL, "/"),
                      headers={"Referer": p["payload"] if "referer" in p["injection_point"] else "http://test.com",
                               "User-Agent": p["payload"] if "agent" in p["injection_point"] else "CRLF/Test"},
                      timeout=TIMEOUT, allow_redirects=False)
            ok(f"[log] {p['name']} → HTTP {r.status_code}")
        except Exception as e:
            err(f"[log] {p['name']} → 异常: {e}")

    print_summary()
    save_results("13_crlf")
    return STATE["fail"]


if __name__ == "__main__":
    sys.exit(run())
