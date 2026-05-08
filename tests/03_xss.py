"""03_xss — XSS 跨站脚本测试（存储型 + 反射型，150+ payload）"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.test_utils import *


def run():
    print_banner("03: XSS 跨站脚本 (150+ payloads)")
    reset_counters()
    s = requests.Session()
    payloads = load_payloads("xss")

    # ── 商品评论 XSS (存储型) ──
    info("=== 商品评论存储型 XSS (POST /products/1/comment) ===")
    comment_count = 0
    for p in payloads:
        try:
            r = s.post(urljoin(BASE_URL, "/products/1/comment"),
                       data={"username": "xss_test", "content": p["payload"]},
                       timeout=TIMEOUT, allow_redirects=False)
            if r.status_code in (302, 200):
                ok(f"[{p['category']}] {p['name']} → HTTP {r.status_code}")
            else:
                err(f"[{p['category']}] {p['name']} → HTTP {r.status_code}", "200/302")
        except Exception as e:
            err(f"[{p['category']}] {p['name']} → 异常: {e}")
        comment_count += 1
    info(f"已提交 {comment_count} 个 XSS payload 到评论")

    # ── 存储型 XSS 验证 ──
    info("=== 存储型 XSS 验证 (GET /products/1) ===")
    r = s.get(urljoin(BASE_URL, "/products/1"), timeout=TIMEOUT, allow_redirects=False)
    assert_body(r, "智能手机", "商品详情页正常渲染")

    found_xss = 0
    xss_keywords = ["<script>", "<ScRiPt>", "onerror=", "onload=", "javascript:", "SVG", "onmouseover",
                    "onfocus", "onblur", "onkeydown", "ondrag", "oncopy", "<iframe", "<embed",
                    "<object", "<link", "onbegin", "autoFocus", "onstart", "ontoggle"]

    for kw in xss_keywords:
        if kw.lower() in r.text.lower():
            found_xss += 1
    if found_xss > 0:
        ok(f"存储型XSS验证 → 发现 {found_xss} 种未转义标签/事件")
    else:
        warn("存储型XSS验证 → 未发现未转义特征（可能已全部转义或被拦）")

    # ── 留言板 XSS ──
    info("=== 留言板存储型 XSS (POST /contact) ===")
    for p in payloads[:40]:  # 选取前40个代表性payload
        try:
            r = s.post(urljoin(BASE_URL, "/contact"),
                       data={"name": "xss_guest", "email": "xss@test.com", "message": p["payload"]},
                       timeout=TIMEOUT, allow_redirects=False)
            ok(f"[contact] {p['name']} → HTTP {r.status_code}")
        except Exception as e:
            err(f"[contact] {p['name']} → 异常: {e}")

    r = s.get(urljoin(BASE_URL, "/contact"), timeout=TIMEOUT, allow_redirects=False)
    found_contact = sum(1 for kw in xss_keywords if kw.lower() in r.text.lower())
    if found_contact > 0:
        ok(f"留言板存储XSS → 发现 {found_contact} 种未转义标签")
    else:
        warn("留言板存储XSS → 未发现未转义特征")

    print_summary()
    save_results("03_xss")
    return STATE["fail"]


if __name__ == "__main__":
    sys.exit(run())
