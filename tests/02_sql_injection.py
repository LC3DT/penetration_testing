"""02_sql_injection — SQL 注入测试（覆盖全部 9 个注入点，200+ payload）"""

import sys, os, time, random
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.test_utils import *


def run():
    print_banner("02: SQL 注入 (200+ payloads)")
    reset_counters()
    s = requests.Session()
    payloads = load_payloads("sqli")

    # ── 登录绕过 ──
    info("=== 登录绕过 (POST /login) ===")
    login_payloads = [p for p in payloads if p.get("injection_point") == "login"]
    for p in login_payloads:
        try:
            r = s.post(urljoin(BASE_URL, "/login"),
                       data={"username": p["username"], "password": p["password"]},
                       timeout=TIMEOUT, allow_redirects=False)
            status = r.status_code
            if status == 302:
                ok(f"{p['name']} → HTTP {status} (重定向)")
            else:
                warn(f"{p['name']} → HTTP {status}")
        except Exception as e:
            err(f"{p['name']} → 超时/异常: {e}")

    # ── API 用户查询注入 ──
    info("=== API 用户查询 (GET /api/users?name=) ===")
    api_user_payloads = [p for p in payloads if p.get("injection_point") == "api_users"]
    for p in api_user_payloads:
        try:
            r = s.get(urljoin(BASE_URL, f"/api/users?name={p['payload']}"), timeout=TIMEOUT)
            try:
                data = r.json().get("data", [])
                ok(f"{p['name']} → HTTP {r.status_code}, {len(data)}条")
            except Exception:
                ok(f"{p['name']} → HTTP {r.status_code}")
        except Exception as e:
            err(f"{p['name']} → 异常: {e}")

    # ── 商品搜索注入 ──
    info("=== 商品搜索注入 (GET /products?q=) ===")
    search_payloads = [p for p in payloads if p.get("injection_point") == "product_search"]
    for p in search_payloads:
        try:
            r = s.get(urljoin(BASE_URL, f"/products?q={p['payload']}"), timeout=TIMEOUT, allow_redirects=False)
            ok(f"{p['name']} → HTTP {r.status_code}")
        except Exception as e:
            err(f"{p['name']} → 异常: {e}")

    # ── 商品详情注入 ──
    info("=== 商品详情注入 (GET /products/:id) ===")
    detail_payloads = [p for p in payloads if p.get("injection_point") == "product_detail"]
    for p in detail_payloads:
        try:
            r = s.get(urljoin(BASE_URL, f"/products/{p['payload']}"), timeout=TIMEOUT, allow_redirects=False)
            ok(f"{p['name']} → HTTP {r.status_code}")
        except Exception as e:
            err(f"{p['name']} → 异常: {e}")

    # ── 注册注入 ──
    info("=== 注册注入 (POST /register) ===")
    reg_payloads = [p for p in payloads if p.get("injection_point") == "register"]
    for p in reg_payloads:
        try:
            unique = f"inject_{random.randint(10000,99999)}"
            r = s.post(urljoin(BASE_URL, "/register"),
                       data={"username": unique, "password": "pass", "email": p["payload"] if "@" not in p["payload"] else f"{unique}{p['payload']}"},
                       timeout=TIMEOUT, allow_redirects=False)
            ok(f"{p['name']} → HTTP {r.status_code}")
        except Exception as e:
            err(f"{p['name']} → 异常: {e}")

    # ── 评论注入 ──
    info("=== 评论注入 (POST /products/1/comment) ===")
    comment_payloads = [p for p in payloads if p.get("injection_point") == "comment"]
    for p in comment_payloads:
        try:
            field = p.get("field", "content")
            data = {"username": "injector", "content": "test_inject"}
            if field == "username":
                data["username"] = p["payload"]
                data["content"] = "test"
            else:
                data["content"] = p["payload"]
            r = s.post(urljoin(BASE_URL, "/products/1/comment"), data=data,
                       timeout=TIMEOUT, allow_redirects=False)
            ok(f"{p['name']} → HTTP {r.status_code}")
        except Exception as e:
            err(f"{p['name']} → 异常: {e}")

    # ── 留言注入 ──
    info("=== 留言注入 (POST /contact) ===")
    contact_payloads = [p for p in payloads if p.get("injection_point") == "contact"]
    for p in contact_payloads:
        try:
            field = p.get("field", "message")
            data = {"name": "inj_name", "email": "inj@test.com", "message": "inj_msg"}
            data[field] = p["payload"]
            r = s.post(urljoin(BASE_URL, "/contact"), data=data,
                       timeout=TIMEOUT, allow_redirects=False)
            ok(f"{p['name']} → HTTP {r.status_code}")
        except Exception as e:
            err(f"{p['name']} → 异常: {e}")

    # ── 资料更新注入 ──
    info("=== 资料更新注入 (POST /profile, 需登录) ===")
    s2 = requests.Session()
    s2.post(urljoin(BASE_URL, "/login"), data={"username": "test", "password": "test123"},
            timeout=TIMEOUT, allow_redirects=True)
    profile_payloads = [p for p in payloads if p.get("injection_point") in ("profile_email", "profile_bio", "profile_avatar")]
    for p in profile_payloads:
        try:
            data = {"email": "x@a.com", "bio": "bio", "avatar_url": ""}
            if p["injection_point"] == "profile_email":
                data["email"] = p["payload"]
            elif p["injection_point"] == "profile_bio":
                data["bio"] = p["payload"]
            else:
                data["avatar_url"] = p["payload"]
            r = s2.post(urljoin(BASE_URL, "/profile"), data=data, timeout=TIMEOUT, allow_redirects=False)
            ok(f"{p['name']} → HTTP {r.status_code}")
        except Exception as e:
            err(f"{p['name']} → 异常: {e}")

    # ── API 商品查询注入 ──
    info("=== API 商品查询注入 (GET /api/products?category=) ===")
    api_prod_payloads = [p for p in payloads if p.get("injection_point") == "api_products"]
    for p in api_prod_payloads:
        try:
            r = s.get(urljoin(BASE_URL, f"/api/products?category={p['payload']}"), timeout=TIMEOUT)
            try:
                data = r.json().get("data", [])
                ok(f"{p['name']} → HTTP {r.status_code}, {len(data)}条")
            except Exception:
                ok(f"{p['name']} → HTTP {r.status_code}")
        except Exception as e:
            err(f"{p['name']} → 异常: {e}")

    print_summary()
    save_results("02_sql_injection")
    return STATE["fail"]


if __name__ == "__main__":
    sys.exit(run())
