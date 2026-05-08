"""01_baseline — 基础功能验证，确保正常业务逻辑可用"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.test_utils import *


def run():
    print_banner("01: 基础功能验证")
    reset_counters()
    s = requests.Session()

    # ── 公开页面 ──
    info("公开页面访问")
    r = s.get(urljoin(BASE_URL, "/"), timeout=TIMEOUT, allow_redirects=False)
    assert_status(r, 200, "首页")
    assert_body(r, "TechShop", "首页含品牌名")

    r = s.get(urljoin(BASE_URL, "/products"), timeout=TIMEOUT, allow_redirects=False)
    assert_status(r, 200, "商品列表")
    assert_body(r, "智能手机", "商品列表含商品名")

    r = s.get(urljoin(BASE_URL, "/products/1"), timeout=TIMEOUT, allow_redirects=False)
    assert_status(r, 200, "商品详情 /1")
    assert_body(r, "智能手机", "商品详情含商品名")

    r = s.get(urljoin(BASE_URL, "/products/999"), timeout=TIMEOUT, allow_redirects=False)
    assert_status(r, 404, "不存在商品 /999")
    assert_body(r, "404", "404页面")

    r = s.get(urljoin(BASE_URL, "/nonexistent"), timeout=TIMEOUT, allow_redirects=False)
    assert_status(r, 404, "不存在路由")

    r = s.get(urljoin(BASE_URL, "/login"), timeout=TIMEOUT, allow_redirects=False)
    assert_status(r, 200, "登录页")
    assert_body(r, "用户登录", "含登录表单")

    r = s.get(urljoin(BASE_URL, "/register"), timeout=TIMEOUT, allow_redirects=False)
    assert_status(r, 200, "注册页")
    assert_body(r, "用户注册", "含注册表单")

    r = s.get(urljoin(BASE_URL, "/contact"), timeout=TIMEOUT, allow_redirects=False)
    assert_status(r, 200, "留言板")
    assert_body(r, "留言板", "含留言列表")

    # ── 需认证页面（未登录） ──
    info("需认证页面（未登录→302重定向）")
    r = s.get(urljoin(BASE_URL, "/dashboard"), timeout=TIMEOUT, allow_redirects=False)
    assert_status(r, 302, "未登录 /dashboard")
    assert_redirect(r, "/login", "重定向到登录")

    r = s.get(urljoin(BASE_URL, "/profile"), timeout=TIMEOUT, allow_redirects=False)
    assert_status(r, 302, "未登录 /profile")
    assert_redirect(r, "/login", "重定向到登录")

    # ── 登录 ──
    info("登录流程")
    r = s.post(urljoin(BASE_URL, "/login"), data={"username": "test", "password": "test123"},
               timeout=TIMEOUT, allow_redirects=False)
    assert_status(r, 302, "登录POST /login")
    assert_redirect(r, "/dashboard", "重定向到dashboard")

    # ── 登录后页面 ──
    info("已登录页面")
    r = s.get(urljoin(BASE_URL, "/dashboard"), timeout=TIMEOUT, allow_redirects=False)
    assert_status(r, 200, "已登录 /dashboard")
    assert_body(r, "test", "页面含用户名")

    r = s.get(urljoin(BASE_URL, "/profile"), timeout=TIMEOUT, allow_redirects=False)
    assert_status(r, 200, "已登录 /profile")
    assert_body(r, "email", "含资料表单")

    # ── 更新资料 ──
    info("更新个人资料")
    r = s.post(urljoin(BASE_URL, "/profile"),
               data={"email": "updated@test.com", "bio": "自动化测试更新", "avatar_url": ""},
               timeout=TIMEOUT, allow_redirects=False)
    assert_body(r, "保存成功", "更新成功")

    # ── 留言 PRG ──
    info("留言提交 (PRG)")
    r = s.post(urljoin(BASE_URL, "/contact"),
               data={"name": "AutoTest", "email": "auto@test.com", "message": "自动化测试留言"},
               timeout=TIMEOUT, allow_redirects=False)
    assert_status(r, 302, "留言POST→302")
    assert_redirect(r, "/contact", "重定向回留言板")

    r = s.get(urljoin(BASE_URL, "/contact?success=1"), timeout=TIMEOUT, allow_redirects=False)
    assert_body(r, "留言成功", "PRG后含成功提示")

    # ── 退出 ──
    info("退出登录")
    r = s.get(urljoin(BASE_URL, "/logout"), timeout=TIMEOUT, allow_redirects=False)
    assert_status(r, 302, "退出 /logout")
    assert_redirect(r, "/", "重定向到首页")

    r = s.get(urljoin(BASE_URL, "/dashboard"), timeout=TIMEOUT, allow_redirects=False)
    assert_status(r, 302, "退出后 /dashboard→登录")

    # ── 商品搜索 ──
    info("商品搜索")
    r = s.get(urljoin(BASE_URL, "/products?q=手机"), timeout=TIMEOUT, allow_redirects=False)
    assert_status(r, 200, "搜索商品")
    assert_body(r, "智能手机", "搜索结果含手机")

    print_summary()
    save_results("01_baseline")
    return STATE["fail"]


if __name__ == "__main__":
    sys.exit(run())
