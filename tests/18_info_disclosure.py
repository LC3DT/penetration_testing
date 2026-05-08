"""18_info_disclosure — 信息泄露测试（路径探测+敏感文件+安全头检查+错误信息，40+ payload）"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.test_utils import *


def run():
    print_banner("18: 信息泄露 (40+ payloads)")
    reset_counters()
    s = requests.Session()
    payloads = load_payloads("info_disclosure")

    # ── HTTP 安全头检查 ──
    info("=== 安全响应头检查 ===")
    header_checks = [p for p in payloads if p.get("check_type") in ("header", "header_missing")]
    r = s.get(urljoin(BASE_URL, "/"), timeout=TIMEOUT, allow_redirects=False)
    for chk in header_checks:
        header_name = chk["check_header"]
        if chk.get("check_type") == "header_missing":
            if header_name in r.headers:
                warn(f"[安全头] {header_name} → 已设置: {r.headers[header_name][:80]}")
            else:
                err(f"[安全头缺失] {header_name}", "应设置", "未设置")
        else:
            if header_name in r.headers:
                val = r.headers[header_name][:50]
                if "Server" in header_name or "Powered" in header_name:
                    warn(f"[信息泄露] {header_name} → {val}")
                else:
                    ok(f"[安全头] {header_name} → 已设置")
            else:
                ok(f"[安全头] {header_name} → 未设置（可能不需要）")

    # ── 敏感路径探测 ──
    info("=== 敏感路径/文件探测 ===")
    path_checks = [p for p in payloads if p.get("check_type") == "path"]
    for chk in path_checks:
        try:
            r = None
            if chk.get("check_type_method") == "TRACE":
                r = requests.request("TRACE", urljoin(BASE_URL, chk["path"]), timeout=TIMEOUT)
            elif chk.get("check_type_method") == "PUT":
                r = requests.put(urljoin(BASE_URL, chk["path"]), data="test", timeout=TIMEOUT)
            else:
                r = s.get(urljoin(BASE_URL, chk["path"]), timeout=TIMEOUT, allow_redirects=False)

            if r.status_code == 200:
                # 敏感文件可访问
                sensitive_keywords = ["passwd", ".env", ".git", "backup", "private", "config",
                                      "debug", "admin", "Dockerfile", "package.json", "data.db"]
                is_sensitive = any(kw in chk["path"] for kw in sensitive_keywords)
                if is_sensitive:
                    content_len = len(r.content)
                    err(f"[敏感暴露] {chk['path']} → HTTP 200, 内容长度: {content_len}", "应禁止", "可访问")
                else:
                    warn(f"[路径] {chk['path']} → HTTP 200 (内容长度: {len(r.content)})")
            elif r.status_code == 403:
                ok(f"[路径] {chk['path']} → HTTP 403 (禁止)")
            elif r.status_code == 404:
                pass  # 正常不存在，不记录
            else:
                ok(f"[路径] {chk['path']} → HTTP {r.status_code}")
        except Exception as e:
            warn(f"[路径] {chk['path']} → 异常: {e}")

    # ── 错误页面信息泄露 ──
    info("=== 错误页面信息泄露检查 ===")
    error_checks = [p for p in payloads if p.get("check_type") == "error_page"]
    for chk in error_checks:
        try:
            r = s.get(urljoin(BASE_URL, chk["path"]), timeout=TIMEOUT, allow_redirects=False)
            info_leak_keywords = ["Exception", "Error", "Stack", "Trace", "at /", "node_modules",
                                  "throw", "SyntaxError", "TypeError", "ReferenceError",
                                  "/simple_html/", "server.js", "db.js", "SQLite"]
            leaked = [kw for kw in info_leak_keywords if kw.lower() in r.text.lower()]
            if leaked:
                err(f"[错误页泄露] {chk['path']} → 泄露关键词: {leaked[:5]}", "不泄露路径", f"泄露{len(leaked)}个")
            else:
                ok(f"[错误页] {chk['path']} → 无敏感信息泄露 (HTTP {r.status_code})")
        except Exception as e:
            warn(f"[错误页] {chk['path']} → 异常: {e}")

    # ── Cookie 安全标志检查 ──
    info("=== Cookie 安全标志检查 ===")
    r = s.get(urljoin(BASE_URL, "/"), timeout=TIMEOUT, allow_redirects=False)
    cookies = r.headers.get("Set-Cookie", "")
    if cookies:
        if "Secure" not in cookies:
            err("[Cookie] 缺少 Secure 标志", "应含 Secure", "未含")
        else:
            ok("[Cookie] Secure 标志已设置")
        if "HttpOnly" not in cookies:
            warn("[Cookie] 缺少 HttpOnly 标志")
        else:
            ok("[Cookie] HttpOnly 标志已设置")
        if "SameSite" not in cookies:
            warn("[Cookie] 缺少 SameSite 标志")
        else:
            ok("[Cookie] SameSite 标志已设置")
    else:
        warn("[Cookie] 响应未设置 Cookie")

    # ── CORS 策略检查 ──
    info("=== CORS 策略检查 ===")
    try:
        r_cors = requests.get(urljoin(BASE_URL, "/"),
                              headers={"Origin": "http://evil.com"},
                              timeout=TIMEOUT, allow_redirects=False)
        acao = r_cors.headers.get("Access-Control-Allow-Origin", "")
        acac = r_cors.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "http://evil.com" and acac == "true":
            err("[CORS] 反射任意 Origin + 允许凭据", "不允许", "允许")
        elif acao == "http://evil.com":
            warn("[CORS] 反射任意 Origin（无凭据）")
        elif acao == "*":
            warn("[CORS] 允许所有 Origin (*)")
        elif not acao:
            ok("[CORS] 未设置 CORS 头（同源策略）")
        else:
            ok(f"[CORS] Origin 头: {acao}")
    except Exception as e:
        warn(f"[CORS] 检查异常: {e}")

    # ── 目录列表探测 ──
    info("=== 目录列表探测 ===")
    dir_checks = [p for p in payloads if p["description"].startswith("检查") and "目录" in p["description"]]
    for chk in dir_checks:
        try:
            r = s.get(urljoin(BASE_URL, chk["path"]), timeout=TIMEOUT, allow_redirects=False)
            if r.status_code == 200 and ("Index of" in r.text or "<title>" in r.text):
                warn(f"[目录列表] {chk['path']} → HTTP 200 (可能可列目录)")
            elif r.status_code == 200:
                ok(f"[目录] {chk['path']} → HTTP 200 (有内容)")
            else:
                ok(f"[目录] {chk['path']} → HTTP {r.status_code}")
        except Exception as e:
            warn(f"[目录] {chk['path']} → 异常: {e}")

    print_summary()
    save_results("18_info_disclosure")
    return STATE["fail"]


if __name__ == "__main__":
    sys.exit(run())
