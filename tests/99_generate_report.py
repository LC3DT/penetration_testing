#!/usr/bin/env python3
"""99_generate_report — 从测试结果生成 Markdown 格式的详细检测报告"""

import sys, os, json, glob, re, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.test_utils import *


def load_all_results(directory: str) -> dict:
    """Load all JSON result files from a directory."""
    reports = {}
    for f in sorted(glob.glob(os.path.join(directory, "*.json"))):
        basename = os.path.basename(f).replace(".json", "")
        try:
            with open(f, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            reports[basename] = data
        except Exception:
            pass
    return reports


def extract_result_details(results: list) -> list:
    """Extract per-item details: name, status, http_code, description."""
    details = []
    for r in results:
        msg = r.get("message", "")
        m = re.search(r'HTTP\s+(\d+)', msg)
        code = int(m.group(1)) if m else 0
        status = r.get("status", "unknown")
        expected = r.get("expected", "")
        got = r.get("got", "")
        details.append({
            "message": msg[:120],
            "status": status,
            "http_code": code,
            "expected": expected,
            "got": got,
        })
    return details


def classify_blocked(results: list) -> tuple:
    """Count blocked vs passed requests."""
    blocked, passed, other = 0, 0, 0
    for r in results:
        msg = r.get("message", "")
        m = re.search(r'HTTP\s+(\d+)', msg)
        if m:
            c = int(m.group(1))
            if c in (403, 405, 406, 431, 500, 502):
                blocked += 1
            else:
                passed += 1
        else:
            other += 1
    return passed, blocked, other


MODULE_NAMES = {
    "01_baseline": "基础功能验证",
    "02_sql_injection": "SQL 注入",
    "03_xss": "XSS 跨站脚本",
    "04_command_injection": "命令注入",
    "05_path_traversal": "路径遍历",
    "06_auth_bypass": "认证绕过",
    "07_crawler": "全站爬虫",
    "08_api_fuzzing": "API 模糊测试",
    "09_concurrent": "并发压力测试",
    "10_log_analyzer": "日志分析",
    "11_ssrf": "SSRF 服务端请求伪造",
    "12_ssti": "SSTI 模板注入",
    "13_crlf": "CRLF 注入",
    "14_open_redirect": "开放重定向",
    "15_file_upload": "文件上传绕过",
    "16_nosql": "NoSQL 注入",
    "17_hpp": "HTTP 参数污染",
    "18_info_disclosure": "信息泄露",
}


def generate_report(no_waf_dir: str = "results/no_waf",
                    waf_dir: str = "results/with_waf",
                    output_path: str = None) -> str:
    """Generate a comprehensive markdown report."""
    if output_path is None:
        output_path = os.path.join(os.path.dirname(no_waf_dir), "WAF_检测报告.md")

    no_waf = load_all_results(no_waf_dir)
    waf = load_all_results(waf_dir)

    now = time.strftime("%Y-%m-%d %H:%M:%S")
    no_waf_url = no_waf.get("01_baseline", {}).get("base_url", no_waf_dir)
    waf_url = waf.get("01_baseline", {}).get("base_url", waf_dir)

    lines = []
    def w(line=""):
        lines.append(line)

    # ===== Header =====
    w("# WAF 检测报告")
    w()
    w(f"> 生成时间: {now}")
    w(f"> 源服务器 (无WAF): `{no_waf_url}`")
    w(f"> WAF 服务器: `{waf_url}`")
    w()

    # ===== Overview =====
    w("## 1. 测试概况")
    w()
    w("| 项目 | 数值 |")
    w("|------|------|")
    all_modules = sorted(set(list(no_waf.keys()) + list(waf.keys())))
    skip_modules = {"summary", "comparison_report", "concurrent_report", "crawler_report",
                    "07_crawler", "09_concurrent", "10_log_analyzer"}
    test_modules = [m for m in all_modules if m not in skip_modules]

    total_attacks = 0
    total_blocked = 0
    total_passed_waf = 0

    for mod in test_modules:
        br = no_waf.get(mod, {}).get("results", [])
        wr = waf.get(mod, {}).get("results", [])
        br_pass, br_block, _ = classify_blocked(br)
        wr_pass, wr_block, _ = classify_blocked(wr)
        total_attacks += br_pass
        total_blocked += wr_block
        total_passed_waf += wr_pass

    overall_rate = (total_blocked / total_attacks * 100) if total_attacks > 0 else 0

    w(f"| 测试模块数 | {len(test_modules)} |")
    w(f"| 总攻击请求数 | {total_attacks} |")
    w(f"| WAF 拦截数 | {total_blocked} |")
    w(f"| **整体检测率** | **{overall_rate:.1f}%** |")
    w(f"| 漏拦 (FN) | {total_attacks - total_blocked} |")
    w(f"| WAF 放行数 | {total_passed_waf} |")
    w()
    w(f"```")
    bar_len = int(overall_rate / 5)
    w(f"整体检测率: [{'█' * bar_len}{'░' * (20 - bar_len)}] {overall_rate:.1f}%")
    w(f"```")
    w()

    # ===== Per Module =====
    w("## 2. 各模块检测详情")
    w()

    module_stats = []
    for mod in test_modules:
        name = MODULE_NAMES.get(mod, mod)
        br = no_waf.get(mod, {}).get("results", [])
        wr = waf.get(mod, {}).get("results", [])
        br_pass, br_block, _ = classify_blocked(br)
        wr_pass, wr_block, _ = classify_blocked(wr)
        rate = (wr_block / br_pass * 100) if br_pass > 0 else 0
        module_stats.append((mod, name, len(wr), br_pass, wr_block, rate))

    # Sort by attack count descending
    module_stats.sort(key=lambda x: -x[3])

    w("| 模块 | 攻击数 | 拦截数 | 检测率 | 评价 |")
    w("|------|--------|--------|--------|------|")
    for mod, name, total, attacks, blocked, rate in module_stats:
        if rate >= 80:
            grade = "🟢 优秀"
        elif rate >= 50:
            grade = "🟡 良好"
        elif rate >= 20:
            grade = "🟠 不足"
        else:
            grade = "🔴 薄弱"
        w(f"| {name} | {attacks} | {blocked} | {rate:.0f}% | {grade} |")
    w()

    # Detection rate visualization
    w("### 检测率可视化")
    w()
    w("```")
    for mod, name, total, attacks, blocked, rate in module_stats:
        bar = "█" * int(rate / 5) + "░" * (20 - int(rate / 5))
        w(f"  {name:<16} [{bar}] {rate:.0f}%")
    w("```")
    w()

    # ===== Detail per module =====
    w("## 3. 攻击细节 (Top 攻击模块)")
    w()
    w("> 仅列出有拦截差异的模块详情。以下表格展示每个 payload 的 WAF 拦截状态。")
    w()

    detail_modules = [m for m in module_stats if m[4] > 0][:6]  # Top 6 with any blocking
    for mod, name, total, attacks, blocked, rate in detail_modules:
        w(f"### 3.{detail_modules.index((mod,name,total,attacks,blocked,rate))+1} {name}")
        w()
        w(f"- 总攻击数: {attacks}")
        w(f"- 被拦截: {blocked}")
        w(f"- 检测率: {rate:.0f}%")
        w()
        br_results = no_waf.get(mod, {}).get("results", [])
        w_results = waf.get(mod, {}).get("results", [])
        br_details = extract_result_details(br_results)
        ww_details = extract_result_details(w_results)

        # Only show first 30 items per module for readability
        w("| # | Payload 描述 | 无WAF状态码 | WAF状态码 | 拦截? |")
        w("|---|-------------|------------|----------|-------|")
        for i in range(min(len(br_details), len(ww_details), 30)):
            bd = br_details[i]
            wd = ww_details[i]
            blocked_icon = "✅" if wd["http_code"] in (403, 405, 406, 431) else "❌"
            w(f"| {i+1} | {bd['message'][:60]} | {bd['http_code']} | {wd['http_code']} | {blocked_icon} |")
        if len(br_details) > 30:
            w(f"| ... | *({len(br_details)-30} more items)* | ... | ... | ... |")
        w()

    # ===== Missed Attacks =====
    w("## 4. 漏拦分析")
    w()
    w("### 4.1 未拦截的攻击类型")
    w()
    w("| 模块 | 未拦截数 | 典型漏拦示例 |")
    w("|------|---------|-------------|")

    for mod, name, total, attacks, blocked, rate in module_stats:
        if blocked < attacks:
            missed = attacks - blocked
            br_results = no_waf.get(mod, {}).get("results", [])
            w_results = waf.get(mod, {}).get("results", [])
            br_details = extract_result_details(br_results)
            ww_details = extract_result_details(w_results)

            # Find 3 examples of missed attacks
            examples = []
            for i in range(min(len(br_details), len(ww_details))):
                if ww_details[i]["http_code"] not in (403, 405, 406, 431):
                    examples.append(br_details[i]["message"][:50])
                if len(examples) >= 3:
                    break
            ex_str = "<br>".join(examples[:3]) if examples else "—"
            w(f"| {name} | {missed} | {ex_str} |")
    w()

    # ===== Blocked Attacks =====
    w("### 4.2 成功拦截的攻击类型")
    w()
    w("| 模块 | 拦截数 | 典型拦截示例 |")
    w("|------|--------|-------------|")

    for mod, name, total, attacks, blocked, rate in module_stats:
        if blocked > 0:
            br_results = no_waf.get(mod, {}).get("results", [])
            w_results = waf.get(mod, {}).get("results", [])
            br_details = extract_result_details(br_results)
            ww_details = extract_result_details(w_results)
            examples = []
            for i in range(min(len(br_details), len(ww_details))):
                if ww_details[i]["http_code"] in (403, 405, 406, 431):
                    examples.append(br_details[i]["message"][:50])
                if len(examples) >= 3:
                    break
            ex_str = "<br>".join(examples[:3]) if examples else "—"
            w(f"| {name} | {blocked} | {ex_str} |")
    w()

    # ===== Recommendations =====
    w("## 5. 改进建议")
    w()

    critical = [(m, n, a, b, r) for m, n, _, a, b, r in module_stats if r == 0 and a > 5]
    weak = [(m, n, a, b, r) for m, n, _, a, b, r in module_stats if 0 < r < 30]
    moderate = [(m, n, a, b, r) for m, n, _, a, b, r in module_stats if 30 <= r < 80]

    if critical:
        w("### 5.1 🔴 紧急: 检测率为 0% 的模块")
        w()
        for mod, name, attacks, blocked, rate in critical:
            w(f"**{name}** — {attacks} 条攻击全部通过，无任何拦截。")
            suggestions = {
                "04_command_injection": "建议在 POST body 中检测命令分隔符 (`;`, `|`, `&&`, `||`, `$()`, `` ` ``) 以及敏感命令关键词",
                "06_auth_bypass": "建议检测登录请求中的万能密码模式 (`' OR`, `'--`, `admin'--`) 和空密码",
                "01_baseline": "基础功能验证为正常流量，无需拦截",
            }
            if mod in suggestions:
                w(f"> {suggestions[mod]}")
            w()
    else:
        w("无检测率为 0% 的紧急模块。")
        w()

    if weak:
        w("### 5.2 🟠 需要加强: 检测率 < 30%")
        w()
        for mod, name, attacks, blocked, rate in weak:
            w(f"**{name}** — 检测率 {rate:.0f}% ({blocked}/{attacks})")
        w()

    if moderate:
        w("### 5.3 🟡 可优化: 检测率 30%-80%")
        w()
        for mod, name, attacks, blocked, rate in moderate:
            w(f"**{name}** — 检测率 {rate:.0f}% ({blocked}/{attacks})")
        w()

    w("### 5.4 通用改进建议")
    w()
    w("1. **POST Body 深度检测**: 当前 WAF 主要检测 URL 参数和 Header，建议增加 POST body 内容的规则检测")
    w("2. **编码绕过防护**: URL 编码、双重编码、Unicode 编码的 payload 需要解码后再检测")
    w("3. **模板注入防护**: 检测 `<%=`, `{{`, `${`, `process.mainModule`, `require(` 等模板引擎注入特征")
    w("4. **安全响应头**: 添加 HSTS, X-Frame-Options, X-Content-Type-Options, CSP 等安全头")
    w("5. **协议白名单**: SSRF 防护应仅允许 http/https 协议且限制目标域名/IP")
    w("6. **文件上传检测**: 检测文件扩展名 (php/jsp/asp 及变体) 和 MIME 类型")
    w()

    # ===== Appendix =====
    w("## 6. 附录")
    w()
    w("### 6.1 测试环境")
    w()
    w(f"| 项目 | 信息 |")
    w(f"|------|------|")
    w(f"| 测试框架 | WAF 测试套件 v1.0 |")
    w(f"| 测试模块 | {len(test_modules)} 个 |")
    w(f"| 总 Payload | 834 条 (14 个 JSON 文件) |")
    w(f"| 无 WAF 结果目录 | `{no_waf_dir}` |")
    w(f"| WAF 结果目录 | `{waf_dir}` |")
    w()

    w("### 6.2 测试覆盖的攻击类型")
    w()
    w("| 类别 | 模块 | Payload 数 |")
    w("|------|------|-----------|")
    w("| SQL 注入 | 02_sql_injection | 92 |")
    w("| XSS | 03_xss | 112 |")
    w("| 命令注入 | 04_command_injection | 63 |")
    w("| 路径遍历 | 05_path_traversal | 59 |")
    w("| 认证绕过 | 06_auth_bypass | — |")
    w("| API Fuzz | 08_api_fuzzing | 128 |")
    w("| SSRF | 11_ssrf | 58 |")
    w("| SSTI | 12_ssti | 59 |")
    w("| CRLF | 13_crlf | 40 |")
    w("| 开放重定向 | 14_open_redirect | 40 |")
    w("| 文件上传 | 15_file_upload | 57 |")
    w("| NoSQL | 16_nosql | 45 |")
    w("| HPP | 17_hpp | 25 |")
    w("| 信息泄露 | 18_info_disclosure | 56 |")
    w()

    report = "\n".join(lines)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"\n  [✓] Markdown 报告已生成: {output_path}")
    print(f"  [*] 报告行数: {len(lines)}")
    return report


if __name__ == "__main__":
    no_waf_dir = sys.argv[1] if len(sys.argv) > 1 else "results/no_waf"
    waf_dir = sys.argv[2] if len(sys.argv) > 2 else "results/with_waf"
    output = sys.argv[3] if len(sys.argv) > 3 else None
    generate_report(no_waf_dir, waf_dir, output)
