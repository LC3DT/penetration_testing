"""10_log_analyzer — 日志分析 + WAF 对比"""

import sys, os, json, re, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.test_utils import *


def collect_logs(log_path: str, label: str) -> dict:
    """解析服务端 / API 请求日志"""
    data = {
        "label": label,
        "total_requests": 0,
        "endpoints": {},
        "methods": {},
        "status_codes": {},
        "attack_signatures": {
            "sql_injection": 0,
            "xss": 0,
            "cmd_injection": 0,
            "path_traversal": 0,
        },
        "errors": [],
    }

    # 分析 API 实际流量（通过请求一次看看效果）
    # 这里改为分析 results/ 目录下的 JSON 报告
    results_dir = os.path.join(OUTPUT_DIR)
    if not os.path.exists(results_dir):
        return data

    for fname in sorted(os.listdir(results_dir)):
        if not fname.endswith(".json") or fname == "comparison_report.json":
            continue
        fpath = os.path.join(results_dir, fname)
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                report = json.load(f)
        except Exception:
            continue

        data["total_requests"] += len(report.get("results", []))
        # 提取模块名作为 endpoint 统计
        name = report.get("name", fname).replace(".json", "")
        data["endpoints"][name] = {
            "pass": report.get("pass", 0),
            "fail": report.get("fail", 0),
        }

        # 统计攻击特征
        for r in report.get("results", []):
            msg = r.get("message", "")
            if any(kw in msg.lower() for kw in ["注入", "sql", "union", "or 1=1", "and 1="]):
                data["attack_signatures"]["sql_injection"] += 1
            if any(kw in msg.lower() for kw in ["xss", "script", "onerror", "onload"]):
                data["attack_signatures"]["xss"] += 1
            if any(kw in msg.lower() for kw in ["命令", "cmd", "注入", "exec"]):
                data["attack_signatures"]["cmd_injection"] += 1
            if any(kw in msg.lower() for kw in ["路径遍历", "traversal", "../", "passwd"]):
                data["attack_signatures"]["path_traversal"] += 1

    return data


def run():
    print_banner("10: 日志分析对比")
    reset_counters()

    info("分析测试结果目录")

    no_waf_dir = os.path.join(OUTPUT_DIR, "no_waf")
    with_waf_dir = os.path.join(OUTPUT_DIR, "with_waf")

    results_no_waf = collect_logs(OUTPUT_DIR, "No WAF")
    results_with_waf = collect_logs(OUTPUT_DIR, "With WAF")

    # 如果没有分目录存放，尝试从主目录分析
    if results_no_waf["total_requests"] == 0:
        results_no_waf = collect_logs(no_waf_dir, "No WAF")
    if results_with_waf["total_requests"] == 0:
        results_with_waf = collect_logs(with_waf_dir, "With WAF")

    info(f"无WAF结果: {results_no_waf['total_requests']} 条记录")
    info(f"有WAF结果: {results_with_waf['total_requests']} 条记录")

    # ── 生成对比报告 ──
    info("生成对比报告")

    comparison = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "rounds": {
            "no_waf": results_no_waf,
            "with_waf": results_with_waf,
        },
        "waf_effectiveness": {},
        "recommendations": [],
    }

    # 如果两轮都有数据，计算效果
    if results_no_waf["total_requests"] > 0 and results_with_waf["total_requests"] > 0:
        no_attacks = results_no_waf["attack_signatures"]
        with_attacks = results_with_waf["attack_signatures"]
        total_no = sum(no_attacks.values())
        total_with = sum(with_attacks.values())

        if total_no > 0:
            detection_rate = (total_no - total_with) / total_no * 100
            comparison["waf_effectiveness"]["estimated_detection_rate"] = f"{detection_rate:.1f}%"
            ok(f"预估检测率: {detection_rate:.1f}%")

        comparison["waf_effectiveness"]["no_waf_attacks"] = no_attacks
        comparison["waf_effectiveness"]["with_waf_attacks"] = with_attacks

    # ── 按模块统计 ──
    module_summary = {}
    for module, stats in results_no_waf.get("endpoints", {}).items():
        if module in results_with_waf.get("endpoints", {}):
            with_stats = results_with_waf["endpoints"][module]
            blocked = stats.get("fail", 0) - with_stats.get("fail", 0)
            module_summary[module] = {
                "no_waf_pass": stats.get("pass", 0),
                "with_waf_pass": with_stats.get("pass", 0),
                "estimated_blocked": max(0, blocked),
            }

    comparison["per_module"] = module_summary

    # ── 建议 ──
    if comparison.get("waf_effectiveness", {}).get("estimated_detection_rate"):
        dr = float(comparison["waf_effectiveness"]["estimated_detection_rate"].replace("%", ""))
        if dr < 50:
            comparison["recommendations"].append("WAF 检测率过低 (<50%)，建议调整规则")
        elif dr < 80:
            comparison["recommendations"].append("WAF 检测率可接受 (50-80%)，建议优化跳过率")
        else:
            comparison["recommendations"].append("WAF 检测率良好 (>80%)")

        # 检查是否有模块检测率低
        for mod, val in module_summary.items():
            blocked = val.get("estimated_blocked", 0)
            if blocked <= 0 and "baseline" not in mod:
                comparison["recommendations"].append(f"模块 '{mod}' 无攻击被拦截，请检查WAF规则")

    # ── 输出报告 ──
    print(f"\n{BS}{'─' * 55}{RC}")
    print(f"  WAF 效果对比报告")
    print(f"{BS}{'─' * 55}{RC}")
    for mod, val in module_summary.items():
        pct = (val["estimated_blocked"] / val["no_waf_pass"] * 100) if val["no_waf_pass"] > 0 else 0
        bar_len = int(pct / 5)
        bar = "█" * bar_len + "░" * (20 - bar_len)
        print(f"  {mod:22s} {bar} {val['estimated_blocked']}/{val['no_waf_pass']} ({pct:.0f}%)")

    print(f"{BS}{'─' * 55}{RC}\n")

    if comparison.get("recommendations"):
        for rec in comparison["recommendations"]:
            warn(rec)

    # ── 保存 ──
    output_path = os.path.join(OUTPUT_DIR, "comparison_report.json")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(comparison, f, ensure_ascii=False, indent=2)
    ok(f"对比报告已保存: {output_path}")

    print_summary()
    save_results("10_log_analyzer")
    return STATE["fail"]


if __name__ == "__main__":
    sys.exit(run())
