#!/usr/bin/env python3
"""WAF 测试套件 — 总入口

用法:
  python3 run_all.py                          # 全部测试（直连模式）
  python3 run_all.py --waf                    # WAF 前置模式（攻击应被拦截）
  python3 run_all.py --compare                # 两轮对比
  python3 run_all.py --skip 07,09             # 跳过爬虫和并发
  python3 run_all.py --only 01,02             # 仅跑指定模块

环境变量:
  BASE_URL=http://192.168.1.100:3000          # 目标地址
  CONCURRENT=50 BATCH_REQUESTS=1000           # 并发参数
  SAVE_RESULTS=1                               # 保存 JSON 结果
  OUTPUT_DIR=./results                          # 输出目录
"""

import sys, os, time, json

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "tests"))

# 确保 lib 可导入
CR = "\033[31m"
CG = "\033[32m"
CB = "\033[34m"
CC = "\033[0m"

TEST_MODULES = {
    "01": ("基础功能", "01_baseline"),
    "02": ("SQL注入", "02_sql_injection"),
    "03": ("XSS跨站脚本", "03_xss"),
    "04": ("命令注入", "04_command_injection"),
    "05": ("路径遍历", "05_path_traversal"),
    "06": ("认证绕过", "06_auth_bypass"),
    "07": ("全站爬虫", "07_crawler"),
    "08": ("API模糊测试", "08_api_fuzzing"),
    "09": ("并发压力", "09_concurrent"),
    "10": ("日志分析", "10_log_analyzer"),
    "11": ("SSRF请求伪造", "11_ssrf"),
    "12": ("SSTI模板注入", "12_ssti"),
    "13": ("CRLF注入", "13_crlf"),
    "14": ("开放重定向", "14_open_redirect"),
    "15": ("文件上传绕过", "15_file_upload"),
    "16": ("NoSQL注入", "16_nosql"),
    "17": ("HTTP参数污染", "17_hpp"),
    "18": ("信息泄露", "18_info_disclosure"),
}


def parse_args():
    flags = {
        "waf": False,
        "compare": False,
        "skip": set(),
        "only": None,
    }
    for arg in sys.argv[1:]:
        if arg == "--waf":
            flags["waf"] = True
        elif arg == "--compare":
            flags["compare"] = True
        elif arg.startswith("--skip="):
            flags["skip"] = set(arg.split("=", 1)[1].split(","))
        elif arg.startswith("--only="):
            flags["only"] = set(arg.split("=", 1)[1].split(","))
    return flags


def run_module(num: str) -> int:
    mod = TEST_MODULES[num]
    name, pkg = mod
    print(f"\n{CC}┌{'─' * 58}┐")
    print(f"│  [{num}] {name:48s} │")
    print(f"└{'─' * 58}┘")
    try:
        m = __import__(pkg)
        return m.run()
    except Exception as e:
        print(f"  {CR}[✗] 模块加载失败: {e}{CC}")
        import traceback
        traceback.print_exc()
        return 1


def check_server() -> bool:
    import requests
    try:
        from tests.lib.test_utils import BASE_URL
        r = requests.get(BASE_URL, timeout=5)
        return r.status_code == 200
    except Exception:
        return False


def print_header(text: str):
    print(f"\n{CC}{'=' * 60}{CC}")
    print(f"{CC}  {text}{CC}")
    print(f"{CB}{'=' * 60}{CC}\n")


def main():
    flags = parse_args()

    # 检查服务器
    print_header("WAF 测试套件 v1.0")
    if not check_server():
        print(f"  {CR}[!] 无法连接到服务器！{CC}")
        print(f"      请确保服务器已启动: node server.js")
        print(f"      或设置环境变量: BASE_URL=http://...")
        sys.exit(1)
    print(f"  {CG}[✓] 服务器连接正常{CC}\n")

    # 决定运行哪些模块
    modules_to_run = []
    if flags["only"]:
        modules_to_run = sorted(flags["only"])
    else:
        modules_to_run = [m for m in TEST_MODULES if m not in flags["skip"]]

    # ── 运行 ──
    t0 = time.monotonic()
    results: dict[str, dict] = {}

    for num in modules_to_run:
        t1 = time.monotonic()
        fail_count = run_module(num)
        t2 = time.monotonic()
        results[num] = {
            "name": TEST_MODULES[num][0],
            "fail": fail_count,
            "time": f"{t2 - t1:.1f}s",
        }

    total_time = time.monotonic() - t0

    # ── 汇总 ──
    print_header("测试汇总")
    total_fail = 0
    for num in modules_to_run:
        r = results[num]
        icon = f"{CG}✓{CC}" if r["fail"] == 0 else f"{CR}✗{CC}"
        print(f"  [{num}] {r['name']:20s} {icon}  ({r['time']})")
        total_fail += r["fail"]

    print(f"\n  {'─' * 40}")
    if total_fail == 0:
        print(f"  {CG}全部通过！总计 {len(modules_to_run)} 个模块，耗时 {total_time:.1f}s{CC}")
    else:
        print(f"  {CR}存在 {total_fail} 个失败项，总计 {len(modules_to_run)} 个模块，耗时 {total_time:.1f}s{CC}")
    print()

    # ── 保存汇总报告 ──
    output_dir = os.environ.get("OUTPUT_DIR", "./results")
    os.makedirs(output_dir, exist_ok=True)
    summary = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_time": f"{total_time:.1f}s",
        "modules": results,
        "total_fail": total_fail,
    }
    with open(os.path.join(output_dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    sys.exit(total_fail)


if __name__ == "__main__":
    main()
