"""09_concurrent — 并发 / 压力测试"""

import sys, os, json, time, statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.test_utils import *


def _get(path: str) -> tuple[int, float]:
    t0 = time.monotonic()
    try:
        r = requests.get(urljoin(BASE_URL, path), timeout=TIMEOUT)
        elapsed = (time.monotonic() - t0) * 1000
        return (r.status_code, elapsed)
    except Exception:
        elapsed = (time.monotonic() - t0) * 1000
        return (0, elapsed)


def _post(path: str, data: dict) -> tuple[int, float]:
    t0 = time.monotonic()
    try:
        r = requests.post(urljoin(BASE_URL, path), data=data, timeout=TIMEOUT)
        elapsed = (time.monotonic() - t0) * 1000
        return (r.status_code, elapsed)
    except Exception:
        elapsed = (time.monotonic() - t0) * 1000
        return (0, elapsed)


def _run_batch(desc: str, fn, fn_args: list, concurrency: int = 50, total: int = 1000):
    info(f"{desc} ({concurrency} 并发 × {total//concurrency} 轮, 共 {total} 次)")
    results: list[tuple[int, float]] = []

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(fn, *args) for args in fn_args]
        for fut in as_completed(futures):
            results.append(fut.result())

    status_codes = [r[0] for r in results]
    latencies = [r[1] for r in results if r[1] > 0]

    success = sum(1 for c in status_codes if 200 <= c < 500)
    failed = sum(1 for c in status_codes if c == 0)
    errors = sum(1 for c in status_codes if c >= 500)

    stats = {
        "desc": desc,
        "total": len(results),
        "success": success,
        "failed": failed,
        "errors": errors,
        "success_rate": f"{success / len(results) * 100:.1f}%",
        "concurrency": concurrency,
    }
    if latencies:
        stats["latency_ms"] = {
            "avg": f"{statistics.mean(latencies):.1f}",
            "min": f"{min(latencies):.1f}",
            "max": f"{max(latencies):.1f}",
            "p50": f"{statistics.median(latencies):.1f}",
            "p99": f"{sorted(latencies)[int(len(latencies) * 0.99)]:.1f}" if len(latencies) >= 100 else "N/A",
        }
        qps = success / (sum(latencies) / 1000) if sum(latencies) > 0 else 0
        stats["qps"] = f"{qps:.1f}"

    ok(f"{desc} — 成功:{success} 失败:{failed+errors} "
       f"{'  QPS:' + str(stats.get('qps', 'N/A')) if 'qps' in stats else ''}")

    return stats


def run():
    print_banner("09: 并发/压力测试")
    reset_counters()

    concurrency = int(os.environ.get("CONCURRENT", "30"))
    batch_total = int(os.environ.get("BATCH_REQUESTS", "600"))
    all_stats = []

    # ── 9.1 正常并发（首页） ──
    info("正常并发（首页）")
    args = [("/",) for _ in range(batch_total)]
    s = _run_batch("首页并发", _get, args, concurrency, batch_total)
    all_stats.append(s)

    # ── 9.2 SQL 注入洪水 ──
    info("SQL 注入洪水")
    sql_paths = [
        ("/api/users?name=' OR '1'='1",),
        ("/api/products?category=' UNION SELECT 1,2,3,4,5,6 --",),
        ("/products/1 OR 1=1",),
    ]
    args = []
    for i in range(batch_total):
        args.append(sql_paths[i % len(sql_paths)])
    s = _run_batch("SQL注入洪水", _get, args, concurrency, batch_total)
    all_stats.append(s)

    # ── 9.3 混合流量 ──
    info("混合流量 (70% 正常 + 30% 攻击)")
    normal_args = [("/",), ("/products",), ("/contact",)]
    attack_args = [
        ("/api/users?name='%20OR%20'1'='1",),
        ("/products?q=' OR 1=1 --",),
    ]
    args = []
    for i in range(batch_total):
        if i % 10 < 7:
            args.append(normal_args[i % len(normal_args)])
        else:
            args.append(attack_args[i % len(attack_args)])
    s = _run_batch("混合流量70/30", _get, args, concurrency, batch_total)
    all_stats.append(s)

    # ── 9.4 突发流量 ──
    info("突发流量 (瞬时高并发)")
    burst_concurrency = concurrency * 3
    burst_total = concurrency * 3
    args = [("/",) for _ in range(burst_total)]
    s = _run_batch("突发流量", _get, args, burst_concurrency, burst_total)
    all_stats.append(s)

    # ── 9.5 登录压力 ──
    info("登录压力")
    post_args = []
    for i in range(min(300, batch_total // 2)):
        user = ["test", "admin", "alice", "bob"][i % 4]
        pw = ["test123", "admin123", "pass1", "pass2"][i % 4]
        post_args.append(("/login", {"username": user, "password": pw}))
    s = _run_batch("登录压力", _post, post_args, min(concurrency, 10), len(post_args))
    all_stats.append(s)

    # ── 保存报告 ──
    output_path = os.path.join(OUTPUT_DIR, "concurrent_report.json")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "base_url": BASE_URL,
        "concurrency": concurrency,
        "scenarios": all_stats,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    ok(f"并发测试报告已保存: {output_path}")

    print_summary()
    save_results("09_concurrent")
    return STATE["fail"]


if __name__ == "__main__":
    sys.exit(run())
