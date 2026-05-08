"""WAF 测试公共库 — HTTP 客户端、断言、会话管理、报告生成"""

import os
import sys
import json
import time
import re
import tempfile
import requests
import random
from urllib.parse import urljoin
from typing import Optional, Any, List, Dict

BASE_URL = os.environ.get("BASE_URL", "http://localhost:3000")
TIMEOUT = int(os.environ.get("TIMEOUT", "10"))
SAVE_RESULTS = os.environ.get("SAVE_RESULTS", "0") == "1"
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", os.path.join(os.path.dirname(__file__), "..", "results"))

STATE = {"pass": 0, "fail": 0, "results": []}

GS = "\033[32m"
RS = "\033[31m"
BS = "\033[34m"
YS = "\033[33m"
RC = "\033[0m"


def _log(prefix: str, msg: str) -> None:
    sys.stdout.write(f"{prefix} {msg}{RC}\n")
    sys.stdout.flush()


def info(msg: str) -> None:
    _log(f"{BS}[*]{RC}", msg)


def ok(msg: str) -> None:
    STATE["pass"] += 1
    _log(f"{GS}[✓]{RC}", msg)
    STATE["results"].append({"status": "pass", "message": msg})


def err(msg: str, expected: str = "", got: str = "") -> None:
    STATE["fail"] += 1
    detail = ""
    if expected:
        detail = f" (expected: {expected}, got: {got})"
    _log(f"{RS}[✗]{RC}", f"{msg}{detail}")
    STATE["results"].append({"status": "fail", "message": msg, "expected": expected, "got": got})


def warn(msg: str) -> None:
    _log(f"{YS}[!]{RC}", msg)


def get(url: str, **kwargs) -> requests.Response:
    kwargs.setdefault("timeout", TIMEOUT)
    kwargs.setdefault("allow_redirects", False)
    return requests.get(urljoin(BASE_URL, url), **kwargs)


def post(url: str, data: dict = None, **kwargs) -> requests.Response:
    kwargs.setdefault("timeout", TIMEOUT)
    kwargs.setdefault("allow_redirects", False)
    return requests.post(urljoin(BASE_URL, url), data=data, **kwargs)


def raw_get(url: str, **kwargs) -> requests.Response:
    return requests.get(urljoin(BASE_URL, url), timeout=TIMEOUT, **kwargs)


def assert_status(r: requests.Response, code: int, label: str = "") -> bool:
    msg = f"{label} → HTTP {code}" if label else f"HTTP {code}"
    if r.status_code == code:
        ok(msg)
        return True
    err(msg, str(code), str(r.status_code))
    return False


def assert_body(r: requests.Response, text: str, label: str = "") -> bool:
    msg = label or f"响应含 '{text}'"
    if text in r.text:
        ok(msg)
        return True
    err(msg, f"含 '{text}'", "未找到")
    return False


def assert_body_not(r: requests.Response, text: str, label: str = "") -> bool:
    msg = label or f"响应不含 '{text}'"
    if text not in r.text:
        ok(msg)
        return True
    err(msg, f"不含 '{text}'", "存在")
    return False


def assert_redirect(r: requests.Response, path: str, label: str = "") -> bool:
    msg = label or f"重定向到 {path}"
    location = r.headers.get("Location", "")
    if path in location:
        ok(msg)
        return True
    err(msg, path, location)
    return False


def assert_json_count(r: requests.Response, count: int, label: str = "") -> bool:
    msg = label or f"JSON 数组长度 = {count}"
    try:
        data = r.json()
        actual = len(data.get("data", data if isinstance(data, list) else []))
    except Exception:
        actual = -1
    if actual == count:
        ok(msg)
        return True
    err(msg, str(count), str(actual))
    return False


def assert_json_field(r: requests.Response, field: str, value: Any, label: str = "") -> bool:
    msg = label or f"JSON.{field} = {value}"
    try:
        data = r.json()
        actual = data.get(field)
    except Exception:
        actual = None
    if actual == value:
        ok(msg)
        return True
    err(msg, str(value), str(actual))
    return False


def print_banner(title: str) -> None:
    width = 60
    print(f"\n{BS}{'=' * width}{RC}")
    print(f"{BS}  {title}{RC}")
    print(f"{BS}{'=' * width}{RC}\n")


def print_summary(total_pass: int = None, total_fail: int = None) -> int:
    p = total_pass if total_pass is not None else STATE["pass"]
    f = total_fail if total_fail is not None else STATE["fail"]
    total = p + f
    print(f"\n{BS}──────────────────────────────────{RC}")
    print(f"  {GS}通过: {p}{RC}  /  {RS}失败: {f}{RC}  /  总计: {total}")
    if f == 0:
        print(f"  {GS}全部通过！{RC}")
    else:
        print(f"  {RS}存在失败项{RC}")
    print(f"{BS}──────────────────────────────────{RC}\n")
    return f


def reset_counters() -> None:
    STATE["pass"] = 0
    STATE["fail"] = 0
    STATE["results"] = []


def get_counters() -> tuple[int, int]:
    return STATE["pass"], STATE["fail"]


def save_results(name: str) -> None:
    if not SAVE_RESULTS:
        return
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    path = os.path.join(OUTPUT_DIR, f"{name}.json")
    report = {
        "name": name,
        "pass": STATE["pass"],
        "fail": STATE["fail"],
        "results": STATE["results"],
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "base_url": BASE_URL,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    info(f"结果已保存: {path}")


def load_payloads(name: str) -> list:
    """Load JSON payload file from tests/payloads/<name>.json"""
    payload_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "payloads")
    path = os.path.join(payload_dir, f"{name}.json")
    if not os.path.exists(path):
        warn(f"Payload 文件不存在: {path}")
        return []
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def payload_loaded(name: str) -> bool:
    """Check if a payload file exists"""
    payload_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "payloads")
    return os.path.exists(os.path.join(payload_dir, f"{name}.json"))
