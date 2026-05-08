# WAF 测试套件

针对 TechShop 漏洞站点的全套自动化渗透测试脚本，用于验证 WAF 的防护能力。

## 快速开始

```bash
# 1. 安装依赖
pip3 install -r requirements.txt

# 2. 确保目标站点已启动
#    (在 ../simple_html 目录下执行 npm start 或 docker-compose up -d)

# 3. 运行全部测试
python3 run_all.py

# 4. 指定目标地址
BASE_URL=http://192.168.1.100:3000 python3 run_all.py
```

## 运行选项

| 参数 | 说明 |
|------|------|
| `--waf` | WAF 前置模式（攻击应被拦截的提示） |
| `--only 01,02,03` | 仅运行指定模块 |
| `--skip 07,09` | 跳过爬虫和并发测试（加速） |
| `--compare` | 先后跑无WAF和有WAF两轮，生成对比报告 |

### 环境变量

```bash
BASE_URL=http://localhost:3000          # 目标站点地址
TIMEOUT=10                              # 单请求超时 (秒)
CONCURRENT=30                           # 并发测试线程数
BATCH_REQUESTS=600                      # 每个场景总请求数
SAVE_RESULTS=1                          # 保存 JSON 结果文件
OUTPUT_DIR=./results                    # 结果输出目录
```

## Payload 系统

所有攻击数据统一存放在 `tests/payloads/` 目录，以 JSON 格式组织：
- 模块通过 `load_payloads("name")` 从 JSON 文件加载数据
- 共 **14 个 JSON 文件，834 条攻击 payload**
- 便于维护和扩展，无需修改 Python 代码即可添加新 payload

## 测试模块（18 个）

| 模块 | 文件 | 内容 | Payload 数 |
|------|------|------|-----------|
| 01 | `tests/01_baseline.py` | 基础功能 — 页面访问/登录/退出/搜索 | — |
| 02 | `tests/02_sql_injection.py` | SQL 注入 — 9个注入点+编码绕过+WAF绕过 | 92 条 |
| 03 | `tests/03_xss.py` | XSS — 评论/留言存储型+Polyglot+JSFuck | 112 条 |
| 04 | `tests/04_command_injection.py` | 命令注入 — avatar_url 63种payload | 63 条 |
| 05 | `tests/05_path_traversal.py` | 路径遍历 — 文件上传恶意文件名+敏感文件 | 59 条 |
| 06 | `tests/06_auth_bypass.py` | 认证绕过 — 万能密码/伪造session/暴力破解 | — |
| 07 | `tests/07_crawler.py` | 全站爬虫 — 提取链接/表单/站点地图JSON | — |
| 08 | `tests/08_api_fuzzing.py` | API模糊 — 参数变异/关键字/方法/Header/混合 | 128 条 |
| 09 | `tests/09_concurrent.py` | 并发压力 — 正常/SQL洪水/混合/突发/登录压测 | — |
| 10 | `tests/10_log_analyzer.py` | 日志分析 — 两轮对比检测率/FP/FN | — |
| 11 | `tests/11_ssrf.py` | **SSRF** — 内网/云元数据/gopher/dict/file协议 | 58 条 |
| 12 | `tests/12_ssti.py` | **SSTI** — EJS/Jinja2/Twig/FreeMarker等引擎RCE | 59 条 |
| 13 | `tests/13_crlf.py` | **CRLF注入** — 响应拆分/Header注入/日志注入 | 40 条 |
| 14 | `tests/14_open_redirect.py` | **开放重定向** — 域欺骗/js:/data:/file:协议 | 40 条 |
| 15 | `tests/15_file_upload.py` | **文件上传绕过** — PHP shell/双扩展/Polyglot/MIME | 57 条 |
| 16 | `tests/16_nosql.py` | **NoSQL注入** — Mongo $eq/$where/CouchDB/Redis | 45 条 |
| 17 | `tests/17_hpp.py` | **HTTP参数污染** — 同名参数/数组注入/覆盖 | 25 条 |
| 18 | `tests/18_info_disclosure.py` | **信息泄露** — 安全头/Cookie/CORS/敏感路径/错误页 | 56 条 |

## 测试输出示例

```
============================================================
  WAF 测试套件 v1.0
============================================================

  [✓] 服务器连接正常

┌──────────────────────────────────────────────────────────┐
│  [01] 基础功能                                             │
└──────────────────────────────────────────────────────────┘
  [*] 公开页面访问
  [✓] 首页 → HTTP 200
  [✓] 商品列表 → HTTP 200
  [✓] 商品详情 /1 → HTTP 200
  ...

──────────────────────────────────
  通过: 34  /  失败: 0  /  总计: 34
  全部通过！
──────────────────────────────────

============================================================
  测试汇总
============================================================
  [01] 基础功能           ✓  (0.1s)
  [02] SQL注入           ✓  (0.1s)
  [03] XSS跨站脚本        ✓  (0.1s)
  [04] 命令注入           ✓  (0.1s)
  [05] 路径遍历           ✓  (0.0s)
  [06] 认证绕过           ✓  (0.1s)
  [07] 全站爬虫           ✓  (0.1s)
  [08] API模糊测试        ✓  (0.1s)
  [09] 并发压力           ✓  (4.9s)
  [10] 日志分析           ✓  (0.0s)
  ─────────────────────────
  全部通过！总计 18 个模块，耗时 8.2s
```

## 目录结构

```
penetration_testing/
├── README.md                   # 本文件
├── ATTACK_GUIDE.md             # 攻击手册（curl/Python 攻击示例）
├── run_all.py                  # 测试总入口（支持 18 个模块）
├── requirements.txt            # Python 依赖
├── tests/
│   ├── lib/
│   │   ├── __init__.py
│   │   └── test_utils.py       # 公共库（HTTP客户端、断言、报告、payload加载）
│   ├── payloads/               # 攻击数据文件（14 JSON，834条）
│   │   ├── sqli.json           # SQL 注入 92 条
│   │   ├── xss.json            # XSS 112 条
│   │   ├── cmdi.json           # 命令注入 63 条
│   │   ├── traversal.json      # 路径遍历 59 条
│   │   ├── ssrf.json           # SSRF 58 条
│   │   ├── ssti.json           # SSTI 59 条
│   │   ├── crlf.json           # CRLF 40 条
│   │   ├── open_redirect.json  # 开放重定向 40 条
│   │   ├── file_upload.json    # 文件上传 57 条
│   │   ├── nosql.json          # NoSQL 45 条
│   │   ├── hpp.json            # HTTP参数污染 25 条
│   │   ├── info_disclosure.json # 信息泄露 56 条
│   │   └── api_fuzzing.json    # API Fuzz 128 条
│   ├── 01_baseline.py
│   ├── 02_sql_injection.py
│   ├── 03_xss.py
│   ├── 04_command_injection.py
│   ├── 05_path_traversal.py
│   ├── 06_auth_bypass.py
│   ├── 07_crawler.py
│   ├── 08_api_fuzzing.py
│   ├── 09_concurrent.py
│   ├── 10_log_analyzer.py
│   ├── 11_ssrf.py              # 新增
│   ├── 12_ssti.py              # 新增
│   ├── 13_crlf.py              # 新增
│   ├── 14_open_redirect.py     # 新增
│   ├── 15_file_upload.py       # 新增
│   ├── 16_nosql.py             # 新增
│   ├── 17_hpp.py               # 新增
│   └── 18_info_disclosure.py   # 新增
└── results/                    # 自动生成的测试报告 (JSON)
    ├── summary.json
    ├── crawler_report.json
    ├── concurrent_report.json
    └── comparison_report.json
```

## WAF 测试工作流

### 第一步：基准测试（无 WAF）

```bash
# 直连目标站点
BASE_URL=http://192.168.1.100:3000 python3 run_all.py
```

此时所有攻击应成功（SQL注入返回全表、XSS未转义、命令注入执行等），记录基准数据。

### 第二步：WAF 拦截测试

```bash
# 通过 WAF 访问
BASE_URL=http://<WAF_IP>:<WAF_PORT> python3 run_all.py --waf
```

此时恶意请求应被 WAF 拦截（返回 403/405 等），正常请求应通过。

### 第三步：对比分析

```bash
python3 tests/10_log_analyzer.py
```

对比两轮 `results/` 目录下的 JSON 报告，计算：

- **检测率** — 被拦截的攻击数 / 总攻击数
- **误拦率（FP）** — 正常请求被拦截的比例
- **漏拦率（FN）** — 攻击请求未被拦截的比例
- **各模块拦截率** — SQL注入 / XSS / 命令注入 / 路径遍历 分别统计

## 自定义攻击脚本

你可基于 `tests/` 目录中的脚本自行扩展：

```python
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.test_utils import *

def run():
    print_banner("自定义测试")
    reset_counters()
    s = requests.Session()

    # 你的测试逻辑
    r = s.get(urljoin(BASE_URL, "/api/users?name=' OR 1=1 --"))
    assert_json_count(r, 5, "SQL注入返回全表")

    print_summary()
    return STATE["fail"]

if __name__ == "__main__":
    sys.exit(run())
```

## 依赖

- Python 3.8+
- `requests` — HTTP 客户端

```bash
pip3 install requests
```

## 相关文档

- `ATTACK_GUIDE.md` — 各漏洞点 curl/Python 攻击示例
- `../simple_html/README.md` — 目标站点说明
