"""07_crawler — 全站自动爬虫，模拟自动化测试程序"""

import sys, os, json, time, re
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.test_utils import *
from html.parser import HTMLParser


class LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[str] = []
        self.forms: list[dict] = []
        self.title: str = ""
        self._in_title = False
        self._current_form = None
        self._current_input = None

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == "a" and "href" in attrs_dict:
            href = attrs_dict["href"]
            if href and not href.startswith(("http://", "https://", "#", "javascript:", "mailto:")):
                self.links.append(href)
        elif tag == "title":
            self._in_title = True
        elif tag == "form":
            self._current_form = {
                "action": attrs_dict.get("action", ""),
                "method": attrs_dict.get("method", "GET").upper(),
                "enctype": attrs_dict.get("enctype", ""),
                "inputs": [],
            }
            self.forms.append(self._current_form)
        elif tag == "input" and self._current_form is not None:
            self._current_form["inputs"].append({
                "name": attrs_dict.get("name", ""),
                "type": attrs_dict.get("type", "text"),
                "value": attrs_dict.get("value", ""),
            })
        elif tag == "textarea" and self._current_form is not None:
            self._current_form["inputs"].append({
                "name": attrs_dict.get("name", ""),
                "type": "textarea",
                "value": "",
            })

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag == "form":
            self._current_form = None

    def handle_data(self, data):
        if self._in_title:
            self.title += data


def run():
    print_banner("07: 全站爬虫")
    reset_counters()
    s = requests.Session()

    visited: set[str] = set()
    to_visit: list[str] = ["/"]
    page_map: dict[str, dict] = {}
    protected_pages: list[dict] = []
    errors: list[dict] = []

    info("开始爬取...")

    # Step 1: 爬取公开页面
    while to_visit and len(visited) < 30:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            r = s.get(urljoin(BASE_URL, url), timeout=TIMEOUT, allow_redirects=False)
        except Exception as e:
            errors.append({"url": url, "error": str(e)})
            continue

        parser = LinkExtractor()
        parser.feed(r.text)
        parser.close()

        page_map[url] = {
            "status": r.status_code,
            "size": len(r.text),
            "title": parser.title.strip() or "(无标题)",
            "links": len(parser.links),
            "forms": len(parser.forms),
        }

        if r.status_code == 302:
            location = r.headers.get("Location", "")
            if "/login" in location:
                protected_pages.append({"url": url, "redirect_to": location})

        for link in parser.links:
            full = urljoin(url, link).replace(BASE_URL, "")
            if full not in visited and not full.startswith("http"):
                to_visit.append(full)

        info(f"  {url} → {r.status_code} ({parser.title.strip() or '无标题'})")

    ok(f"爬取完成: {len(visited)} 个页面")

    # Step 2: 登录后爬取受保护页面
    info("登录后爬取受保护页面")
    s2 = requests.Session()
    s2.post(urljoin(BASE_URL, "/login"), data={"username": "test", "password": "test123"},
            timeout=TIMEOUT, allow_redirects=True)

    protected_urls = ["/dashboard", "/profile"]
    for url in protected_urls:
        if url in visited:
            continue
        visited.add(url)
        try:
            r = s2.get(urljoin(BASE_URL, url), timeout=TIMEOUT, allow_redirects=False)
        except Exception as e:
            errors.append({"url": url, "error": str(e)})
            continue

        parser = LinkExtractor()
        parser.feed(r.text)
        parser.close()

        page_map[url] = {
            "status": r.status_code,
            "size": len(r.text),
            "title": parser.title.strip() or "(无标题)",
            "links": len(parser.links),
            "forms": len(parser.forms),
            "auth_required": True,
        }
        info(f"  {url} → {r.status_code} ({parser.title.strip() or '无标题'}) [需登录]")

    ok(f"登录后爬取: {len(protected_urls)} 个受保护页")

    # Step 3: 统计
    public_pages = {k: v for k, v in page_map.items() if not v.get("auth_required")}
    auth_pages = {k: v for k, v in page_map.items() if v.get("auth_required")}

    info(f"统计 — 公开: {len(public_pages)}  需登录: {len(auth_pages)}  错误: {len(errors)}")

    # Step 4: 输出报告
    report = {
        "base_url": BASE_URL,
        "crawled_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "pages": page_map,
        "protected_pages": protected_pages,
        "errors": errors,
        "statistics": {
            "total_pages": len(visited),
            "public": len(public_pages),
            "auth_required": len(auth_pages),
            "errors": len(errors),
        },
    }

    output_path = os.path.join(OUTPUT_DIR, "crawler_report.json")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    ok(f"站点地图报告已保存: {output_path}")

    print_summary()
    save_results("07_crawler")
    return STATE["fail"]


if __name__ == "__main__":
    sys.exit(run())
