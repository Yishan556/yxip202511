import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import re
import os
import ipaddress
import logging
import time
from tempfile import NamedTemporaryFile
from urllib.parse import urlparse

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

URLS = [
    'https://ip.164746.xyz',
    'https://www.wetest.vip/page/cloudflare/address_v4.html',
    'https://api.uouin.com/cloudflare.html',
    'https://ipdb.api.030101.xyz/?type=bestcf&country=true',
    'https://ipdb.api.030101.xyz/?type=cfv4;cfv6&country=true',
    'https://bestip.badking.pp.ua',
    'https://ipdb.api.030101.xyz/?type=bestproxy&country=true'
]

# IPv4 + IPv6 + 可选端口
IP_PORT_PATTERN = re.compile(
    r'('
    r'(?:\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)'        # IPv4
    r'|'
    r'(?:\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b)'  # IPv6
    r')'
    r'(?::(\d{1,5}))?'  # 可选端口
)

MAX_PER_SITE = 20  # 每个站点最大抓取数量

def create_session(retries=2, backoff_factor=0.5, status_forcelist=(500, 502, 503, 504)):
    session = requests.Session()
    retry = Retry(
        total=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        allowed_methods=["GET"]
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; IP-Scraper/1.0; +https://example.com)"
    })
    return session

def normalize_and_validate_ip(raw_ip: str, raw_port: str = None):
    try:
        ip_obj = ipaddress.ip_address(raw_ip)
        if raw_port:
            port = int(raw_port)
            if not (0 < port <= 65535):
                return None
        else:
            port = None

        if ip_obj.version == 6:
            if port:
                return f"[{ip_obj}]:{port}"
            return f"[{ip_obj}]"
        else:
            if port:
                return f"{ip_obj}:{port}"
            return str(ip_obj)
    except ValueError:
        return None

def fetch_ips_in_order(session, url, last_request_times):
    collected = []
    parsed = urlparse(url)
    domain = parsed.netloc

    # 简单节流
    now = time.monotonic()
    if domain in last_request_times:
        elapsed = now - last_request_times[domain]
        if elapsed < 0.5:
            time.sleep(0.5 - elapsed)
    last_request_times[domain] = time.monotonic()

    try:
        resp = session.get(url, timeout=5)
        if resp.status_code == 200 and resp.text:
            matches = IP_PORT_PATTERN.findall(resp.text)
            for raw_ip, raw_port in matches:
                ip_str = normalize_and_validate_ip(raw_ip, raw_port)
                if not ip_str:
                    continue
                if ip_str not in (ip for ip, _ in collected):  # 站点内去重
                    collected.append((ip_str, url))
                if len(collected) >= MAX_PER_SITE:
                    break
        else:
            logging.warning("请求 %s 返回状态码 %s", url, resp.status_code)
    except requests.RequestException as e:
        logging.warning("请求 %s 失败: %s", url, e)
    return collected

def main():
    if os.path.exists('ip.txt'):
        try:
            os.remove('ip.txt')
        except OSError as e:
            logging.error("删除旧 ip.txt 失败: %s", e)

    session = create_session()
    last_request_times = {}
    global_unique = []
    global_seen = set()

    for url in URLS:
        logging.info("抓取 %s （按网页顺序取前 %d 个）", url, MAX_PER_SITE)
        site_ips = fetch_ips_in_order(session, url, last_request_times)
        for ip, source in site_ips:
            if ip not in global_seen:
                global_seen.add(ip)
                global_unique.append((ip, source))
        logging.info("从 %s 获取 %d 个 IP，累计 %d 个", url, len(site_ips), len(global_unique))

    if global_unique:
        try:
            with NamedTemporaryFile('w', delete=False, encoding='utf-8', newline='\n') as tmp:
                for ip, src in global_unique:
                    tmp.write(f"{ip}\t{src}\n")
                temp_name = tmp.name
            os.replace(temp_name, 'ip.txt')
            logging.info("已保存 %d 个唯一 IP 到 ip.txt（包含来源 URL）", len(global_unique))
        except Exception as e:
            logging.error("写入 ip.txt 失败: %s", e)
    else:
        logging.info("未抓取到任何 IP")

if __name__ == '__main__':
    main()

