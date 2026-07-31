# -*- coding: utf-8 -*-
"""proxy-pool 聚合器：抓取上游订阅 -> 解析去重 -> 输出 clash.yaml / v2ray.txt"""
import base64
import ipaddress
import json
import os
import re
import socket
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

import yaml

sys.stdout.reconfigure(encoding="utf-8")
BJT = timezone(timedelta(hours=8))
UA = {"User-Agent": "Mozilla/5.0 (proxy-pool aggregator)"}

# ---------- 抓取 ----------

def fetch(url, tries=3):
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.read().decode("utf-8", errors="replace")
        except Exception as e:
            print(f"  抓取失败({i+1}/{tries}) {url}: {e}")
            time.sleep(3)
    return None

# ---------- clash 配置解析 ----------

def load_clash_proxies(text):
    try:
        data = yaml.safe_load(text)
        proxies = (data or {}).get("proxies") or []
        return [p for p in proxies if isinstance(p, dict)]
    except Exception:
        pass
    proxies, in_section = [], False
    for line in text.splitlines():
        if re.match(r"^proxies\s*:", line):
            in_section = True
            continue
        if in_section and re.match(r"^[A-Za-z-]+\s*:", line) and not line.startswith(" "):
            break
        if in_section:
            m = re.match(r"^\s*-\s*(\{.*\})\s*$", line)
            if m:
                try:
                    p = yaml.safe_load(m.group(1))
                    if isinstance(p, dict):
                        proxies.append(p)
                except Exception:
                    continue
    return proxies

# ---------- 分享链接解析（-> clash 代理） ----------

def b64pad(s):
    s = s.strip().replace("\n", "").replace("\r", "")
    return s + "=" * (-len(s) % 4)

def b64d(s):
    return base64.urlsafe_b64decode(b64pad(s)).decode("utf-8", errors="replace")

def parse_query(qs):
    return {k: v[0] for k, v in urllib.parse.parse_qs(qs).items()}

def conv_vmess(link):
    cfg = json.loads(b64d(link[len("vmess://"):]))
    p = {"name": cfg.get("ps") or "vmess", "type": "vmess",
         "server": cfg.get("add"), "port": int(cfg.get("port")),
         "uuid": cfg.get("id"), "alterId": int(cfg.get("aid") or 0),
         "cipher": cfg.get("scy") or "auto", "udp": True}
    if (cfg.get("tls") or "").lower() == "tls":
        p["tls"] = True
        p["skip-cert-verify"] = True
        if cfg.get("sni"):
            p["servername"] = cfg["sni"]
    net = cfg.get("net") or "tcp"
    if net == "ws":
        p["network"] = "ws"
        ws = {"path": cfg.get("path") or "/"}
        if cfg.get("host"):
            ws["headers"] = {"Host": cfg["host"]}
        p["ws-opts"] = ws
    elif net != "tcp":
        p["network"] = net
    return p

def conv_vless(link):
    u = urllib.parse.urlsplit(link)
    q = parse_query(u.query)
    sec = q.get("security", "none")
    p = {"name": urllib.parse.unquote(u.fragment) or "vless", "type": "vless",
         "server": u.hostname, "port": u.port, "uuid": u.username, "udp": True}
    if q.get("flow"):
        p["flow"] = q["flow"]
    if sec in ("tls", "reality"):
        p["tls"] = True
        p["skip-cert-verify"] = True
        if q.get("sni"):
            p["servername"] = q["sni"]
        if q.get("fp"):
            p["client-fingerprint"] = q["fp"]
        if sec == "reality":
            ro = {}
            if q.get("pbk"):
                ro["public-key"] = q["pbk"]
            if q.get("sid"):
                ro["short-id"] = q["sid"]
            p["reality-opts"] = ro
    ntype = q.get("type", "tcp")
    if ntype == "ws":
        p["network"] = "ws"
        ws = {"path": q.get("path", "/")}
        if q.get("host"):
            ws["headers"] = {"Host": q["host"]}
        p["ws-opts"] = ws
    elif ntype != "tcp":
        p["network"] = ntype
    return p

def conv_trojan(link):
    u = urllib.parse.urlsplit(link)
    q = parse_query(u.query)
    p = {"name": urllib.parse.unquote(u.fragment) or "trojan", "type": "trojan",
         "server": u.hostname, "port": u.port,
         "password": urllib.parse.unquote(u.username or ""),
         "udp": True, "skip-cert-verify": True}
    if q.get("sni"):
        p["sni"] = q["sni"]
    if q.get("type") == "ws":
        p["network"] = "ws"
        ws = {"path": q.get("path", "/")}
        if q.get("host"):
            ws["headers"] = {"Host": q["host"]}
        p["ws-opts"] = ws
    return p

def conv_ss(link):
    body = link[len("ss://"):]
    frag = ""
    if "#" in body:
        body, frag = body.split("#", 1)
    plugin = ""
    if "/?" in body:
        body, q = body.split("/?", 1)
        plugin = parse_query(q).get("plugin", "")
    if "@" not in body:
        body = b64d(body)
    userinfo, hostport = body.rsplit("@", 1)
    if ":" not in userinfo:
        userinfo = b64d(userinfo)
    method, password = userinfo.split(":", 1)
    host, port = hostport.rsplit(":", 1)
    p = {"name": urllib.parse.unquote(frag) or "ss", "type": "ss",
         "server": host, "port": int(port), "cipher": method,
         "password": password, "udp": True}
    if plugin:
        p["plugin"] = "obfs"
        p["plugin-opts"] = {"mode": "http"}
    return p

def conv_hy2(link):
    u = urllib.parse.urlsplit(link)
    q = parse_query(u.query)
    p = {"name": urllib.parse.unquote(u.fragment) or "hysteria2", "type": "hysteria2",
         "server": u.hostname, "port": u.port,
         "password": urllib.parse.unquote(u.username or ""),
         "skip-cert-verify": True}
    if q.get("sni"):
        p["sni"] = q["sni"]
    return p

CONVERTERS = {"vmess": conv_vmess, "vless": conv_vless, "trojan": conv_trojan,
              "ss": conv_ss, "hysteria2": conv_hy2, "hy2": conv_hy2}

def load_share_links(text):
    try:
        decoded = b64d(text)
        if "://" not in decoded:
            decoded = text
    except Exception:
        decoded = text
    decoded = decoded.replace("&amp;", "&")  # 部分源内容被 HTML 转义
    proxies = []
    for line in decoded.splitlines():
        line = line.strip()
        if not line or "://" not in line:
            continue
        scheme = line.split("://", 1)[0].lower()
        conv = CONVERTERS.get(scheme)
        if not conv:
            continue
        try:
            p = conv(line)
            if p.get("server") and p.get("port"):
                proxies.append(p)
        except Exception:
            continue
    return proxies

# ---------- 反向转换（clash 代理 -> 分享链接，给 v2rayN） ----------

def b64e(s, urlsafe=False, strip_pad=False):
    raw = s.encode("utf-8")
    out = (base64.urlsafe_b64encode(raw) if urlsafe else base64.b64encode(raw)).decode()
    return out.rstrip("=") if strip_pad else out

def q(s):
    return urllib.parse.quote(str(s), safe="")

def link_ss(p):
    ui = b64e(f"{p['cipher']}:{p['password']}", urlsafe=True, strip_pad=True)
    extra = ""
    if p.get("plugin"):
        opts = p.get("plugin-opts") or {}
        pl = f"obfs-local;obfs={opts.get('mode','http')}"
        if opts.get("host"):
            pl += f";obfs-host={opts['host']}"
        extra = "/?plugin=" + q(pl)
    return f"ss://{ui}@{p['server']}:{p['port']}{extra}#{q(p['name'])}"

def link_ssr(p):
    pwd = b64e(p["password"], urlsafe=True, strip_pad=True)
    remarks = b64e(p["name"], urlsafe=True, strip_pad=True)
    core = f"{p['server']}:{p['port']}:{p.get('protocol','origin')}:{p['cipher']}:{p.get('obfs','plain')}:{pwd}/?remarks={remarks}"
    return "ssr://" + b64e(core, urlsafe=True, strip_pad=True)

def link_vmess(p):
    j = {"v": "2", "ps": p["name"], "add": p["server"], "port": str(p["port"]),
         "id": p["uuid"], "aid": str(p.get("alterId", 0)),
         "scy": p.get("cipher", "auto"), "net": p.get("network", "tcp"),
         "type": "none", "host": "", "path": "", "tls": "tls" if p.get("tls") else ""}
    if p.get("servername"):
        j["sni"] = p["servername"]
    ws = p.get("ws-opts") or {}
    if p.get("network") == "ws":
        j["path"] = ws.get("path", "/")
        j["host"] = (ws.get("headers") or {}).get("Host", "")
    return "vmess://" + b64e(json.dumps(j, ensure_ascii=False))

def link_vless(p):
    params = {}
    if p.get("tls"):
        ro = p.get("reality-opts") or {}
        params["security"] = "reality" if ro else "tls"
        if p.get("servername"):
            params["sni"] = p["servername"]
        if p.get("client-fingerprint"):
            params["fp"] = p["client-fingerprint"]
        if p.get("flow"):
            params["flow"] = p["flow"]
        if ro.get("public-key"):
            params["pbk"] = ro["public-key"]
        if ro.get("short-id"):
            params["sid"] = ro["short-id"]
    else:
        params["security"] = "none"
    net = p.get("network", "tcp")
    params["type"] = net
    if net == "ws":
        ws = p.get("ws-opts") or {}
        params["path"] = ws.get("path", "/")
        host = (ws.get("headers") or {}).get("Host")
        if host:
            params["host"] = host
    qs = "&".join(f"{k}={q(v)}" for k, v in params.items())
    return f"vless://{p['uuid']}@{p['server']}:{p['port']}?{qs}#{q(p['name'])}"

def link_trojan(p):
    params = {"allowInsecure": "1"}
    if p.get("sni"):
        params["sni"] = p["sni"]
    if p.get("network") == "ws":
        ws = p.get("ws-opts") or {}
        params["type"] = "ws"
        params["path"] = ws.get("path", "/")
        host = (ws.get("headers") or {}).get("Host")
        if host:
            params["host"] = host
    qs = "&".join(f"{k}={q(v)}" for k, v in params.items())
    return f"trojan://{q(p['password'])}@{p['server']}:{p['port']}?{qs}#{q(p['name'])}"

def link_hy2(p):
    qs = "insecure=1"
    if p.get("sni"):
        qs += f"&sni={q(p['sni'])}"
    return f"hysteria2://{q(p['password'])}@{p['server']}:{p['port']}?{qs}#{q(p['name'])}"

LINKERS = {"ss": link_ss, "ssr": link_ssr, "vmess": link_vmess,
           "vless": link_vless, "trojan": link_trojan, "hysteria2": link_hy2}

# ---------- 校验 ----------

REQUIRED = {"ss": ["server", "port", "cipher", "password"],
            "ssr": ["server", "port", "cipher", "password", "protocol", "obfs"],
            "vmess": ["server", "port", "uuid"], "vless": ["server", "port", "uuid"],
            "trojan": ["server", "port", "password"], "hysteria2": ["server", "port", "password"],
            "hysteria": ["server", "port"], "tuic": ["server", "port", "uuid", "password"],
            "socks5": ["server", "port"], "http": ["server", "port"]}

def valid(p):
    t = str(p.get("type", "")).lower()
    if not all(p.get(k) not in (None, "") for k in REQUIRED.get(t, ["server", "port"])):
        return False
    try:
        port = int(p.get("port"))
        if not (1 <= port <= 65535):
            return False
        p["port"] = port
    except Exception:
        return False
    return True

# ---------- 国家识别 ----------

CC_NAME = {
    "HK": "香港", "TW": "台湾", "MO": "澳门", "JP": "日本", "SG": "新加坡", "KR": "韩国",
    "US": "美国", "CA": "加拿大", "GB": "英国", "DE": "德国", "FR": "法国", "NL": "荷兰",
    "RU": "俄罗斯", "IN": "印度", "TR": "土耳其", "TH": "泰国", "VN": "越南", "MY": "马来西亚",
    "PH": "菲律宾", "ID": "印尼", "UA": "乌克兰", "GR": "希腊", "PL": "波兰", "NO": "挪威",
    "SE": "瑞典", "FI": "芬兰", "RO": "罗马尼亚", "LV": "拉脱维亚", "LT": "立陶宛", "ES": "西班牙",
    "IT": "意大利", "BR": "巴西", "AR": "阿根廷", "MX": "墨西哥", "CL": "智利", "EG": "埃及",
    "ZA": "南非", "AE": "阿联酋", "SA": "沙特", "IL": "以色列", "IR": "伊朗", "PK": "巴基斯坦",
    "KZ": "哈萨克斯坦", "CH": "瑞士", "AT": "奥地利", "BE": "比利时", "IE": "爱尔兰", "PT": "葡萄牙",
    "CZ": "捷克", "HU": "匈牙利", "DK": "丹麦", "NZ": "新西兰", "AU": "澳大利亚", "IS": "冰岛",
    "LU": "卢森堡", "EE": "爱沙尼亚", "BG": "保加利亚", "HR": "克罗地亚", "RS": "塞尔维亚",
    "CO": "哥伦比亚", "PE": "秘鲁", "PA": "巴拿马", "UY": "乌拉圭", "VE": "委内瑞拉", "KH": "柬埔寨",
    "MM": "缅甸", "NP": "尼泊尔", "BD": "孟加拉", "LK": "斯里兰卡", "MN": "蒙古", "LA": "老挝",
    "MT": "马耳他", "CY": "塞浦路斯", "MD": "摩尔多瓦", "AM": "亚美尼亚", "AZ": "阿塞拜疆",
    "GE": "格鲁吉亚", "BY": "白俄罗斯", "NG": "尼日利亚", "KE": "肯尼亚", "MA": "摩洛哥",
    "QA": "卡塔尔", "KW": "科威特", "EC": "厄瓜多尔", "BO": "玻利维亚", "PY": "巴拉圭",
    "CU": "古巴", "CN": "中国", "SC": "塞舌尔", "MU": "毛里求斯", "SK": "斯洛伐克",
    "SI": "斯洛文尼亚", "MK": "北马其顿", "AL": "阿尔巴尼亚", "DZ": "阿尔及利亚",
    "TN": "突尼斯", "IQ": "伊拉克", "JO": "约旦", "LB": "黎巴嫩", "BH": "巴林",
    "OM": "阿曼", "UZ": "乌兹别克斯坦", "KG": "吉尔吉斯斯坦", "TJ": "塔吉克斯坦",
    "TM": "土库曼斯坦", "BN": "文莱", "PR": "波多黎各", "DO": "多米尼加", "GT": "危地马拉",
    "CR": "哥斯达黎加", "TT": "特立尼达和多巴哥", "IM": "马恩岛", "JE": "泽西岛",
    "GG": "根西岛", "GI": "直布罗陀", "AD": "安道尔", "LI": "列支敦士登", "MC": "摩纳哥",
    "SM": "圣马力诺", "VA": "梵蒂冈", "FO": "法罗群岛", "GL": "格陵兰", "PF": "法属波利尼西亚",
}
CN_TO_CC = {v: k for k, v in CC_NAME.items()}
CN_TO_CC.update({"美國": "US", "台灣": "TW", "韓國": "KR", "俄羅斯": "RU", "英國": "GB",
                 "德國": "DE", "法國": "FR", "澳洲": "AU", "荷蘭": "NL", "泰國": "TH",
                 "馬來西亞": "MY", "菲律賓": "PH", "印度尼西亚": "ID", "烏克蘭": "UA",
                 "希臘": "GR", "波蘭": "PL", "芬蘭": "FI", "羅馬尼亞": "RO", "阿聯酋": "AE",
                 "新西蘭": "NZ", "澳門": "MO", "冰島": "IS", "盧森堡": "LU", "愛爾蘭": "IE",
                 "比利时": "BE", "丹麥": "DK", "印度尼西亚": "ID", "哈薩克斯坦": "KZ"})
_CN_KEYS = sorted(CN_TO_CC.keys(), key=len, reverse=True)

FLAG_RE = re.compile(r"[\U0001F1E6-\U0001F1FF]{2}")
PREFIX_RE = re.compile(r"^\[[^\]]*\]\s*")
ISO_RE = re.compile(r"^([A-Z]{2})(?=[-_\s|])")

def flag_of(cc):
    return chr(0x1F1E6 + ord(cc[0]) - 65) + chr(0x1F1E6 + ord(cc[1]) - 65)

def cc_from_flag(flag):
    return chr(ord(flag[0]) - 0x1F1E6 + 65) + chr(ord(flag[1]) - 0x1F1E6 + 65)

def detect_cc(name):
    """从节点名识别国别：国旗 emoji > 中文国名 > 前缀 ISO 代码"""
    s = PREFIX_RE.sub("", name)
    m = FLAG_RE.search(s)
    if m:
        return cc_from_flag(m.group(0))
    for zh in _CN_KEYS:
        if zh in s:
            return CN_TO_CC[zh]
    m = ISO_RE.match(s)
    if m and m.group(1) in CC_NAME:
        return m.group(1)
    return None

# ---------- GeoIP 补识别 ----------

GEOIP_URLS = [
    "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb",
    "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country.mmdb",
    "https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/GeoLite2-Country.mmdb",
]

def download_mmdb():
    for u in GEOIP_URLS:
        try:
            req = urllib.request.Request(u, headers=UA)
            with urllib.request.urlopen(req, timeout=60) as r:
                data = r.read()
            if len(data) > 1_000_000:
                fd, path = tempfile.mkstemp(suffix=".mmdb")
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
                print(f"  GeoIP 库下载成功（{len(data)//1024//1024}MB）：{u}")
                return path
        except Exception as e:
            print(f"  GeoIP 下载失败 {u}: {e}")
    return None

def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def _resolve(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

def enrich_cc(merged, country_of):
    """对名称识别失败的节点，按服务器 IP 归属地补识别；任何一步失败都静默跳过"""
    unknown = [p for p in merged if not country_of.get(p["name"])]
    if not unknown:
        return
    try:
        import maxminddb
    except ImportError:
        print("  maxminddb 未安装，跳过 GeoIP 补识别")
        return
    path = download_mmdb()
    if not path:
        return
    try:
        hosts = {p["server"] for p in unknown}
        ip_of = {h: h for h in hosts if _is_ip(h)}
        todo = [h for h in hosts if h not in ip_of]
        with ThreadPoolExecutor(max_workers=48) as ex:
            futs = {ex.submit(_resolve, h): h for h in todo}
            try:
                for fut in as_completed(futs, timeout=90):
                    ip = fut.result()
                    if ip:
                        ip_of[futs[fut]] = ip
            except Exception:
                pass
        fixed = 0
        with maxminddb.open_database(path) as reader:
            for p in unknown:
                ip = ip_of.get(p["server"])
                if not ip:
                    continue
                try:
                    rec = reader.get(ip)
                except Exception:
                    continue
                # mihomo metadb 返回值可能是小写字符串('kr')或列表(['us','google'])
                if isinstance(rec, str):
                    cc = rec
                elif isinstance(rec, (list, tuple)) and rec:
                    cc = str(rec[0])
                elif isinstance(rec, dict):  # 标准 GeoLite2 格式
                    cc = ((rec.get("country") or {}).get("iso_code")
                          or (rec.get("registered_country") or {}).get("iso_code"))
                else:
                    cc = None
                cc = cc.upper() if cc else None
                if cc and re.fullmatch(r"[A-Z]{2}", cc):
                    country_of[p["name"]] = cc
                    fixed += 1
        print(f"GeoIP 补识别成功: {fixed}/{len(unknown)}")
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass

# ---------- 主流程 ----------

def source_urls():
    today = datetime.now(BJT)
    dates = [(today - timedelta(days=i)).strftime("%Y%m%d") for i in range(2)]
    return [
        ("freeSub", "clash",
         ["https://raw.githubusercontent.com/Ruk1ng001/freeSub/main/clash.yaml"]),
        ("NoMoreWalls", "clash",
         ["https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.meta.yml"]),
        ("free18", "clash",
         ["https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/c.yaml"]),
        ("ermaozi", "clash",
         ["https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/clash.yml"]),
        ("clashfree", "clash",
         [f"https://raw.githubusercontent.com/free-nodes/clashfree/main/clash{d}.yml" for d in dates]),
        ("Eternity", "clash",
         ["https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.yml"]),
        ("Pawdroid", "share",
         ["https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub"]),
    ]

def main():
    merged, stats, seen = [], {}, set()
    for tag, kind, urls in source_urls():
        text = None
        for u in urls:
            text = fetch(u)
            if text and len(text) > 200:
                break
        if not text:
            stats[tag] = 0
            print(f"[{tag}] 抓取失败，本轮跳过")
            continue
        plist = load_clash_proxies(text) if kind == "clash" else load_share_links(text)
        ok = 0
        for p in plist:
            if not valid(p):
                continue
            key = (str(p.get("type")).lower(), p.get("server"), p.get("port"),
                   str(p.get("uuid") or p.get("password") or "")[:16])
            if key in seen:
                continue
            seen.add(key)
            ok += 1
            base = str(p.get("name") or "node").strip().replace("\n", " ")[:60]
            p["name"] = f"[{tag}#{ok:03d}] {base}"
            merged.append(p)
        stats[tag] = ok
        print(f"[{tag}] 有效节点 {ok} 个（原始 {len(plist)}）")
    print(f"合计去重后节点: {len(merged)}")

    names = [p["name"] for p in merged]

    # ---- 国家分组：名称识别 + GeoIP 补识别 ----
    country_of = {p["name"]: detect_cc(p["name"]) for p in merged}
    print(f"名称识别国别: {sum(1 for v in country_of.values() if v)}/{len(merged)}")
    enrich_cc(merged, country_of)

    buckets = {}
    for p in merged:
        buckets.setdefault(country_of[p["name"]], []).append(p["name"])
    unknown_names = buckets.pop(None, [])

    TEST_URL = "https://www.youtube.com/generate_204"
    POPULAR = ["HK", "TW", "JP", "SG", "KR", "US"]
    ordered = sorted(buckets.items(),
                     key=lambda kv: (POPULAR.index(kv[0]) if kv[0] in POPULAR else 90, -len(kv[1])))

    def ut(gname, ns):
        return {"name": gname, "type": "url-test", "url": TEST_URL,
                "interval": 300, "tolerance": 100, "lazy": True, "proxies": ns}

    country_groups, tiny = [], []
    for cc, ns in ordered:
        if len(ns) < 3:
            tiny.extend(ns)
            continue
        country_groups.append(ut(f"{flag_of(cc)} {CC_NAME.get(cc, cc)}·{len(ns)}", ns))
    n_real_groups = len(country_groups)
    if tiny:
        country_groups.append(ut(f"🌍 其他·{len(tiny)}", tiny))
    if unknown_names:
        country_groups.append(ut(f"🏳️ 未标注·{len(unknown_names)}", unknown_names))

    group_names = [g["name"] for g in country_groups]
    groups = ([{"name": "🚀 节点选择", "type": "select",
                "proxies": ["⚡ 自动最快"] + group_names + ["DIRECT"] + names},
               ut("⚡ 自动最快", names)]
              + country_groups)

    top = sorted(buckets.items(), key=lambda kv: -len(kv[1]))[:10]
    print(f"分组完成: {n_real_groups} 个国家组，其他 {len(tiny)}，未标注 {len(unknown_names)}")
    print("国别 TOP10: " + ", ".join(f"{CC_NAME.get(cc, cc)}{len(ns)}" for cc, ns in top))

    clash = {
        "mixed-port": 7890,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "ipv6": False,
        "dns": {
            "enable": True,
            "listen": "0.0.0.0:1053",
            "enhanced-mode": "fake-ip",
            "nameserver": ["223.5.5.5", "119.29.29.29"],
            "fallback": ["https://dns.google/dns-query", "https://1.1.1.1/dns-query"],
            "fake-ip-filter": ["*.lan", "*.local", "localhost.*", "*.msftconnecttest.com",
                               "*.msftncsi.com", "time.*.com", "*.stun.*.*"],
        },
        "proxies": merged,
        "proxy-groups": groups,
        "rules": [
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
            "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
            "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
            "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
            "GEOIP,CN,DIRECT",
            "MATCH,🚀 节点选择",
        ],
    }
    with open("clash.yaml", "w", encoding="utf-8") as f:
        yaml.safe_dump(clash, f, allow_unicode=True, sort_keys=False, default_flow_style=False)

    links, skipped = [], 0
    for p in merged:
        linker = LINKERS.get(str(p.get("type")).lower())
        if not linker:
            skipped += 1
            continue
        try:
            links.append(linker(p))
        except Exception:
            skipped += 1
    v2 = base64.b64encode("\n".join(links).encode("utf-8")).decode()
    with open("v2ray.txt", "w", encoding="utf-8") as f:
        f.write(v2)
    print(f"v2ray.txt: {len(links)} 条分享链接（{skipped} 个类型不支持已跳过）")

    now = datetime.now(BJT).strftime("%Y-%m-%d %H:%M:%S 北京时间")
    stat_rows = "\n".join(f"| {k} | {v} |" for k, v in stats.items())
    block = (f"<!--STATS-->\n更新于 **{now}**，共 **{len(merged)}** 个去重节点\n\n"
             f"| 上游源 | 节点数 |\n|---|---|\n{stat_rows}\n<!--/STATS-->")
    try:
        with open("README.md", encoding="utf-8") as f:
            readme = f.read()
        readme = re.sub(r"<!--STATS-->.*<!--/STATS-->", block, readme, flags=re.S)
        with open("README.md", "w", encoding="utf-8") as f:
            f.write(readme)
    except FileNotFoundError:
        pass
    print("完成：clash.yaml / v2ray.txt / README.md 已更新")

if __name__ == "__main__":
    main()
