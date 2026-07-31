# -*- coding: utf-8 -*-
"""proxy-pool 聚合器：抓取上游订阅 -> 解析去重 -> 输出 clash.yaml / v2ray.txt"""
import base64
import json
import re
import sys
import time
import urllib.parse
import urllib.request
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

# ---------- 主流程 ----------

def source_urls():
    today = datetime.now(BJT)
    dates = [(today - timedelta(days=i)).strftime("%Y%m%d") for i in range(2)]
    return [
        ("freeSub", "clash",
         ["https://raw.githubusercontent.com/Ruk1ng001/freeSub/main/clash.yaml"]),
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
        "proxy-groups": [
            {"name": "🚀 节点选择", "type": "select",
             "proxies": ["⚡ 自动最快", "DIRECT"] + names},
            {"name": "⚡ 自动最快", "type": "url-test",
             "url": "https://www.youtube.com/generate_204",
             "interval": 300, "tolerance": 100, "lazy": True,
             "proxies": names},
        ],
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
