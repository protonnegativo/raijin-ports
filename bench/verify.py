"""Checks that every naabu and nmap result is in a raijin-ports result.

The engine output is a file with naabu JSONL (or naabu text, host:port per line), nmap XML documents
(-oX) or both: the `raw` file raijin-ports saves, or the engines' outputs concatenated. Results are:

- each open port naabu reported, identified by (host, ip, port, protocol): it must be in the locations
  of a finding ("host:port [ip]") whose protocol matches, or in a group that lists the host
  ("host [ip]") and has the port in its ports (ranges like "19500-19699" are expanded);
- each port nmap reported open with a service name, identified by (ip, port, service): every naabu
  host on that IP must have the port with the same service (nmap's name, "ssl/" first for TLS), and
  the same product and version when nmap had them.

With a scope file (the one raijin-ports ran with), results outside it count as out of scope, not
missing.

usage: python verify.py <engine output> <raijin.json> [scope.txt]
"""
import ipaddress
import json
import re
import sys
import xml.etree.ElementTree as ET

raw, out = sys.argv[1], sys.argv[2]
o = json.load(open(out))
rules = []
if len(sys.argv) > 3:
    for line in open(sys.argv[3]):
        line = line.strip().lower()
        if line and not line.startswith("#"):
            rules.append((line.startswith("!"), line.lstrip("!").strip()))


def rule_match(rule, target):
    if "/" in rule or is_ip(rule):
        try:
            return ipaddress.ip_address(target) in ipaddress.ip_network(rule, strict=False)
        except ValueError:
            return False
    if rule.startswith("*."):
        return target.endswith(rule[1:])
    return target == rule


def in_scope(host, ip):
    if not rules:
        return True
    t = host or ip
    hits = [ex for ex, r in rules if rule_match(r, t)]
    return bool(hits) and not any(hits)


def is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def host_loc(host, ip):
    if not host:
        return ip
    return f"{host} [{ip}]" if ip else host


def port_loc(host, ip, port):
    h = host or ip
    hp = f"[{h}]:{port}" if ":" in h else f"{h}:{port}"
    return f"{hp} [{ip}]" if host and ip else hp


# what the output says: (location, port, protocol) -> list of (service, product, version) strings seen
have = {}
for f in o["findings"]:
    proto = f.get("protocol", "tcp")
    for loc in f.get("locations", []):
        m = re.match(r"^(\[[^\]]+\]|[^:\s]+):(\d+)(?: \[(.+)\])?$", loc)
        if not m:
            continue
        h, port, ip = m.group(1).strip("[]"), int(m.group(2)), m.group(3)
        hl = host_loc(h, ip) if ip else h
        have.setdefault((hl, port, proto), []).append(" ".join(x for x in (f.get("service", ""), f.get("product", ""), f.get("version", "")) if x))
for g in o["groups"]:
    for spec in g["ports"]:
        head, _, desc = spec.partition(" ")
        nums, _, proto = head.partition("/")
        proto = proto or "tcp"
        a, _, b = nums.partition("-")
        for port in range(int(a), int(b or a) + 1):
            for hl in g.get("locations", []):
                have.setdefault((hl, port, proto), []).append(desc)

naabu, nmap = set(), []
text = open(raw, encoding="utf-8", errors="replace").read()
for line in text.splitlines():
    line = line.strip()
    if line.startswith("{"):
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if isinstance(e, dict) and e.get("port") and (e.get("ip") or e.get("host")):
            host = (e.get("host") or "").lower().rstrip(".")
            ip = e.get("ip") or ""
            if host == ip or (is_ip(host) and not ip):
                host, ip = "", ip or host
            naabu.add((host, ip, int(e["port"]), (e.get("protocol") or "tcp").lower()))
    elif re.match(r"^(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9._-]+):\d+$", line):
        h, _, p = line.rpartition(":")
        h = h.strip("[]").lower()
        naabu.add(("", h, int(p), "tcp") if is_ip(h) else (h, "", int(p), "tcp"))

for doc in re.findall(r"<nmaprun.*?</nmaprun>", text, re.S):
    root = ET.fromstring(doc)
    for h in root.iter("host"):
        ip = next((a.get("addr") for a in h.iter("address") if a.get("addrtype") in ("ipv4", "ipv6")), None)
        for p in h.iter("port"):
            st = p.find("state")
            s = p.find("service")
            if st is None or not st.get("state", "").startswith("open") or s is None or not s.get("name"):
                continue
            name = ("ssl/" if s.get("tunnel") == "ssl" else "") + s.get("name")
            nmap.append((ip, int(p.get("portid")), p.get("protocol"), name, s.get("product", ""), s.get("version", "")))

oos = {r for r in naabu if not in_scope(r[0], r[1])}
naabu -= oos
miss = []
for host, ip, port, proto in sorted(naabu):
    if (host_loc(host, ip), port, proto) not in have:
        miss.append(("naabu", host, ip, port, proto))

checked = 0
for ip, port, proto, name, product, version in nmap:
    if not in_scope("", ip) and not any(i == ip for _, i, _, _ in naabu):
        continue
    hosts = sorted({h for h, i, p, pr in naabu if i == ip and p == port and pr == proto}) or [""]
    for h in hosts:
        checked += 1
        got = have.get((host_loc(h, ip), port, proto), [])
        want = [x for x in (name, product, version) if x]
        ok = any(g.split(" ", 1)[0].rstrip("?") == name and all(w in g for w in want[1:]) for g in got)
        if not ok:
            miss.append(("nmap", h, ip, port, proto, name, product, version, got))

print(f"{len(naabu)} naabu results (host, ip, port, protocol), {len(nmap)} nmap services "
      f"({checked} host/port/service checks), {len(miss)} missing from output", f"({len(oos)} out of scope)",
      "truncated" if o.get("budget") else "")
for m in miss[:5]:
    print("  MISSING", m)
sys.exit(1 if miss else 0)
