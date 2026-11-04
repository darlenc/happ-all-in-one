#!/usr/bin/env python3
"""Merge public VPN URI subscriptions for Happ. Standard library only.

Static format checks are NOT a connectivity, ownership, or safety audit.
"""
from __future__ import annotations

import argparse
import base64
import collections
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import re
import time
from urllib.parse import parse_qs, unquote, urlsplit
from urllib.request import Request, urlopen

SOURCES = {
    "imnocrew": "https://raw.githubusercontent.com/imnocrew/vpn-configs/master/top100.txt",
    "au1rxx": "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/v2ray-base64.txt",
    "mini": "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/mini.txt",
    "collector": "https://raw.githubusercontent.com/mehrtat/vless-collector/main/vless.txt",
    "radar": "https://radarhub.top/v2ray.txt",
}
PREFIX = re.compile(r"^(vless|trojan|hy2|hysteria2)://", re.I)
UUID = re.compile(r"^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$")
MAX_BYTES = 1_500_000


def subscription_lines(data: str) -> list[str]:
    lines = [s.strip().lstrip("\ufeff") for s in data.splitlines()]
    if not any(PREFIX.match(s) for s in lines):
        try:
            raw = "".join(x for x in lines if not x.startswith("#"))
            raw = re.sub(r"\\s+", "", raw).replace("-", "+").replace("_", "/")
            data = base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8")
            lines = [s.strip() for s in data.splitlines()]
        except (ValueError, UnicodeError):
            return []
    return [s for s in lines if PREFIX.match(s)]


def public_host(name: str) -> bool:
    if not name or name.lower() == "localhost":
        return False
    try:
        return ipaddress.ip_address(name).is_global
    except ValueError:
        return (
            bool(re.fullmatch(r"[A-Za-z0-9.-]{4,253}", name))
            and "." in name
            and not name.lower().endswith((".local", ".lan", ".internal", ".invalid"))
        )


def parse_node(uri: str) -> dict | None:
    if len(uri) > 4500:
        return None
    try:
        p = urlsplit(uri)
        scheme = p.scheme.lower()
        host, port = p.hostname, p.port
        if scheme not in ("vless", "trojan", "hy2", "hysteria2"):
            return None
        if not host or not port or not public_host(host):
            return None
        if re.search(r"%(?![0-9a-fA-F]{2})", p.netloc):
            return None
        params = {k.lower(): vs[-1] for k, vs in parse_qs(p.query, keep_blank_values=True).items()}
        q = {k: v.lower() for k, v in params.items()}
        if any(q.get(k) in ("1", "true", "yes") for k in
               ("insecure", "allowinsecure", "skip-cert-verify", "allow-insecure")):
            return None
        user = unquote(p.username or "")
        if scheme == "vless":
            if not UUID.fullmatch(user) or q.get("security") not in ("tls", "reality"):
                return None
            if q.get("security") == "reality" and not params.get("pbk"):
                return None
        elif not user:
            return None
        if scheme == "trojan" and q.get("security", "tls") != "tls":
            return None
        if scheme in ("hy2", "hysteria2") and not (q.get("sni") or q.get("peer")):
            return None
        return {
            "uri": uri.split("#", 1)[0],
            "host": host.lower(),
            "port": port,
            "scheme": scheme,
            "sni": (q.get("sni") or q.get("servername") or q.get("peer") or "").strip("."),
        }
    except (ValueError, UnicodeError):
        return None


def netkey(host: str) -> str:
    try:
        ip = ipaddress.ip_address(host)
        return str(ipaddress.ip_network(
            f"{ip}/24" if ip.version == 4 else f"{ip}/48", strict=False))
    except ValueError:
        return host


def fetch(url: str) -> str:
    for attempt in range(2):
        try:
            req = Request(url, headers={"User-Agent": "HappAllInOne/1.0", "Accept": "text/plain,*/*"})
            with urlopen(req, timeout=18) as response:
                data = response.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise ValueError("source too large")
            return data.decode("utf-8-sig", errors="replace")
        except Exception as exc:
            print(f"Source failure ({attempt + 1}/2): {url}: {exc}")
            if attempt == 0:
                time.sleep(1)
    return ""


def select(groups: dict[str, list[dict]], maximum: int) -> list[dict]:
    queues = {src: collections.deque(nodes) for src, nodes in groups.items()}
    used = set()
    subnets = collections.Counter()
    snis = collections.Counter()
    selected = []
    while any(queues.values()) and len(selected) < maximum:
        for source, queue in queues.items():
            if not queue:
                continue
            node = queue.popleft()
            identity = (node["host"], node["port"], node["scheme"])
            net = netkey(node["host"])
            sni = node["sni"]
            if identity in used or subnets[net] >= 2 or (sni and snis[sni] >= 4):
                continue
            used.add(identity)
            subnets[net] += 1
            if sni:
                snis[sni] += 1
            selected.append({**node, "source": source})
            if len(selected) >= maximum:
                break
    return selected


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--out", default="happ-all.txt")
    args = parser.parse_args()
    if not 1 <= args.limit <= 500:
        parser.error("limit must be 1..500")

    groups = {}
    report_sources = {}
    for name, url in SOURCES.items():
        lines = subscription_lines(fetch(url))
        filtered = [n for line in lines if (n := parse_node(line)) is not None]
        groups[name] = filtered
        report_sources[name] = {"raw": len(lines), "format_accepted": len(filtered)}
        print(f"{name}: {len(lines)} links, {len(filtered)} valid formats")

    nodes = select(groups, args.limit)
    if len(nodes) < min(30, args.limit):
        raise RuntimeError(
            f"Only {len(nodes)} nodes survived: refusing to replace previous good subscription")

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    output = Path(args.out)
    output.parent.mkdir(parents=True, exist_ok=True)
    header = [
        f"#profile-title: Happ ALL-IN-ONE ({len(nodes)})",
        "#profile-update-interval: 6",
        f"# Generated: {now}",
        "# Public unknown nodes. Reachability and owner trust NOT verified.",
    ]
    lines = [n["uri"] + f"#AI-{i:03d}-{n['source']}"
             for i, n in enumerate(nodes, 1)]
    payload = "\n".join(header + lines) + "\n"
    staging = output.with_suffix(output.suffix + ".tmp")
    staging.write_text(payload, encoding="utf-8")
    staging.replace(output)

    report = {
        "generated_utc": now,
        "nodes": len(nodes),
        "sources": report_sources,
        "by_source": dict(collections.Counter(n["source"] for n in nodes)),
        "by_protocol": dict(collections.Counter(n["scheme"] for n in nodes)),
        "notice": "Static filtering only: not tested from Russia or audited for privacy.",
    }
    Path("status.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(nodes)} entries to {output}")


if __name__ == "__main__":
    main()
