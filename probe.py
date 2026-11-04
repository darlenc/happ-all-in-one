#!/usr/bin/env python3
"""Probe public VPN nodes through a real HTTPS request using sing-box.

Tests run FROM THE GITHUB ACTIONS RUNNER, not from the user's network in Russia.
No TCP-only "ping" is counted as a passing proxy.
"""
from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import json
from pathlib import Path
import socket
import ssl
import statistics
import subprocess
import tempfile
import time
from urllib.parse import parse_qs, unquote, urlsplit
from urllib.request import ProxyHandler, Request, build_opener, HTTPSHandler


TEST_URLS = (
    ("https://www.gstatic.com/generate_204", 204),
    ("https://www.cloudflare.com/cdn-cgi/trace", 200),
)
ALLOWED_FP = {"chrome", "firefox", "edge", "safari", "ios", "android", "qq", "360", "random", "randomized"}
ALLOWED_TRANSPORT = {"tcp", "raw", "ws", "grpc", "httpupgrade", "http"}
MAX_LINE_LENGTH = 4500


def query_map(query: str) -> dict[str, str]:
    return {key.lower(): vals[-1] for key, vals in
            parse_qs(query, keep_blank_values=True).items()}


def convert_uri(uri: str) -> dict | None:
    """Only convert simple, supported URI variants; never loosen TLS checks."""
    if len(uri) > MAX_LINE_LENGTH:
        return None
    try:
        p = urlsplit(uri.strip())
        q = query_map(p.query)
        scheme = p.scheme.lower()
        if not p.hostname or not p.port:
            return None
        if any(q.get(k, "").lower() in ("true", "1", "yes") for k in
               ("insecure", "allowinsecure", "skip-cert-verify", "allow-insecure")):
            return None
        sni = q.get("sni") or q.get("peer") or q.get("servername") or p.hostname
        node = {"type": "hysteria2" if scheme == "hy2" else scheme,
                "tag": "checked-node", "server": p.hostname, "server_port": p.port}
        tls = {"enabled": True, "server_name": sni}
        if "alpn" in q:
            val = [x.strip() for x in q["alpn"].split(",") if x.strip()]
            if val:
                tls["alpn"] = val
        fp = q.get("fp", "").lower()
        if scheme == "vless" and q.get("security", "") == "reality" and not fp:
            fp = "chrome"
        if fp in ALLOWED_FP and scheme != "hy2" and scheme != "hysteria2":
            tls["utls"] = {"enabled": True, "fingerprint": fp}
        if scheme == "vless":
            if q.get("security") not in ("tls", "reality"):
                return None
            node["uuid"] = unquote(p.username or "")
            if not node["uuid"]:
                return None
            if q.get("flow"):
                node["flow"] = q["flow"]
            if q.get("security") == "reality":
                if not q.get("pbk"):
                    return None
                tls["reality"] = {"enabled": True, "public_key": q["pbk"], "short_id": q.get("sid", "")}
        elif scheme == "trojan":
            if q.get("security", "tls") != "tls":
                return None
            node["password"] = unquote(p.username or "")
            if not node["password"]:
                return None
        elif scheme in ("hy2", "hysteria2"):
            node["password"] = unquote(p.username or "")
            if p.password:
                node["password"] += ":" + unquote(p.password)
            if not node["password"]:
                return None
            obfs = q.get("obfs", "")
            if obfs and obfs != "salamander":
                return None
            if obfs:
                if not q.get("obfs-password"):
                    return None
                node["obfs"] = {"type": "salamander", "password": q["obfs-password"]}
        else:
            return None
        node["tls"] = tls

        if scheme in ("vless", "trojan"):
            transport = q.get("type", "tcp").lower()
            if transport not in ALLOWED_TRANSPORT:
                return None
            if transport in ("ws", "grpc", "httpupgrade", "http"):
                trans = {"type": transport}
                if transport == "grpc":
                    trans["service_name"] = q.get("servicename", "")
                else:
                    trans["path"] = q.get("path", "/")
                    if q.get("host"):
                        if transport == "http":
                            trans["host"] = [q["host"]]
                        elif transport == "httpupgrade":
                            trans["host"] = q["host"]
                        else:
                            trans["headers"] = {"Host": q["host"]}
                node["transport"] = trans
        return node
    except (ValueError, UnicodeError):
        return None


def wait_for_port(process: subprocess.Popen, port: int, seconds: float = 2.5) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if process.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.06)
    return False


def probe(uri: str, sing_box: str, timeout: float) -> dict:
    outbound = convert_uri(uri)
    if outbound is None:
        return {"success": False, "reason": "unsupported"}
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    config = {
        "log": {"level": "error"},
        "inbounds": [{"type": "mixed", "tag": "probe-in",
                      "listen": "127.0.0.1", "listen_port": port}],
        "outbounds": [outbound],
        "route": {"final": "checked-node"},
    }
    with tempfile.TemporaryDirectory(prefix="happ-probe-") as tmp:
        conf = Path(tmp) / "test.json"
        conf.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")
        proc = None
        try:
            proc = subprocess.Popen(
                [sing_box, "run", "-c", str(conf)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            if not wait_for_port(proc, port):
                return {"success": False, "reason": "startup_error"}
            proxy_url = f"http://127.0.0.1:{port}"
            opener = build_opener(
                ProxyHandler({"http": proxy_url, "https": proxy_url}),
                HTTPSHandler(context=ssl.create_default_context()),
            )
            began = time.monotonic()
            # Request goes through the configured VPN outbound, not direct.
            for target, expected in TEST_URLS:
                try:
                    request = Request(target, headers={"User-Agent": "HappPoolHealthcheck/1.0"})
                    with opener.open(request, timeout=timeout) as response:
                        if response.status == expected:
                            return {"success": True, "latency_ms": round(
                                (time.monotonic() - began) * 1000),
                                "url": target}
                except Exception:
                    pass
            return {"success": False, "reason": "proxy_http_failed"}
        finally:
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="candidates.txt")
    parser.add_argument("--output", default="happ-all.txt")
    parser.add_argument("--binary", default="./sing-box")
    parser.add_argument("--workers", type=int, default=12)
    parser.add_argument("--timeout", type=float, default=7)
    parser.add_argument("--limit", type=int, default=100)
    args = parser.parse_args()
    if not 1 <= args.workers <= 32 or not 2 <= args.timeout <= 20:
        parser.error("invalid workers or timeout")
    lines = [s.strip() for s in Path(args.input).read_text(encoding="utf-8").splitlines()
             if s.startswith(("vless://", "trojan://", "hy2://", "hysteria2://"))]
    results = []
    reasons = Counter()
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(probe, line, args.binary, args.timeout): line for line in lines}
        for i, future in enumerate(as_completed(futures), 1):
            line = futures[future]
            try:
                result = future.result()
            except Exception:
                result = {"success": False, "reason": "probe_exception"}
            if result["success"]:
                results.append((result["latency_ms"], line))
            else:
                reasons[result.get("reason", "unknown")] += 1
            if i % 40 == 0 or i == len(lines):
                print(f"Probed {i}/{len(lines)}: {len(results)} working, reasons={dict(reasons)}", flush=True)

    # Do not fabricate 100 "healthy" nodes: publish however many actually passed.
    results.sort(key=lambda entry: entry[0])
    results = results[:args.limit]
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines_out = [
        f"#profile-title: Happ TESTED ({len(results)})",
        "#profile-update-interval: 6",
        f"# Verified via HTTPS from a GitHub Actions runner at {timestamp}",
        "# IMPORTANT: working from GitHub does NOT guarantee working from Russia",
    ]
    lines_out.extend(
        line.split("#", 1)[0] + f"#OK-{i:03d}-{latency}ms"
        for i, (latency, line) in enumerate(results, 1)
    )
    output = Path(args.output)
    output.write_text("\n".join(lines_out) + "\n", encoding="utf-8")
    status_path = Path("status.json")
    status = json.loads(status_path.read_text(encoding="utf-8")) if status_path.exists() else {}
    status["proxy_probe"] = {
        "checked_at_utc": timestamp, "tested": len(lines),
        "passed": len(results), "failed": len(lines) - len(results),
        "failures_by_reason": dict(reasons),
        "median_pass_latency_ms": round(statistics.median(p[0] for p in results)) if results else None,
        "network": "GitHub Actions hosted runner, NOT the user's home/mobile network",
        "description": "HTTPS requests sent through a sing-box local HTTP proxy using each remote node",
    }
    status["nodes"] = len(results)
    status_path.write_text(json.dumps(status, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Published {len(results)} nodes with verified HTTPS from runner.")
    if not results:
        print("WARNING: no proxy passed; the published subscription intentionally has no nodes.")


if __name__ == "__main__":
    main()
