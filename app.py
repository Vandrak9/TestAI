#!/usr/bin/env python3
"""
Web rozhranie pre Port Scanner s AI analýzou
Spustenie: python app.py
"""

import ipaddress
import json
import re
import socket
import ssl
import hashlib
import hmac
import os
import secrets
import sqlite3
import subprocess
import threading
import time
import urllib.request
import dns.resolver
import dns.reversename
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask, render_template, request, Response,
    stream_with_context, session, redirect, url_for, flash, jsonify,
)
import anthropic

from port_scanner import PREDEFINED_PROFILES, scan_port

# ── UDP sken ───────────────────────────────────────────────────────────────────
_UDP_SERVICES = {
    53: 'DNS', 67: 'DHCP', 69: 'TFTP', 111: 'RPC', 123: 'NTP',
    137: 'NetBIOS-NS', 138: 'NetBIOS-DGM', 161: 'SNMP', 162: 'SNMP-Trap',
    500: 'IKE', 514: 'Syslog', 520: 'RIP', 623: 'IPMI', 1194: 'OpenVPN',
    1900: 'UPnP/SSDP', 4500: 'IPsec-NAT', 5353: 'mDNS', 5060: 'SIP',
}
_UDP_PROBES = {
    53:   b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03',
    123:  b'\x1b' + b'\x00' * 47,
    161:  b'\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x00\x05\x00',
    1900: b'M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:"ssdp:discover"\r\nMX:2\r\nST:ssdp:all\r\n\r\n',
    5353: b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05_http\x04_tcp\x05local\x00\x00\x0c\x00\x01',
}
_UDP_DEFAULT_PORTS = sorted(_UDP_SERVICES.keys())

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# ── História skenov (SQLite) ───────────────────────────────────────────────────

DB_PATH = os.path.join(os.path.dirname(__file__), "history.db")


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT NOT NULL,
                host        TEXT NOT NULL,
                ip          TEXT NOT NULL,
                port_label  TEXT,
                open_count  INTEGER,
                open_ports  TEXT,
                ai_analysis TEXT,
                os_hint     TEXT,
                device_type TEXT
            )
        """)
        # Migration: add columns if missing (existing DB)
        existing = {row[1] for row in conn.execute("PRAGMA table_info(scans)")}
        if "os_hint" not in existing:
            conn.execute("ALTER TABLE scans ADD COLUMN os_hint TEXT")
        if "device_type" not in existing:
            conn.execute("ALTER TABLE scans ADD COLUMN device_type TEXT")
        if "http_security" not in existing:
            conn.execute("ALTER TABLE scans ADD COLUMN http_security TEXT")
        if "total_scanned" not in existing:
            conn.execute("ALTER TABLE scans ADD COLUMN total_scanned INTEGER")
        if "geo_whois" not in existing:
            conn.execute("ALTER TABLE scans ADD COLUMN geo_whois TEXT")
        if "udp_ports" not in existing:
            conn.execute("ALTER TABLE scans ADD COLUMN udp_ports TEXT")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS schedules (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                host           TEXT NOT NULL,
                port_label     TEXT NOT NULL DEFAULT 'top100',
                threads        INTEGER DEFAULT 100,
                interval_hours INTEGER NOT NULL DEFAULT 24,
                last_run       TEXT,
                next_run       TEXT NOT NULL,
                last_status    TEXT,
                enabled        INTEGER DEFAULT 1
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role          TEXT NOT NULL DEFAULT 'user',
                active        INTEGER NOT NULL DEFAULT 1,
                created_at    TEXT NOT NULL
            )
        """)
        # Migrácia: ak je tabuľka prázdna, vytvor admina z env premenných
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count == 0:
            admin_user = os.environ.get("APP_USERNAME", "admin")
            env_hash = os.environ.get("APP_PASSWORD_HASH")
            if env_hash:
                admin_hash = env_hash
            else:
                admin_hash = hashlib.sha256(
                    os.environ.get("APP_PASSWORD", "admin").encode()
                ).hexdigest()
            conn.execute(
                "INSERT INTO users (username, password_hash, role, active, created_at) VALUES (?, ?, 'admin', 1, ?)",
                (admin_user, admin_hash, datetime.now().isoformat()),
            )


def _get_ttl(ip: str):
    """Ping a vráti TTL hodnotu (alebo None)."""
    try:
        res = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            capture_output=True, text=True, timeout=3,
        )
        for line in res.stdout.splitlines():
            low = line.lower()
            if "ttl=" in low:
                ttl_str = low.split("ttl=")[1].split()[0].rstrip(")")
                return int(ttl_str)
    except Exception:
        pass
    return None


def detect_os_hint(ip: str, open_ports: list) -> dict:
    """Odhadne OS a typ zariadenia bez externých nástrojov."""
    port_nums = {p["port"] for p in open_ports}
    os_hint = None
    confidence = "low"
    device_type = None

    # 1. TTL
    ttl = _get_ttl(ip)
    if ttl:
        if ttl <= 64:
            os_hint = "Linux / Unix / macOS"
        elif ttl <= 128:
            os_hint = "Windows"
        elif ttl <= 255:
            os_hint = "Cisco / Sieťový prvok"

    # 2. Banner analysis (overrides TTL if specific match found)
    _os_keywords = [
        ("ubuntu",   "Linux (Ubuntu)",     "high"),
        ("debian",   "Linux (Debian)",     "high"),
        ("centos",   "Linux (CentOS)",     "high"),
        ("red hat",  "Linux (RHEL)",       "high"),
        ("fedora",   "Linux (Fedora)",     "high"),
        ("alpine",   "Linux (Alpine)",     "high"),
        ("freebsd",  "FreeBSD",            "high"),
        ("openbsd",  "OpenBSD",            "high"),
        ("windows",  "Windows",            "high"),
        ("microsoft","Windows",            "high"),
        ("iis",      "Windows (IIS)",      "high"),
        ("synology", "Synology NAS",       "high"),
        ("qnap",     "QNAP NAS",           "high"),
        ("mikrotik", "MikroTik RouterOS",  "high"),
        ("cisco",    "Cisco IOS",          "high"),
        ("junos",    "Juniper JunOS",      "high"),
        ("openssh",  "Linux / Unix",       "medium"),
        ("apache",   "Linux / Unix",       "low"),
        ("nginx",    "Linux / Unix",       "low"),
    ]
    for p in open_ports:
        banner = (p.get("banner") or "").lower()
        if not banner:
            continue
        for keyword, name, conf in _os_keywords:
            if keyword in banner:
                if conf == "high" or (conf == "medium" and confidence == "low") or os_hint is None:
                    os_hint = name
                    confidence = conf
                if confidence == "high":
                    break
        if confidence == "high":
            break

    # 3. Port-based device type heuristics
    if 9100 in port_nums or (515 in port_nums and 631 in port_nums):
        device_type = "Tlačiareň"
    elif 5060 in port_nums or 5061 in port_nums or 2000 in port_nums:
        device_type = "VoIP / PBX"
    elif 554 in port_nums and 80 in port_nums:
        device_type = "IP Kamera"
    elif 554 in port_nums:
        device_type = "IP Kamera / Media Server"
    elif 102 in port_nums or 502 in port_nums or 44818 in port_nums:
        device_type = "Priemyselné zariadenie (SCADA/PLC)"
    elif 3389 in port_nums:
        device_type = "Windows Server / Desktop"
        if os_hint is None or confidence == "low":
            os_hint = "Windows"
            confidence = "medium"
    elif 5988 in port_nums or 5989 in port_nums:
        device_type = "Server (WBEM/IPMI)"
    elif 23 in port_nums and 161 in port_nums:
        device_type = "Sieťový prvok (Router/Switch)"
        if os_hint is None or confidence == "low":
            os_hint = "Cisco / Sieťový prvok"
    elif 23 in port_nums:
        device_type = "Starý server / Sieťový prvok"

    if not device_type:
        has_db  = bool(port_nums & {3306, 5432, 1433, 1521, 27017, 6379, 9200, 50000})
        has_web = bool(port_nums & {80, 443, 8080, 8443})
        has_k8s = bool(port_nums & {6443, 2376, 2379})
        if has_k8s:
            device_type = "Kubernetes / Docker Host"
        elif has_db and has_web:
            device_type = "Web + Databázový Server"
        elif has_db:
            device_type = "Databázový Server"
        elif has_web:
            device_type = "Web Server"
        elif port_nums:
            device_type = "Server / Zariadenie"

    return {
        "os_hint":     os_hint or "Neznámy",
        "device_type": device_type or "Neznáme",
        "confidence":  confidence,
        "ttl":         ttl,
    }


def detect_tarpit(open_ports: list, total_scanned: int) -> dict:
    """
    Detekuje TCP tarpit obranu (napr. MikroTik action=tarpit).
    Tarpit odpovedá SYN-ACK na všetky porty → port vyzerá otvorený,
    ale nikdy nepošle žiadne dáta (žiadny banner).
    """
    result = {"detected": False, "confidence": "none", "open_ratio": 0.0,
              "banner_ratio": 0.0, "note": None}

    if total_scanned < 15 or not open_ports:
        return result

    open_count = len(open_ports)
    open_ratio = open_count / total_scanned
    with_banner = sum(1 for p in open_ports if (p.get("banner") or "").strip())
    banner_ratio = with_banner / open_count if open_count else 0.0

    result["open_ratio"] = round(open_ratio * 100, 1)
    result["banner_ratio"] = round(banner_ratio * 100, 1)

    # Tarpit signál: >30% portov "otvorených" + <5% má banner
    if open_ratio >= 0.60 and banner_ratio < 0.05:
        result["detected"] = True
        result["confidence"] = "high"
        result["note"] = (
            f"Pravdepodobný TCP tarpit — {open_count}/{total_scanned} portov "
            f"sa tvári ako otvorených ({result['open_ratio']}%), "
            f"ale len {with_banner} má banner. "
            "Výsledky nemusia odrážať skutočný stav portov."
        )
    elif open_ratio >= 0.30 and banner_ratio < 0.05 and open_count >= 20:
        result["detected"] = True
        result["confidence"] = "medium"
        result["note"] = (
            f"Možný TCP tarpit — {open_count}/{total_scanned} portov "
            f"otvorených bez bannera. Odporúčame overiť manuálne."
        )
    elif open_ratio >= 0.20 and banner_ratio == 0.0 and open_count >= 15:
        result["detected"] = False
        result["confidence"] = "low"
        result["note"] = (
            f"Podozrivé: {open_count} portov otvorených, žiadny banner. "
            "Môže byť firewall filtrujúci odpovede."
        )

    return result


def scan_udp(ip: str, ports: list, timeout: float = 2.0) -> list:
    """Skenuje UDP porty; detekuje ICMP port unreachable (vyžaduje root)."""
    results = []
    try:
        icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        icmp_sock.settimeout(0.5)
    except Exception:
        icmp_sock = None
    try:
        for port in ports:
            service = _UDP_SERVICES.get(port, 'unknown')
            probe = _UDP_PROBES.get(port, b'\x00')
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.settimeout(timeout)
            try:
                udp_sock.sendto(probe, (ip, port))
                try:
                    data, _ = udp_sock.recvfrom(1024)
                    banner = data[:64].decode('utf-8', errors='replace').strip()
                    results.append({'port': port, 'state': 'open', 'service': service, 'banner': banner})
                    continue
                except socket.timeout:
                    pass
                # Skontroluj ICMP port unreachable
                if icmp_sock:
                    closed = False
                    try:
                        while True:
                            raw, addr = icmp_sock.recvfrom(1024)
                            if addr[0] == ip and len(raw) >= 52:
                                # raw[20]=type, raw[21]=code; orig UDP dst port = raw[50:52]
                                if raw[20] == 3 and raw[21] == 3:
                                    orig_port = (raw[50] << 8) | raw[51]
                                    if orig_port == port:
                                        closed = True
                                        break
                    except socket.timeout:
                        pass
                    if closed:
                        results.append({'port': port, 'state': 'closed', 'service': service})
                        continue
                results.append({'port': port, 'state': 'open|filtered', 'service': service})
            except Exception as e:
                results.append({'port': port, 'state': 'error', 'service': service, 'error': str(e)[:60]})
            finally:
                udp_sock.close()
    finally:
        if icmp_sock:
            icmp_sock.close()
    return results


def geoip_lookup(ip: str) -> dict:
    """Geolokácia IP adresy cez ip-api.com (bezplatné, 45 req/min)."""
    try:
        url = f'http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,isp,org,as,query'
        req = urllib.request.Request(url, headers={'User-Agent': 'PortScanner/1.0'})
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read())
        if data.get('status') == 'success':
            return data
        return {'error': data.get('message', 'geolokácia zlyhala')}
    except Exception as e:
        return {'error': str(e)[:80]}


def whois_lookup(target: str) -> dict:
    """Whois lookup pre IP alebo doménu."""
    try:
        result = subprocess.run(
            ['whois', target],
            capture_output=True, text=True, timeout=12,
            env={**os.environ, 'LANG': 'C'},
        )
        raw = result.stdout[:3000]
        parsed = {}
        _keys = {
            'netname': 'Sieť', 'org-name': 'Organizácia', 'orgname': 'Organizácia',
            'country': 'Krajina', 'descr': 'Popis', 'created': 'Vytvorené',
            'last-modified': 'Upravené', 'registrant': 'Registrant',
            'registrar': 'Registrar', 'creation date': 'Vytvorené',
            'updated date': 'Upravené', 'name server': 'Nameserver',
            'mnt-by': 'Spravuje', 'abuse-mailbox': 'Abuse',
        }
        seen: set = set()
        for line in raw.splitlines():
            if ':' not in line or line.startswith('%') or line.startswith('#'):
                continue
            key, _, val = line.partition(':')
            k = key.strip().lower()
            v = val.strip()
            if v and k in _keys and k not in seen:
                seen.add(k)
                parsed[_keys[k]] = v
        return {'parsed': parsed, 'raw': raw}
    except FileNotFoundError:
        return {'error': 'whois nie je nainštalovaný'}
    except Exception as e:
        return {'error': str(e)[:80]}


_WEAK_CIPHERS = {"RC4", "DES", "3DES", "EXPORT", "NULL", "anon", "MD5", "IDEA", "SEED"}
_SEC_HEADERS = {
    "strict-transport-security": ("HSTS", "critical",
        "Chýba HSTS — prehliadač sa môže pripojiť cez nešifrované HTTP"),
    "x-frame-options": ("X-Frame-Options", "medium",
        "Chýba ochrana proti clickjackingu"),
    "x-content-type-options": ("X-Content-Type-Options", "low",
        "Chýba ochrana proti MIME sniffingu"),
    "content-security-policy": ("CSP", "medium",
        "Chýba Content Security Policy — riziko XSS"),
    "referrer-policy": ("Referrer-Policy", "low",
        "Chýba Referrer-Policy"),
    "permissions-policy": ("Permissions-Policy", "low",
        "Chýba Permissions-Policy"),
}
_TLS_METHODS = [
    ("TLS 1.3", ssl.TLSVersion.TLSv1_3),
    ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
]
# TLS 1.0/1.1 — Python/OpenSSL môže mať zakázané, skúšame opatrne
try:
    _TLS_METHODS += [
        ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
        ("TLS 1.0", ssl.TLSVersion.TLSv1),
    ]
except AttributeError:
    pass


def _tls_connect(host: str, port: int, max_ver, min_ver=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.maximum_version = max_ver
        if min_ver:
            ctx.minimum_version = min_ver
    except Exception:
        return None
    try:
        with socket.create_connection((host, port), timeout=4) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                return {
                    "version": s.version(),
                    "cipher": s.cipher(),
                    "cert": s.getpeercert(binary_form=False),
                }
    except Exception:
        return None


def check_http_security(host: str, port: int) -> dict:
    """Skontroluje HTTP/HTTPS bezpečnosť daného portu."""
    if port in {443, 8443, 9443}:
        use_tls = True
    elif port in {80, 8080, 8000, 3000, 8888, 9090}:
        use_tls = False
    else:
        # Auto-detekcia: skús TLS pripojenie
        test = _tls_connect(host, port, ssl.TLSVersion.TLSv1_2)
        use_tls = test is not None
    findings = []   # [{severity, title, detail}]
    tls_info = {}
    cert_info = {}
    resp_headers = {}

    # ── TLS checks ──────────────────────────────────────────────────────────
    if use_tls:
        supported_versions = []
        best_conn = None

        for label, ver in _TLS_METHODS:
            conn = _tls_connect(host, port, ver, ver)
            if conn:
                supported_versions.append(label)
                if best_conn is None:
                    best_conn = conn
                    best_conn["version_label"] = label

        if not best_conn:
            # Skús bez obmedzenia verzie
            best_conn = _tls_connect(host, port,
                                     ssl.TLSVersion.TLSv1_2)

        if best_conn:
            cipher_name, proto, bits = best_conn["cipher"]
            tls_info = {
                "negotiated": best_conn.get("version_label", best_conn["version"]),
                "cipher": cipher_name,
                "bits": bits,
                "supported_versions": supported_versions,
            }

            # Weak cipher
            if any(w in cipher_name for w in _WEAK_CIPHERS):
                findings.append({"severity": "critical", "title": "Slabá šifra",
                    "detail": f"Cipher suite {cipher_name} je považovaná za nebezpečnú"})

            # Old TLS
            if "TLS 1.0" in supported_versions:
                findings.append({"severity": "high", "title": "Podporovaný TLS 1.0",
                    "detail": "TLS 1.0 je zastaralý (RFC 8996) — zraniteľný voči BEAST, POODLE"})
            if "TLS 1.1" in supported_versions:
                findings.append({"severity": "medium", "title": "Podporovaný TLS 1.1",
                    "detail": "TLS 1.1 je zastaralý a odporúča sa zakázať"})
            if "TLS 1.3" in supported_versions:
                findings.append({"severity": "ok", "title": "TLS 1.3 podporovaný",
                    "detail": "Najnovší a najbezpečnejší TLS protokol"})

            # Cert checks
            raw_cert = best_conn.get("cert")
            if not raw_cert:
                # Získame cert priamo
                try:
                    ctx2 = ssl.create_default_context()
                    ctx2.check_hostname = False
                    ctx2.verify_mode = ssl.CERT_NONE
                    with socket.create_connection((host, port), timeout=4) as raw:
                        with ctx2.wrap_socket(raw, server_hostname=host) as s:
                            raw_cert = s.getpeercert()
                except Exception:
                    pass

            if raw_cert:
                # Expirácia
                not_after_str = raw_cert.get("notAfter", "")
                try:
                    not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                    days_left = (not_after - datetime.utcnow()).days
                    cert_info["expires"] = not_after.strftime("%Y-%m-%d")
                    cert_info["days_left"] = days_left
                    if days_left < 0:
                        findings.append({"severity": "critical", "title": "Certifikát expiroval",
                            "detail": f"Certifikát expiroval pred {-days_left} dňami"})
                    elif days_left < 14:
                        findings.append({"severity": "high", "title": "Certifikát expiruje čoskoro",
                            "detail": f"Zostáva {days_left} dní do expirácie"})
                    elif days_left < 30:
                        findings.append({"severity": "medium", "title": "Certifikát expiruje o menej ako 30 dní",
                            "detail": f"Zostáva {days_left} dní"})
                    else:
                        findings.append({"severity": "ok", "title": "Certifikát platný",
                            "detail": f"Platí do {cert_info['expires']} ({days_left} dní)"})
                except Exception:
                    pass

                # Self-signed
                subject = dict(x[0] for x in raw_cert.get("subject", []))
                issuer  = dict(x[0] for x in raw_cert.get("issuer", []))
                cert_info["subject"] = subject.get("commonName", "")
                cert_info["issuer"]  = issuer.get("organizationName", issuer.get("commonName", ""))
                if subject == issuer:
                    findings.append({"severity": "medium", "title": "Self-signed certifikát",
                        "detail": "Certifikát nie je podpísaný dôveryhodnou autoritou (CA)"})

                # SAN
                sans = [v for t, v in raw_cert.get("subjectAltName", []) if t == "DNS"]
                cert_info["sans"] = sans[:10]
        else:
            findings.append({"severity": "critical", "title": "TLS spojenie zlyhalo",
                "detail": "Nepodarilo sa nadviazať šifrované spojenie"})

    # ── HTTP headers ─────────────────────────────────────────────────────────
    try:
        scheme = "https" if use_tls else "http"
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/",
            headers={"User-Agent": "Mozilla/5.0 PortScanner/1.0"},
            method="GET",
        )
        ctx_h = ssl.create_default_context() if use_tls else None
        if ctx_h:
            ctx_h.check_hostname = False
            ctx_h.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=5, context=ctx_h) as r:
            for k, v in r.headers.items():
                resp_headers[k.lower()] = v

        # Server header — version disclosure
        srv = resp_headers.get("server", "")
        if srv:
            import re
            if re.search(r"[\d.]{3,}", srv):
                findings.append({"severity": "low", "title": "Server verzia v hlavičke",
                    "detail": f"Server: {srv} — prezrádza verziu softvéru"})

        # Security headers
        for hdr, (name, sev, msg) in _SEC_HEADERS.items():
            if hdr in resp_headers:
                val = resp_headers[hdr]
                # HSTS — skontroluj max-age
                if hdr == "strict-transport-security":
                    try:
                        ma = int(next(p.split("=")[1] for p in val.split(";")
                                      if "max-age" in p.lower()))
                        if ma < 15768000:  # < 6 mesiacov
                            findings.append({"severity": "medium",
                                "title": "HSTS max-age je krátky",
                                "detail": f"max-age={ma}s — odporúča sa min. 15768000 (6 mesiacov)"})
                        else:
                            findings.append({"severity": "ok", "title": "HSTS nastavený správne",
                                "detail": f"max-age={ma}s"})
                    except Exception:
                        findings.append({"severity": "ok", "title": "HSTS prítomný", "detail": val})
            else:
                if hdr == "strict-transport-security" and not use_tls:
                    continue  # HSTS nemá zmysel na HTTP
                findings.append({"severity": sev, "title": f"Chýba {name}", "detail": msg})

        # HTTP na HTTPS redirect
        if not use_tls:
            location = resp_headers.get("location", "")
            if location.startswith("https://"):
                findings.append({"severity": "ok", "title": "HTTP → HTTPS redirect",
                    "detail": f"Presmerováva na {location}"})
            else:
                findings.append({"severity": "medium", "title": "Chýba HTTP → HTTPS redirect",
                    "detail": "Server nepresmeroava na HTTPS"})

    except Exception as e:
        findings.append({"severity": "info", "title": "HTTP požiadavka zlyhala",
            "detail": str(e)[:120]})

    # Severity order for sorting
    _order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "ok": 5}
    findings.sort(key=lambda f: _order.get(f["severity"], 9))

    return {
        "port": port,
        "tls": tls_info,
        "cert": cert_info,
        "server": resp_headers.get("server", ""),
        "findings": findings,
    }


def save_scan(host: str, ip: str, port_label: str, open_ports: list,
              ai_text: str = None, os_hint: str = None, device_type: str = None,
              total_scanned: int = None) -> int:
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            "INSERT INTO scans (timestamp, host, ip, port_label, open_count, open_ports, ai_analysis, os_hint, device_type, total_scanned) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), host, ip,
             port_label, len(open_ports), json.dumps(open_ports), ai_text,
             os_hint, device_type, total_scanned),
        )
        return cur.lastrowid


def parse_host_range(host_str: str) -> list:
    """Vráti zoznam IP adries pre jednú IP, CIDR alebo rozsah."""
    host_str = host_str.strip()
    try:
        if '/' in host_str:
            net = ipaddress.ip_network(host_str, strict=False)
            return [str(h) for h in list(net.hosts())[:254]]
        if '-' in host_str:
            parts = host_str.rsplit('-', 1)
            base, end_part = parts[0].strip(), parts[1].strip()
            try:
                start_ip = ipaddress.ip_address(base)
                end_ip = ipaddress.ip_address(end_part)
            except ValueError:
                prefix = '.'.join(base.split('.')[:-1])
                start_ip = ipaddress.ip_address(base)
                end_ip = ipaddress.ip_address(f"{prefix}.{end_part}")
            result, cur, end_int = [], int(start_ip), int(end_ip)
            while cur <= end_int and len(result) < 254:
                result.append(str(ipaddress.ip_address(cur)))
                cur += 1
            return result
    except Exception:
        pass
    return [host_str]


def run_scan_sync(host: str, port_label: str, threads: int = 100, timeout: float = 1.0):
    """Synchronný sken — uloží výsledok do DB a vráti scan_id."""
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return None
    ports = PREDEFINED_PROFILES.get(port_label, PREDEFINED_PROFILES["top100"])
    otvorene = []
    with ThreadPoolExecutor(max_workers=min(threads, 200)) as executor:
        futures = {executor.submit(scan_port, ip, p, timeout): p for p in ports}
        for future in as_completed(futures):
            res = future.result()
            if res["stav"] == "otvorený":
                otvorene.append(res)
    otvorene = sorted(otvorene, key=lambda x: x["port"])
    os_info = detect_os_hint(ip, otvorene)
    return save_scan(host, ip, port_label, otvorene,
                     os_hint=os_info["os_hint"], device_type=os_info["device_type"],
                     total_scanned=len(ports))


def _scheduler_loop():
    """Beží na pozadí, spúšťa naplánované skeny."""
    while True:
        try:
            time.sleep(60)
            now = datetime.utcnow()
            now_str = now.strftime("%Y-%m-%d %H:%M:%S")
            with sqlite3.connect(DB_PATH) as conn:
                conn.row_factory = sqlite3.Row
                due = conn.execute(
                    "SELECT * FROM schedules WHERE enabled=1 AND next_run <= ?",
                    (now_str,)
                ).fetchall()
            for sched in due:
                try:
                    scan_id = run_scan_sync(sched["host"], sched["port_label"], sched["threads"])
                    next_run = (now + timedelta(hours=sched["interval_hours"])).strftime("%Y-%m-%d %H:%M:%S")
                    status = f"OK (sken #{scan_id})" if scan_id else "CHYBA: host nedostupný"
                except Exception as e:
                    next_run = (now + timedelta(hours=sched["interval_hours"])).strftime("%Y-%m-%d %H:%M:%S")
                    status = f"CHYBA: {str(e)[:80]}"
                with sqlite3.connect(DB_PATH) as conn:
                    conn.execute(
                        "UPDATE schedules SET last_run=?, next_run=?, last_status=? WHERE id=?",
                        (now_str, next_run, status, sched["id"])
                    )
        except Exception as e:
            print(f"[scheduler] chyba: {e}")


init_db()
threading.Thread(target=_scheduler_loop, daemon=True).start()

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def get_user(username: str):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute(
            "SELECT * FROM users WHERE username = ? AND active = 1", (username,)
        ).fetchone()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.path))
        if session.get("role") != "admin":
            flash("Nemáte oprávnenie na túto stránku.", "error")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated


# ── Auth routes ────────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("logged_in"):
        return redirect(url_for("index"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = get_user(username)
        if user and user["password_hash"] == hash_password(password):
            session.permanent = True
            session["logged_in"] = True
            session["username"] = user["username"]
            session["role"] = user["role"]
            next_url = request.args.get("next", url_for("index"))
            return redirect(next_url)
        else:
            error = "Nesprávne meno alebo heslo."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ── Admin: správa používateľov ─────────────────────────────────────────────────

@app.route("/admin/users")
@admin_required
def admin_users():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        users = conn.execute(
            "SELECT id, username, role, active, created_at FROM users ORDER BY id"
        ).fetchall()
    return render_template("users.html", users=users, current_user=session.get("username"))


@app.route("/admin/users/add", methods=["POST"])
@admin_required
def admin_users_add():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "user")
    if not username or not password:
        flash("Meno a heslo sú povinné.", "error")
        return redirect(url_for("admin_users"))
    if role not in ("admin", "user"):
        role = "user"
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, active, created_at) VALUES (?, ?, ?, 1, ?)",
                (username, hash_password(password), role, datetime.now().isoformat()),
            )
        flash(f"Používateľ '{username}' bol vytvorený.", "ok")
    except sqlite3.IntegrityError:
        flash(f"Používateľ '{username}' už existuje.", "error")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:uid>/delete", methods=["POST"])
@admin_required
def admin_users_delete(uid):
    if uid == 1:
        flash("Prvého admina nemožno zmazať.", "error")
        return redirect(url_for("admin_users"))
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("SELECT username FROM users WHERE id = ?", (uid,)).fetchone()
        if row:
            conn.execute("DELETE FROM users WHERE id = ?", (uid,))
            flash(f"Používateľ '{row[0]}' bol zmazaný.", "ok")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:uid>/toggle", methods=["POST"])
@admin_required
def admin_users_toggle(uid):
    if uid == 1:
        flash("Prvého admina nemožno deaktivovať.", "error")
        return redirect(url_for("admin_users"))
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("UPDATE users SET active = 1 - active WHERE id = ?", (uid,))
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:uid>/password", methods=["POST"])
@admin_required
def admin_users_password(uid):
    password = request.form.get("password", "")
    if not password:
        flash("Heslo nesmie byť prázdne.", "error")
        return redirect(url_for("admin_users"))
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(password), uid))
    flash("Heslo bolo zmenené.", "ok")
    return redirect(url_for("admin_users"))


@app.route("/profile/password", methods=["POST"])
@login_required
def profile_change_password():
    current = request.form.get("current_password", "")
    new_pw = request.form.get("new_password", "")
    if not new_pw:
        flash("Nové heslo nesmie byť prázdne.", "error")
        return redirect(url_for("index"))
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?", (session["username"],)
        ).fetchone()
    if not row or row[0] != hash_password(current):
        flash("Aktuálne heslo je nesprávne.", "error")
        return redirect(url_for("index"))
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (hash_password(new_pw), session["username"]),
        )
    flash("Heslo bolo úspešne zmenené.", "ok")
    return redirect(url_for("index"))


@app.route("/api/myip")
@login_required
def my_ip():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    ip = ip.split(",")[0].strip()
    return jsonify({"ip": ip})


_scanner_ip_cache: dict = {}

def _fetch_scanner_ip() -> str:
    """Zistí verejnú IP adresu servera (skenera). Výsledok sa cachuje."""
    if "ip" in _scanner_ip_cache:
        return _scanner_ip_cache["ip"]
    import urllib.request
    services = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ]
    for url in services:
        try:
            with urllib.request.urlopen(url, timeout=4) as r:
                ip = r.read().decode().strip()
                if ip:
                    _scanner_ip_cache["ip"] = ip
                    return ip
        except Exception:
            continue
    return "neznáma"


@app.route("/api/scannerip")
@login_required
def scanner_ip():
    return jsonify({"ip": _fetch_scanner_ip()})


@app.route("/api/history")
@login_required
def history():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, timestamp, host, ip, port_label, open_count, total_scanned, open_ports, ai_analysis, os_hint, device_type, http_security, geo_whois, udp_ports "
            "FROM scans ORDER BY id DESC LIMIT 100"
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/history/<int:scan_id>", methods=["DELETE"])
@login_required
def delete_scan(scan_id):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    return jsonify({"ok": True})


# ── Scanner routes ─────────────────────────────────────────────────────────────

def stream_scan(host: str, ports: list, threads: int = 100, timeout: float = 1.0, port_label: str = ""):
    """Generátor — posiela udalosti SSE klientovi v reálnom čase."""

    def send(event: str, data: dict) -> str:
        return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        yield send("error", {"message": f"Nemožno preložiť hostname: {host}"})
        return

    yield send("status", {"message": f"Skenujem {host} ({ip}) — {len(ports)} portov..."})

    otvorene = []
    celkom = len(ports)
    hotovo = 0

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, ip, p, timeout): p for p in ports}
        for future in as_completed(futures):
            hotovo += 1
            vysledok = future.result()

            if vysledok["stav"] == "otvorený":
                otvorene.append(vysledok)
                yield send("port", vysledok)

            if hotovo % 50 == 0 or hotovo == celkom:
                yield send("progress", {"done": hotovo, "total": celkom})

    otvorene = sorted(otvorene, key=lambda x: x["port"])
    tarpit = detect_tarpit(otvorene, celkom)
    os_info = detect_os_hint(ip, otvorene) if not tarpit["detected"] else \
              {"os_hint": "Neznámy (TCP tarpit)", "device_type": "Neznáme (TCP tarpit)",
               "confidence": "none", "ttl": _get_ttl(ip)}

    scan_id = save_scan(host, ip, port_label, otvorene,
                        os_hint=os_info["os_hint"], device_type=os_info["device_type"],
                        total_scanned=celkom)

    yield send("scan_done", {
        "open_count": len(otvorene),
        "total": celkom,
        "host": host,
        "ip": ip,
        "scan_id": scan_id,
        "os_hint": os_info["os_hint"],
        "device_type": os_info["device_type"],
        "os_confidence": os_info["confidence"],
        "ttl": os_info["ttl"],
        "tarpit": tarpit,
    })

    # Auto HTTP/HTTPS security check — bez extra kliknutia, nespotrebuje API kredity
    _web_ports = {80, 443, 8080, 8443, 3000, 8888, 9090, 9443}
    found_web = [p["port"] for p in otvorene if p["port"] in _web_ports]
    if found_web and not tarpit["detected"]:
        http_results = []
        for port in found_web[:3]:
            try:
                http_results.append(check_http_security(ip, port))
            except Exception as e:
                http_results.append({"port": port, "error": str(e)[:80], "findings": []})
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("UPDATE scans SET http_security=? WHERE id=?",
                         (json.dumps(http_results, ensure_ascii=False), scan_id))
        yield send("http_security", {"results": http_results, "scan_id": scan_id})

    # Auto geo + whois
    try:
        geo = geoip_lookup(ip)
        whois_data = whois_lookup(host)
        geo_whois_json = json.dumps({'geo': geo, 'whois': whois_data}, ensure_ascii=False)
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("UPDATE scans SET geo_whois=? WHERE id=?", (geo_whois_json, scan_id))
        yield send("geo_whois", {"geo": geo, "whois": whois_data})
    except Exception:
        pass

    yield send("done", {})


@app.route("/")
@login_required
def index():
    profily = list(PREDEFINED_PROFILES.keys())
    return render_template("index.html", profily=profily, username=session.get("username"))


@app.route("/scan")
@login_required
def scan():
    host = request.args.get("host", "").strip()
    port_arg = request.args.get("ports", "top100").strip()
    threads = min(int(request.args.get("threads", 100)), 500)
    timeout = float(request.args.get("timeout", 1.0))

    if not host:
        return Response("Chyba: host je povinný", status=400)

    if port_arg in PREDEFINED_PROFILES:
        ports = PREDEFINED_PROFILES[port_arg]
    else:
        ports = set()
        for cast in port_arg.split(","):
            cast = cast.strip()
            if "-" in cast:
                start, end = cast.split("-", 1)
                ports.update(range(int(start), int(end) + 1))
            else:
                ports.add(int(cast))
        ports = sorted(ports)

    return Response(
        stream_with_context(stream_scan(host, ports, threads, timeout, port_arg)),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/http-check/<int:scan_id>")
@login_required
def http_check(scan_id):
    """Spustí HTTP/HTTPS bezpečnostný check pre porty nájdené v skene."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT host, ip, open_ports FROM scans WHERE id=?", (scan_id,)
        ).fetchone()
    if not row:
        return jsonify({"error": "Sken nenájdený"}), 404

    open_ports = json.loads(row["open_ports"] or "[]")
    host = row["ip"] or row["host"]
    web_port_nums = {80, 443, 8080, 8443, 3000, 8888, 9090, 5000, 9443}
    web_ports = sorted(
        p["port"] for p in open_ports if p["port"] in web_port_nums
    )
    if not web_ports:
        return jsonify({"error": "Žiadne HTTP/HTTPS porty nenájdené", "results": []})

    results = []
    for port in web_ports:
        try:
            r = check_http_security(host, port)
            results.append(r)
        except Exception as e:
            results.append({"port": port, "error": str(e), "findings": []})

    # Ulož do DB
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("UPDATE scans SET http_security=? WHERE id=?",
                     (json.dumps(results, ensure_ascii=False), scan_id))

    return jsonify({"results": results})


@app.route("/analyze/<int:scan_id>")
@login_required
def analyze(scan_id):
    """SSE stream: spustí AI analýzu pre uložený sken a uloží výsledok."""

    def gen():
        def send(event, data):
            return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"

        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            scan = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()

        if not scan:
            yield send("error", {"message": "Sken nenájdený."})
            return

        ports = json.loads(scan["open_ports"] or "[]")

        if not ports:
            ai_text = "Žiadne otvorené porty — analýza nie je potrebná."
            yield send("ai_chunk", {"text": ai_text})
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute("UPDATE scans SET ai_analysis=? WHERE id=?", (ai_text, scan_id))
            yield send("done", {})
            return

        port_list = "\n".join(
            f"- Port {p['port']} ({p['sluzba']})" + (f" | banner: {p['banner']}" if p.get("banner") else "")
            for p in ports
        )
        prompt = (
            f"Port sken: {scan['host']} ({scan['ip']})\n"
            f"Otvorené porty:\n{port_list}\n\n"
            "Stručná bezpečnostná analýza v slovenčine (max 250 slov):\n"
            "1. **Kritické riziká** – len najdôležitejšie hrozby pre tieto porty\n"
            "2. **Top 3 odporúčania** – konkrétne kroky\n"
            "3. **Celkové riziko**: Nízke / Stredné / Vysoké / Kritické"
        )

        client = anthropic.Anthropic()
        ai_chunks = []

        try:
            with client.messages.stream(
                model="claude-haiku-4-5-20251001",
                max_tokens=700,
                messages=[{"role": "user", "content": prompt}],
            ) as stream:
                for event in stream:
                    if event.type == "content_block_delta" and hasattr(event, "delta"):
                        if event.delta.type == "text_delta":
                            ai_chunks.append(event.delta.text)
                            yield send("ai_chunk", {"text": event.delta.text})
        except Exception as e:
            yield send("error", {"message": f"AI chyba: {str(e)}"})
            return

        ai_text = "".join(ai_chunks)
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("UPDATE scans SET ai_analysis=? WHERE id=?", (ai_text, scan_id))

        yield send("done", {})

    return Response(
        stream_with_context(gen()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Plánované skeny ────────────────────────────────────────────────────────────

@app.route("/api/schedules")
@login_required
def list_schedules():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM schedules ORDER BY id DESC").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/schedules", methods=["POST"])
@login_required
def create_schedule():
    d = request.get_json(force=True) or {}
    host = (d.get("host") or "").strip()
    if not host:
        return jsonify({"error": "host je povinný"}), 400
    port_label = d.get("port_label", "top100")
    interval_hours = max(1, int(d.get("interval_hours", 24)))
    threads = min(int(d.get("threads", 100)), 300)
    next_run = (datetime.utcnow() + timedelta(hours=interval_hours)).strftime("%Y-%m-%d %H:%M:%S")
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            "INSERT INTO schedules (host, port_label, threads, interval_hours, next_run) VALUES (?,?,?,?,?)",
            (host, port_label, threads, interval_hours, next_run),
        )
    return jsonify({"id": cur.lastrowid, "next_run": next_run}), 201


@app.route("/api/schedules/<int:sid>", methods=["PATCH"])
@login_required
def patch_schedule(sid):
    d = request.get_json(force=True) or {}
    sets, vals = [], []
    if "enabled" in d:
        sets.append("enabled=?"); vals.append(1 if d["enabled"] else 0)
    if "interval_hours" in d:
        sets.append("interval_hours=?"); vals.append(max(1, int(d["interval_hours"])))
    if not sets:
        return jsonify({"error": "nič na zmenu"}), 400
    vals.append(sid)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(f"UPDATE schedules SET {', '.join(sets)} WHERE id=?", vals)
    return jsonify({"ok": True})


@app.route("/api/schedules/<int:sid>", methods=["DELETE"])
@login_required
def del_schedule(sid):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM schedules WHERE id=?", (sid,))
    return jsonify({"ok": True})


@app.route("/api/schedules/<int:sid>/run", methods=["POST"])
@login_required
def run_schedule_now(sid):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        sched = conn.execute("SELECT * FROM schedules WHERE id=?", (sid,)).fetchone()
    if not sched:
        return jsonify({"error": "nenájdený"}), 404
    scan_id = run_scan_sync(sched["host"], sched["port_label"], sched["threads"])
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    next_run = (datetime.utcnow() + timedelta(hours=sched["interval_hours"])).strftime("%Y-%m-%d %H:%M:%S")
    status = f"OK (sken #{scan_id})" if scan_id else "CHYBA: host nedostupný"
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE schedules SET last_run=?, next_run=?, last_status=? WHERE id=?",
            (now_str, next_run, status, sid),
        )
    return jsonify({"ok": True, "scan_id": scan_id})


# ── Rekon: ping, DNS, SSL ──────────────────────────────────────────────────────

def ping_host(host: str) -> dict:
    try:
        r = subprocess.run(
            ["ping", "-c", "4", "-W", "2", host],
            capture_output=True, text=True, timeout=20,
        )
        out = r.stdout
        rtt = re.search(r"rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", out)
        loss = re.search(r"(\d+)% packet loss", out)
        ttl = re.search(r"ttl=(\d+)", out, re.IGNORECASE)
        return {
            "alive": r.returncode == 0,
            "min": float(rtt.group(1)) if rtt else None,
            "avg": float(rtt.group(2)) if rtt else None,
            "max": float(rtt.group(3)) if rtt else None,
            "loss": int(loss.group(1)) if loss else 100,
            "ttl": int(ttl.group(1)) if ttl else None,
        }
    except Exception as e:
        return {"alive": False, "error": str(e)}


def dns_lookup(target: str) -> dict:
    records = {}
    for rtype in ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]:
        try:
            answers = dns.resolver.resolve(target, rtype, lifetime=5)
            records[rtype] = [str(r) for r in answers]
        except Exception:
            pass
    # PTR – reverzný DNS (len pre IP)
    try:
        ipaddress.ip_address(target)
        rev = dns.reversename.from_address(target)
        answers = dns.resolver.resolve(rev, "PTR", lifetime=5)
        records["PTR"] = [str(r) for r in answers]
    except Exception:
        pass
    return records


def ssl_cert_info(host: str, port: int = 443) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
        return {
            "cn": subject.get("commonName"),
            "issuer_org": issuer.get("organizationName") or issuer.get("commonName"),
            "issuer_cn": issuer.get("commonName"),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "sans": sans[:12],
            "cipher": cipher[0] if cipher else None,
            "protocol": version,
        }
    except ssl.SSLCertVerificationError as e:
        return {"error": f"Neplatný certifikát: {e.reason}"}
    except ConnectionRefusedError:
        return {"error": "Port 443 je zatvorený"}
    except Exception as e:
        return {"error": str(e)}


@app.route("/api/rekon/<path:target>")
@login_required
def rekon_api(target):
    """Ping + DNS záznamy + SSL certifikát pre doménu alebo IP."""
    target = target.strip()
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        ip = target

    # Parallelné volania
    with ThreadPoolExecutor(max_workers=3) as ex:
        f_ping = ex.submit(ping_host, ip)
        f_dns  = ex.submit(dns_lookup, target)
        f_ssl  = ex.submit(ssl_cert_info, target)
        ping_res = f_ping.result()
        dns_res  = f_dns.result()
        ssl_res  = f_ssl.result()

    return jsonify({"ip": ip, "ping": ping_res, "dns": dns_res, "ssl": ssl_res})


@app.route("/api/geowhois/<path:target>")
@login_required
def geowhois_api(target):
    """Geolokácia + whois pre IP alebo doménu."""
    target = target.strip()
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        ip = target
    geo = geoip_lookup(ip)
    whois_data = whois_lookup(target)
    return jsonify({"ip": ip, "geo": geo, "whois": whois_data})


@app.route("/scan-udp")
@login_required
def scan_udp_route():
    """SSE: UDP sken pre zadaný host."""
    host = request.args.get("host", "").strip()
    scan_id = request.args.get("scan_id", type=int)
    if not host:
        return Response("Chyba: host je povinný", status=400)

    def gen():
        def send(event, data):
            return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            yield send("error", {"message": f"Nemožno preložiť hostname: {host}"})
            return
        yield send("udp_start", {"host": host, "ip": ip, "count": len(_UDP_DEFAULT_PORTS)})
        results = scan_udp(ip, _UDP_DEFAULT_PORTS)
        open_ports = [r for r in results if r["state"] in ("open", "open|filtered")]
        # Ulož do DB ak máme scan_id
        if scan_id:
            try:
                with sqlite3.connect(DB_PATH) as conn:
                    conn.execute("UPDATE scans SET udp_ports=? WHERE id=?",
                                 (json.dumps(results, ensure_ascii=False), scan_id))
            except Exception:
                pass
        yield send("udp_done", {
            "host": host, "ip": ip,
            "results": results,
            "open_count": len(open_ports),
        })
        yield send("done", {})

    return Response(
        stream_with_context(gen()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Porovnanie skenov ──────────────────────────────────────────────────────────

@app.route("/api/compare")
@login_required
def compare_scans():
    a = request.args.get("a", type=int)
    b = request.args.get("b", type=int)
    if not a or not b:
        return jsonify({"error": "a a b sú povinné"}), 400
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        sa = conn.execute("SELECT * FROM scans WHERE id=?", (a,)).fetchone()
        sb = conn.execute("SELECT * FROM scans WHERE id=?", (b,)).fetchone()
    if not sa or not sb:
        return jsonify({"error": "sken nenájdený"}), 404
    pa = {p["port"]: p for p in json.loads(sa["open_ports"] or "[]")}
    pb = {p["port"]: p for p in json.loads(sb["open_ports"] or "[]")}
    return jsonify({
        "scan_a": {"id": sa["id"], "timestamp": sa["timestamp"], "host": sa["host"], "ip": sa["ip"], "open_count": sa["open_count"]},
        "scan_b": {"id": sb["id"], "timestamp": sb["timestamp"], "host": sb["host"], "ip": sb["ip"], "open_count": sb["open_count"]},
        "new_ports":    [pb[p] for p in pb if p not in pa],
        "closed_ports": [pa[p] for p in pa if p not in pb],
        "unchanged":    [pa[p] for p in pa if p in pb],
    })


# ── Sken rozsahu IP ────────────────────────────────────────────────────────────

@app.route("/scan-range")
@login_required
def scan_range():
    host_arg = request.args.get("host", "").strip()
    port_arg = request.args.get("ports", "top100").strip()
    threads = min(int(request.args.get("threads", 100)), 300)
    timeout = float(request.args.get("timeout", 0.8))

    if not host_arg:
        return Response("Chyba: host je povinný", status=400)

    hosts = parse_host_range(host_arg)
    if not hosts:
        return Response("Chyba: prázdny rozsah", status=400)

    ports = PREDEFINED_PROFILES.get(port_arg, PREDEFINED_PROFILES["top100"])

    def gen():
        def send(event, data):
            return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"

        yield send("range_start", {"total_hosts": len(hosts), "ports_count": len(ports)})
        total_open = 0

        for idx, host in enumerate(hosts):
            try:
                ip = socket.gethostbyname(host)
            except socket.gaierror:
                yield send("range_host_done", {
                    "host": host, "ip": None, "index": idx,
                    "total": len(hosts), "open_count": 0, "scan_id": None, "skipped": True,
                })
                continue

            yield send("range_host_start", {"host": host, "ip": ip, "index": idx, "total": len(hosts)})
            otvorene = []
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(scan_port, ip, p, timeout): p for p in ports}
                for future in as_completed(futures):
                    res = future.result()
                    if res["stav"] == "otvorený":
                        otvorene.append(res)
                        yield send("range_port", {"host": host, "ip": ip, **res})

            otvorene = sorted(otvorene, key=lambda x: x["port"])
            tarpit_r = detect_tarpit(otvorene, len(ports))
            os_r = detect_os_hint(ip, otvorene) if not tarpit_r["detected"] else \
                   {"os_hint": None, "device_type": None}
            scan_id = save_scan(host, ip, port_arg, otvorene,
                                os_hint=os_r["os_hint"], device_type=os_r["device_type"],
                                total_scanned=len(ports))
            total_open += len(otvorene)

            # HTTP check pre web porty (max 2 porty na host aby range nebol pomalý)
            _web = {80, 443, 8080, 8443}
            found_web_r = [p["port"] for p in otvorene if p["port"] in _web]
            http_r = None
            if found_web_r and not tarpit_r["detected"] and scan_id:
                http_res_r = []
                for wp in found_web_r[:2]:
                    try:
                        http_res_r.append(check_http_security(ip, wp))
                    except Exception:
                        pass
                if http_res_r:
                    http_r = http_res_r
                    with sqlite3.connect(DB_PATH) as conn2:
                        conn2.execute("UPDATE scans SET http_security=? WHERE id=?",
                                      (json.dumps(http_res_r, ensure_ascii=False), scan_id))

            yield send("range_host_done", {
                "host": host, "ip": ip, "index": idx, "total": len(hosts),
                "open_count": len(otvorene), "scan_id": scan_id, "skipped": False,
                "http_security": http_r,
                "tarpit": tarpit_r["detected"],
            })

        yield send("range_done", {"total_hosts": len(hosts), "total_open": total_open})

    return Response(
        stream_with_context(gen()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Webhook (automatické nasadenie) ───────────────────────────────────────────

WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")
DEPLOY_SCRIPT = os.path.join(os.path.dirname(__file__), "deploy.sh")


@app.route("/webhook", methods=["POST"])
def webhook():
    """Prijíma POST od GitHub/Gitea a spúšťa deploy.sh."""
    if not WEBHOOK_SECRET:
        return jsonify({"error": "WEBHOOK_SECRET nie je nastavený"}), 500

    # Overenie podpisu
    signature = request.headers.get("X-Hub-Signature-256", "")
    body = request.get_data()
    expected = "sha256=" + hmac.new(
        WEBHOOK_SECRET.encode(), body, "sha256"
    ).hexdigest()

    if not hmac.compare_digest(signature, expected):
        return jsonify({"error": "Neplatný podpis"}), 403

    # Spustenie deploy skriptu na pozadí
    try:
        subprocess.Popen(
            ["bash", DEPLOY_SCRIPT],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return jsonify({"status": "nasadenie spustené"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("DEBUG", "false").lower() == "true"
    print(f"[*] Spúšťam web server na http://0.0.0.0:{port}")
    print(f"[*] Prihlásenie: spravuj používateľov na /admin/users")
    app.run(host="0.0.0.0", port=port, debug=debug, threaded=True)
