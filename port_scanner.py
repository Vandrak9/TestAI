#!/usr/bin/env python3
"""
Port Scanner s AI analýzou
Skenuje porty cieľového hosta a AI (Claude) analyzuje výsledky.
"""

import socket
import sys
import time
import argparse
import anthropic
from concurrent.futures import ThreadPoolExecutor, as_completed

# Databáza bežných služieb
COMMON_SERVICES = {
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    119: "NNTP",
    123: "NTP",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    194: "IRC",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP Submission",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS Proxy",
    1194: "OpenVPN",
    1433: "MSSQL",
    1521: "Oracle DB",
    1723: "PPTP VPN",
    2049: "NFS",
    2375: "Docker HTTP",
    2376: "Docker HTTPS",
    3000: "Dev Server / Grafana",
    3306: "MySQL",
    3389: "RDP",
    3690: "SVN",
    4444: "Metasploit",
    4899: "Radmin",
    5000: "Flask / UPnP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
    6379: "Redis",
    6443: "Kubernetes API",
    7070: "RealAudio",
    8080: "HTTP Proxy / Tomcat",
    8443: "HTTPS Alt",
    8888: "Jupyter Notebook",
    9090: "Prometheus",
    9200: "Elasticsearch",
    9300: "Elasticsearch Cluster",
    27017: "MongoDB",
    27018: "MongoDB",
    50000: "DB2",
}

PREDEFINED_PROFILES = {
    "rychly": list(range(1, 1025)),
    "web": [80, 443, 8080, 8443, 3000, 8888],
    "databazy": [3306, 5432, 1433, 1521, 27017, 6379, 9200],
    "vzdialeny": [22, 23, 3389, 5900, 5985, 5986],
    "top100": [
        21, 22, 23, 25, 53, 80, 110, 111, 119, 135, 139, 143, 161, 194,
        389, 443, 445, 465, 514, 587, 636, 993, 995, 1080, 1194, 1433,
        1521, 1723, 2049, 2375, 2376, 3000, 3306, 3389, 4444, 5000,
        5432, 5900, 5985, 5986, 6379, 8080, 8443, 8888, 9090, 9200, 27017,
    ],
}


def scan_port(host: str, port: int, timeout: float = 1.0) -> dict:
    """Pokúsi sa pripojiť na port a vráti výsledok."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            if result == 0:
                service = COMMON_SERVICES.get(port, "Neznáma")
                # Pokus o získanie banneru
                banner = ""
                try:
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(256).decode("utf-8", errors="ignore").strip()
                    banner = banner[:100]
                except Exception:
                    pass
                return {"port": port, "stav": "otvorený", "sluzba": service, "banner": banner}
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    return {"port": port, "stav": "zatvorený"}


def scan_host(host: str, ports: list, max_threads: int = 100, timeout: float = 1.0) -> list:
    """Skenuje všetky porty paralelne."""
    otvorene = []
    celkom = len(ports)
    hotovo = 0

    print(f"\n[*] Skenujem {host} — {celkom} portov ({max_threads} vlákien)...\n")

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_port, host, p, timeout): p for p in ports}
        for future in as_completed(futures):
            hotovo += 1
            vysledok = future.result()
            if vysledok["stav"] == "otvorený":
                otvorene.append(vysledok)
                sluzba = vysledok["sluzba"]
                banner_info = f" | Banner: {vysledok['banner']}" if vysledok.get("banner") else ""
                print(f"  [OPEN]  Port {vysledok['port']:5d}  →  {sluzba}{banner_info}")
            # Jednoduchý progress bar
            if hotovo % 100 == 0 or hotovo == celkom:
                pct = hotovo / celkom * 100
                print(f"  Progress: {hotovo}/{celkom} ({pct:.0f}%)", end="\r")

    print()
    return sorted(otvorene, key=lambda x: x["port"])


def ai_analyza(host: str, otvorene_porty: list) -> str:
    """Pošle výsledky skenu Claude AI na analýzu."""
    if not otvorene_porty:
        return "Neboli nájdené žiadne otvorené porty. Cieľ je buď offline alebo má firewall."

    client = anthropic.Anthropic()

    # Zostavenie prehľadu pre AI
    zhrnutie = f"Výsledky port skenu pre hostiteľa: {host}\n\n"
    zhrnutie += f"Celkový počet otvorených portov: {len(otvorene_porty)}\n\n"
    zhrnutie += "Otvorené porty:\n"

    for p in otvorene_porty:
        banner_info = f" (banner: {p['banner']})" if p.get("banner") else ""
        zhrnutie += f"  - Port {p['port']} ({p['sluzba']}){banner_info}\n"

    prompt = f"""Si expert na sieťovú bezpečnosť. Analyzuj nasledujúce výsledky port skenu a podaj podrobnú bezpečnostnú správu v slovenčine.

{zhrnutie}

Prosím, zahrň do analýzy:

1. **Prehľad nájdených služieb** – vysvetli účel každej otvorenej služby
2. **Bezpečnostné riziká** – identifikuj potenciálne zraniteľnosti a hrozby pre každý otvorený port
3. **Kritické nálezy** – zvýrazni najnebezpečnejšie porty/služby (ak existujú)
4. **Odporúčania** – konkrétne kroky na zlepšenie bezpečnosti
5. **Celkové hodnotenie** – stručné zhrnutie bezpečnostného stavu (stupnica: Nízke / Stredné / Vysoké / Kritické riziko)

Buď konkrétny a praktický. Ak vidíš nebezpečné kombinácie (napr. Telnet + FTP = nešifrované prenos), upozorni na to.
"""

    print("\n[*] AI analýza prebieha...\n")
    print("=" * 70)

    full_response = ""

    with client.messages.stream(
        model="claude-opus-4-6",
        max_tokens=4096,
        thinking={"type": "adaptive"},
        messages=[{"role": "user", "content": prompt}],
    ) as stream:
        for event in stream:
            if event.type == "content_block_start":
                if hasattr(event, "content_block") and event.content_block.type == "thinking":
                    print("[Premýšľam...]\n")
            elif event.type == "content_block_delta":
                if hasattr(event, "delta"):
                    if event.delta.type == "text_delta":
                        print(event.delta.text, end="", flush=True)
                        full_response += event.delta.text

    print("\n" + "=" * 70)
    return full_response


def resolve_host(host: str) -> str:
    """Preloží hostname na IP adresu."""
    try:
        ip = socket.gethostbyname(host)
        if ip != host:
            print(f"[*] {host} → {ip}")
        return ip
    except socket.gaierror:
        print(f"[!] Chyba: Nemožno preložiť hostname '{host}'")
        sys.exit(1)


def parse_ports(port_arg: str) -> list:
    """Parsuje argument portov: rozsahy, čiarky alebo profily."""
    if port_arg in PREDEFINED_PROFILES:
        print(f"[*] Profil '{port_arg}': {len(PREDEFINED_PROFILES[port_arg])} portov")
        return PREDEFINED_PROFILES[port_arg]

    porty = set()
    for cast in port_arg.split(","):
        cast = cast.strip()
        if "-" in cast:
            start, end = cast.split("-", 1)
            porty.update(range(int(start), int(end) + 1))
        else:
            porty.add(int(cast))
    return sorted(porty)


def main():
    parser = argparse.ArgumentParser(
        description="Port Scanner s AI analýzou (Claude)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Príklady:
  python port_scanner.py 192.168.1.1
  python port_scanner.py example.com --ports web
  python port_scanner.py 10.0.0.1 --ports 22,80,443
  python port_scanner.py 10.0.0.1 --ports 1-1024 --threads 200
  python port_scanner.py 10.0.0.1 --ports databazy --bez-ai

Profily portov:
  rychly   - porty 1-1024 (štandard)
  top100   - top 100 najčastejších portov
  web      - webové služby (80,443,8080,8443,3000,8888)
  databazy - databázové porty (MySQL, PostgreSQL, MongoDB, Redis...)
  vzdialeny - vzdialený prístup (SSH, RDP, VNC, WinRM)
        """,
    )
    parser.add_argument("host", help="Cieľový hostiteľ (IP alebo hostname)")
    parser.add_argument(
        "--ports", "-p",
        default="top100",
        help="Porty na skenovanie: rozsah (1-1024), zoznam (22,80,443), alebo profil (default: top100)",
    )
    parser.add_argument(
        "--threads", "-t",
        type=int,
        default=100,
        help="Počet paralelných vlákien (default: 100)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Timeout pre každý port v sekundách (default: 1.0)",
    )
    parser.add_argument(
        "--bez-ai",
        action="store_true",
        help="Preskočí AI analýzu (len vypíše otvorené porty)",
    )

    args = parser.parse_args()

    print("=" * 70)
    print("       PORT SCANNER  s  AI ANALÝZOU  (Claude Opus 4.6)")
    print("=" * 70)

    # Preloženie hostu
    ip = resolve_host(args.host)

    # Parsovanie portov
    porty = parse_ports(args.ports)

    zacatok = time.time()

    # Skenovanie
    otvorene = scan_host(ip, porty, args.threads, args.timeout)

    elapsed = time.time() - zacatok

    print(f"\n[+] Skenovanie dokončené za {elapsed:.1f}s")
    print(f"[+] Nájdených otvorených portov: {len(otvorene)} z {len(porty)}\n")

    if not args.bez_ai:
        ai_analyza(args.host, otvorene)
    else:
        if otvorene:
            print("Otvorené porty:")
            for p in otvorene:
                print(f"  {p['port']:5d}  {p['sluzba']}")
        else:
            print("Žiadne otvorené porty nenájdené.")


if __name__ == "__main__":
    main()
