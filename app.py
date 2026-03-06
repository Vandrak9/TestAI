#!/usr/bin/env python3
"""
Web rozhranie pre Port Scanner s AI analýzou
Spustenie: python app.py
"""

import json
import socket
import hashlib
import os
import secrets
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps
from flask import (
    Flask, render_template, request, Response,
    stream_with_context, session, redirect, url_for, flash,
)
import anthropic

from port_scanner import PREDEFINED_PROFILES, scan_port

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Prihlasovacie údaje z premenných prostredia
APP_USERNAME = os.environ.get("APP_USERNAME", "admin")
APP_PASSWORD_HASH = os.environ.get(
    "APP_PASSWORD_HASH",
    hashlib.sha256(os.environ.get("APP_PASSWORD", "admin").encode()).hexdigest(),
)


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.path))
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

        if username == APP_USERNAME and hash_password(password) == APP_PASSWORD_HASH:
            session.permanent = True
            session["logged_in"] = True
            session["username"] = username
            next_url = request.args.get("next", url_for("index"))
            return redirect(next_url)
        else:
            error = "Nesprávne meno alebo heslo."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ── Scanner routes ─────────────────────────────────────────────────────────────

def stream_scan(host: str, ports: list, threads: int = 100, timeout: float = 1.0):
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

    yield send("scan_done", {
        "open_count": len(otvorene),
        "total": celkom,
        "host": host,
        "ip": ip,
    })

    if not otvorene:
        yield send("ai_chunk", {"text": "Neboli nájdené žiadne otvorené porty."})
        yield send("done", {})
        return

    yield send("ai_start", {"message": "Claude analyzuje výsledky..."})

    client = anthropic.Anthropic()

    zhrnutie = f"Výsledky port skenu pre: {host} ({ip})\n\n"
    zhrnutie += f"Otvorených portov: {len(otvorene)}\n\n"
    for p in otvorene:
        banner_info = f" (banner: {p['banner']})" if p.get("banner") else ""
        zhrnutie += f"  - Port {p['port']} ({p['sluzba']}){banner_info}\n"

    prompt = f"""Si expert na sieťovú bezpečnosť. Analyzuj výsledky port skenu a podaj podrobnú bezpečnostnú správu v slovenčine.

{zhrnutie}

Zahrň:
1. **Prehľad služieb** – účel každej otvorenej služby
2. **Bezpečnostné riziká** – zraniteľnosti pre každý port
3. **Kritické nálezy** – najnebezpečnejšie porty (ak existujú)
4. **Odporúčania** – konkrétne kroky (firewall pravidlá, zakázanie služieb...)
5. **Celkové hodnotenie** – Nízke / Stredné / Vysoké / Kritické riziko

Buď konkrétny. Upozorni na nebezpečné kombinácie služieb.
"""

    try:
        with client.messages.stream(
            model="claude-opus-4-6",
            max_tokens=4096,
            thinking={"type": "adaptive"},
            messages=[{"role": "user", "content": prompt}],
        ) as stream:
            for event in stream:
                if event.type == "content_block_delta" and hasattr(event, "delta"):
                    if event.delta.type == "text_delta":
                        yield send("ai_chunk", {"text": event.delta.text})
    except Exception as e:
        yield send("error", {"message": f"AI chyba: {str(e)}"})

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
        stream_with_context(stream_scan(host, ports, threads, timeout)),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("DEBUG", "false").lower() == "true"
    print(f"[*] Spúšťam web server na http://0.0.0.0:{port}")
    print(f"[*] Prihlásenie: {APP_USERNAME} / (nastavené cez APP_PASSWORD)")
    app.run(host="0.0.0.0", port=port, debug=debug, threaded=True)
