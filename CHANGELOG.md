# Changelog

## [0.4.4] – 2026-03-07
### Bezpečnosť
- **CSP** (`Content-Security-Policy`): `default-src 'self'` — blokuje načítanie externých skriptov a zdrojov
- **Permissions-Policy**: zakázaná kamera, mikrofón, geolokácia pre prehliadač
- `frame-ancestors 'self'`, `base-uri 'self'`, `form-action 'self'` — ochrana proti clickjacking a form hijacking

## [0.4.3] – 2026-03-07
### Opravené
- **Flask**: `host` zmenený z `0.0.0.0` na `127.0.0.1` — port 5000 nie je verejne dostupný
- **nginx**: `server_tokens off` — hlavička vracia len `nginx` bez verzie

## [0.4.2] – 2026-03-07
### Opravené
- **SSH banner grab**: port 22 teraz číta banner bez HTTP probe → eliminovaný "invalid format" v sshd logoch
- **HTTPS banner grab**: porty 443/8443/9443 používajú SSL wrapper
- **AI false positives**: prompt rozšírený o kontext pre správnu interpretáciu:
  - Port 80 bez HSTS = správne správanie
  - Port 443 → HTTP 400 = normálne nginx
  - SSH "invalid format" = artefakt skenera
  - Port 5000 za reverse proxy = nie je riziko
- **fail2ban**: IP `178.143.16.59` pridaná do whitelist

## [0.4.1] – 2026-03-07 (infraštruktúra)
### Bezpečnosť servera
- **fail2ban** – SSH ochrana: ban po 3 neúspešných pokusoch, trvanie 24 hodín
- Aktívny útočník `188.166.26.201` okamžite zablokovaný
- Config: `/etc/fail2ban/jail.local`

## [0.4.0] – 2026-03-07
### Pridané
- **HTTPS** – nginx reverse proxy + Let's Encrypt TLS certifikát (auto-obnova)
- HTTP → HTTPS redirect (301)
- Bezpečnostné hlavičky: `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`
- **Rate limiting** (`flask-limiter`) na kľúčových endpointoch:
  - `/login` POST: 10/min, 30/hod — ochrana proti brute force
  - `/scan`, `/scan-udp`: 20/min, 200/hod
  - `/scan-range`: 10/min, 100/hod
  - `/api/rekon`: 30/min

## [0.3.1] – 2026-03-07
### Opravené
- Tab "Rekon" premenovaný na **"DNS & Ping"** – zrozumiteľnejší názov
- Tabs menu: horizontálny scroll na mobile (`overflow-x:auto`, `white-space:nowrap`) – všetky záložky dostupné

## [0.3.0] – 2026-03-07
### Pridané
- Nový tab **DNS & Ping** pre prieskum hostiteľa
- **ICMP Ping** – latencia min/avg/max, strata paketov (%), TTL (4 pakety)
- **DNS záznamy** – A, AAAA, CNAME, MX, NS, TXT, SOA, PTR (knižnica `dnspython`)
- **SSL/TLS certifikát** – CN, vydavateľ, platnosť + zostatok dní, SAN, protokol, šifra
- API endpoint `GET /api/rekon/<target>` – 3 paralelné volania cez `ThreadPoolExecutor`
- Tab sa predvyplní hostom zo skenera pri prepnutí

## [0.2.1] – 2026-03-07
### Pridané
- **Správa používateľov** – SQLite tabuľka `users` (username, password_hash, role, active)
- Login migrovaný z env premenných na DB autentifikáciu
- Roly `admin` / `user`; dekorátory `@login_required`, `@admin_required`
- Admin UI `/admin/users` – pridanie, zmazanie, aktivácia/deaktivácia, zmena hesla
- Modal dialóg na zmenu hesla v admin UI
- Vlastná zmena hesla pre prihláseného používateľa (`POST /profile/password`)
- Nav: odkaz "Používatelia" viditeľný len pre admina + flash správy v UI
- UDP výsledky ukladané do DB cez `scan_id`

## [0.2.0] – 2026-03-07

### Pridané
- **UDP sken** — checkbox v konfigurácii spustí sken 18 bežných UDP portov (DNS, NTP, SNMP, NetBIOS, SIP, UPnP, OpenVPN, IPsec, mDNS, DHCP, TFTP, Syslog, IPMI, IKE, RIP, RPC); detekcia ICMP port unreachable; rozlišuje stavy `open`, `open|filtered`, `closed`
- **Geolokácia** — automaticky po každom skene; zobrazuje krajinu, región, mesto, ISP, organizáciu a ASN cez ip-api.com (bez API kľúča, 45 req/min)
- **Whois** — automaticky po každom skene; parsuje kľúčové polia (sieť, organizácia, krajina, dátumy, nameservery, abuse kontakt) cez systémový `whois`
- Výsledky geo/whois uložené v DB (`geo_whois TEXT`), zobrazené v karte po skene aj v histórii
- Badge s kódom krajiny (🌍 SK) v group headeri histórie

### Opravené
- **TLS auto-detekcia na neštandardných portoch** — `check_http_security` teraz vyskúša TLS pripojenie na ľubovoľnom porte; ak uspeje → HTTPS sken, inak HTTP (predtým fungoval TLS iba na 443, 8443, 9443)

### Interné zmeny
- Nové DB stĺpce: `geo_whois TEXT`, `udp_ports TEXT` (s automatickou migráciou)
- Nové API endpointy: `GET /api/geowhois/<target>`, `GET /scan-udp` (SSE stream)
- Servisné funkcie: `scan_udp()`, `geoip_lookup()`, `whois_lookup()`

## [0.1.0] – 2026-03-07

### Pridané
- **Webové rozhranie** – Flask aplikácia s prihlásením (používateľ + heslo v `.env`)
- **Real-time sken** – výsledky sa streamujú cez Server-Sent Events (SSE) priamo do prehliadača
- **Sken jednej IP** – zadanie hostnamu alebo IP, výber portov (bežné/všetky/vlastné)
- **Hromadný sken (range)** – sken celého rozsahu IP adries s nastavením počtu vlákien
- **AI analýza** – Claude AI vyhodnotí otvorené porty a navrhne bezpečnostné odporúčania (uložené v histórii)
- **Detekcia OS a typu zariadenia** – kombinácia TTL ping, banner grabbing a heuristiky portov
- **Detekcia TCP tarpit (honeypot)** – identifikuje MikroTik `action=tarpit` a podobné mechanizmy (vysoký pomer otvorených portov bez bannerov)
- **HTTP/HTTPS bezpečnostný sken** – automaticky sa spustí pri nájdení webových portov (80, 443, 8080, 8443); kontroluje verziu TLS, expiráciu certifikátu, self-signed cert, bezpečnostné hlavičky (HSTS, CSP, X-Frame-Options, …)
- **História skenov** – uložená v SQLite, zoskupená podľa cieľovej IP, limit 100 záznamov
- **IP bar** – zobrazuje vašu IP a IP skenera (VPS), tlačidlo na rýchle naskenovananie vlastnej IP
- **Automatické nasadenie** – webhook endpoint `/webhook` + `deploy.sh` + systemd pre auto-deploy pri `git push`
- **Responzívny dizajn** – funguje na mobile aj desktope

### Technické detaily
- Python 3 + Flask, SSE streaming
- SQLite (`history.db`) pre históriu
- Detekcia OS: TTL analýza (Linux ≤64, Windows ≤128, Cisco/sieťové ≤255), banner keywords, port heuristika
- Tarpit detekcia: ≥60 % otvorených portov + <5 % bannerov = vysoká istota
- HTTP sken: `ssl` modul pre TLS, `urllib` pre hlavičky – bez spotrebu AI tokenov
