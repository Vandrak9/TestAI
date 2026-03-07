# Changelog

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
