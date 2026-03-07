# Port Scanner – AI bezpečnostný nástroj

Webový nástroj na skenovanie portov s AI analýzou (Claude), detekciou OS, HTTP/HTTPS bezpečnostným skenovaním a históriou skenov.

---

## Funkcie

| Funkcia | Popis |
|---|---|
| Sken jednej IP | Hostname alebo IP, výber portov (bežné / všetky / vlastné) |
| Hromadný sken | Rozsah IP adries, nastaviteľný počet vlákien |
| Detekcia OS | TTL analýza, banner grabbing, port heuristika |
| Detekcia tarpit | Identifikuje honeypot/tarpit mechanizmy (MikroTik a pod.) |
| HTTP/HTTPS sken | TLS verzia, expirácia certifikátu, bezpečnostné hlavičky; auto-detekcia na ľubovoľnom porte |
| UDP sken | DNS, NTP, SNMP, SIP, UPnP, OpenVPN, IPsec a ďalšie; detekcia ICMP unreachable |
| Geolokácia | Krajina, región, mesto, ISP, ASN (ip-api.com, bez kľúča) |
| Whois | Registrant, dátumy, nameservery, abuse kontakt |
| AI analýza | Claude AI vyhodnotí nálezy a navrhne odporúčania |
| História | SQLite, zoskupená podľa IP, posledných 100 záznamov |

---

## Inštalácia

### Požiadavky
- Python 3.10+
- VPS / Linux server
- Anthropic API kľúč ([console.anthropic.com](https://console.anthropic.com))

### Postup

```bash
# 1. Klonujte repozitár
git clone https://github.com/Vandrak9/TestAI /opt/portscanner
cd /opt/portscanner

# 2. Vytvorte virtual environment a nainštalujte závislosti
python3 -m venv venv
venv/bin/pip install -r requirements.txt

# 3. Nastavte premenné prostredia
cp .env.example .env
nano .env
```

### Obsah `.env`

```env
ANTHROPIC_API_KEY=sk-ant-...     # Anthropic API kľúč
SECRET_KEY=<nahodny-retazec>     # Flask session secret (openssl rand -hex 32)
APP_USERNAME=admin                # Prihlasovacie meno
APP_PASSWORD=<vase-heslo>         # Prihlasovacie heslo
PORT=5000                         # Port aplikácie
DEBUG=false
```

### Spustenie ako systemd služba

```bash
sudo cp scanner.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable scanner
sudo systemctl start scanner

# Stav
sudo systemctl status scanner
sudo journalctl -u scanner -f
```

---

## Použitie

### Sken jednej IP / hostnamu

1. Do poľa **Host / IP** zadajte cieľ (napr. `192.168.1.1` alebo `example.com`)
2. Vyberte rozsah portov:
   - **Bežné** – top 1000 portov
   - **Všetky** – 1–65535
   - **Vlastné** – zadajte ručne (napr. `22,80,443` alebo `1-1024`)
3. Kliknite **Spustiť sken**

Po skene sa automaticky zobrazia:
- Zoznam otvorených portov s bannermi
- OS / typ zariadenia (ak sa podarí zistiť)
- Upozornenie ak je detekovaný tarpit/honeypot
- HTTP/HTTPS bezpečnostné výsledky (len ak sú nájdené webové porty)

### Hromadný sken (range)

1. Prepnite na záložku **Range**
2. Zadajte rozsah IP (napr. `192.168.1.1-192.168.1.254`)
3. Zadajte porty a počet vlákien
4. Výsledky sa zobrazujú v reálnom čase

### História

- Záložka **História** zobrazuje posledných 100 skenov
- Zoskupené podľa cieľovej IP
- Každý sken obsahuje: otvorené porty, OS hint, HTTP/HTTPS nálezy, AI analýzu
- Kliknutím na sken sa rozbalí detail

### IP bar

V hornej časti stránky vidíte:
- **Vaša IP** – verejná IP z ktorej pristupujete
- **IP skenera** – verejná IP VPS/servera kde beží nástroj
- Tlačidlo **Skenovať moju IP** – rýchle skenovanie vašej vlastnej IP

---

## Automatické nasadenie (Webhook)

Pri každom `git push` sa VPS automaticky aktualizuje:

```bash
# 1. Vygenerujte webhook secret
openssl rand -hex 32
# Výsledok pridajte do .env ako WEBHOOK_SECRET=...

# 2. V GitHub nastavte webhook:
#    URL:          http://<ip-servera>:5000/webhook
#    Content-Type: application/json
#    Secret:       (váš WEBHOOK_SECRET)
#    Events:       Just the push event
```

---

## Štruktúra projektu

```
/opt/portscanner/
├── app.py              # Flask aplikácia (hlavná logika)
├── port_scanner.py     # Scanner engine
├── deploy.sh           # Auto-deploy skript (volá webhook)
├── scanner.service     # Systemd unit file
├── requirements.txt    # Python závislosti
├── .env                # Konfigurácia (nie v gite!)
├── .env.example        # Šablóna pre .env
├── CHANGELOG.md        # História zmien
└── templates/
    ├── index.html      # Hlavná stránka
    └── login.html      # Prihlasovacia stránka
```

---

## Bezpečnostné poznámky

- Nástroj je určený pre **autorizované testovanie** vlastnej infraštruktúry
- Skenujte iba siete a zariadenia, na ktoré máte oprávnenie
- API kľúč a heslo nikdy nevkladajte priamo do kódu — používajte `.env`
- Odporúčame spustiť za reverse proxy (nginx) s HTTPS

---

## Verzia

Aktuálna verzia: **0.2.0**
Pozri [CHANGELOG.md](CHANGELOG.md) pre históriu zmien.
