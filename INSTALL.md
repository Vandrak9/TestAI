# Inštalácia na VPS

## 1. Prvotné nasadenie

```bash
# Klonujte repozitár
git clone <repo-url> /opt/portscanner
cd /opt/portscanner

# Vytvorte virtual environment
python3 -m venv venv
venv/bin/pip install -r requirements.txt

# Nastavte prostredie
cp .env.example .env
nano .env   # vyplňte API kľúč, heslo, secret kľúče
```

## 2. Systemd služba (beh na pozadí + autostart)

```bash
# Upravte User= v scanner.service ak nie ste ubuntu
nano scanner.service

# Nainštalujte službu
sudo cp scanner.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable scanner
sudo systemctl start scanner

# Skontrolujte stav
sudo systemctl status scanner
sudo journalctl -u scanner -f
```

## 3. Oprávnenia pre deploy skript

```bash
chmod +x deploy.sh

# Povolte reštart služby bez sudo hesla
sudo visudo
# Pridajte riadok (nahraďte ubuntu vaším userom):
# ubuntu ALL=(ALL) NOPASSWD: /bin/systemctl restart scanner
```

## 4. Automatické nasadenie cez Webhook

### Vygenerujte webhook secret
```bash
openssl rand -hex 32
# Výsledok vložte do .env ako WEBHOOK_SECRET=...
```

### Nastavte webhook v GitHub / Gitea
```
URL:           http://vasa-ip:5000/webhook
Content-Type:  application/json
Secret:        (váš WEBHOOK_SECRET)
Events:        Just the push event
```

Po každom `git push` sa VPS automaticky stiahne nový kód a reštartuje aplikáciu.

## 5. Otvorenie portu (firewall)

```bash
sudo ufw allow 5000
sudo ufw status
```

## 6. Zmena hesla

```bash
nano /opt/portscanner/.env
# Zmeňte APP_PASSWORD=nove-heslo
sudo systemctl restart scanner
```

## Štruktúra projektu

```
/opt/portscanner/
├── app.py              # Flask web aplikácia
├── port_scanner.py     # Scanner engine
├── deploy.sh           # Nasadzovací skript
├── scanner.service     # Systemd unit
├── requirements.txt
├── .env                # Tajné kľúče (nie v gite!)
├── .env.example        # Šablóna
└── templates/
    ├── index.html      # Hlavná stránka
    └── login.html      # Prihlasovacia stránka
```
