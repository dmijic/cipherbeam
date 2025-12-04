# 🔐 CipherBeam — Web Security Scanner

**CipherBeam** is a lightweight web security analysis tool built in Python (Flask).  
It performs a series of non-intrusive checks on any public website and highlights potential configuration risks.

This project is part of my personal lab portfolio (lab.dariomijic.com) and is focused on practical, hands-on security tooling.

---

## 🚀 Features

✔️ HTTPS & TLS validation  
✔️ Certificate issuer & expiration  
✔️ Security headers analysis (CSP, HSTS, X-Frame-Options, etc.)  
✔️ Cookie attribute inspection (Secure, HttpOnly, SameSite)  
✔️ Mixed content detection (HTTPS site loading HTTP resources)  
✔️ CORS policy review  
✔️ robots.txt inspection  
✔️ CMS fingerprinting  
✔️ directory listing detection  
✔️ login form security check  
✔️ basic HTTP method discovery  
✔️ public security.txt lookup

Each check includes:

- status
- detailed explanation
- recommendations
- extracted metadata

---

## 🧩 Technology Stack

- Python
- Flask
- Gunicorn (production server)
- Requests
- BeautifulSoup
- HTML/CSS/JS frontend

No intrusive scanning is performed — purely configuration inspection through HTTP.

---

## 🛠 Local Development

`git clone https://github.com/dmijic/cipherbeam.git`

### create venv

`python3 -m venv .venv
source .venv/bin/activate`

### install dependencies

`pip install -r requirements.txt`

### run locally

`python app.py`

### App runs on:

http://127.0.0.1:5000

# 📌 Author

## 👤 Dario Mijić

Personal security and development sandbox:
lab.dariomijic.com

This tool was built as part of a wider portfolio for security-focused development roles.

⚠️ Disclaimer

CipherBeam performs passive checks only.
It does not exploit, brute-force or attack systems.

Use responsibly.
