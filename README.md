# 🛡️ SecureNet: Adaptive Authentication with DNS Intelligence

[![Python](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.x-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> An intelligent, AI-driven adaptive authentication system that combines behavioral biometrics, DNS security, and machine learning–based risk scoring for context-aware multi-factor authentication.

---

## 📋 Table of Contents
- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)
- [Contact](#contact)

---

## 🎯 Overview

SecureNet enhances traditional authentication by integrating:

- **Behavioral biometrics**
- **DNS threat intelligence**
- **Machine learning risk scoring**
- **Adaptive MFA triggers**

This ensures high security with low user friction.

### The Problem
Traditional authentication suffers from:
- Credential stuffing & phishing
- DNS spoofing & cache poisoning
- Static MFA rules that are annoying
- No behavioral anomaly detection

### The Solution
SecureNet provides:
- **98% ML accuracy** in identifying legitimate users  
- **0 false negatives** across 35+ attack simulations  
- **<100ms average authentication cycle**  
- **Adaptive MFA** based on real-time risk  

---

## ✨ Key Features

### 🔐 Behavioral Biometrics
- Keystroke dynamics (dwell/flight time, digraph/trigraph patterns)
- Device fingerprinting (OS, browser, UA, network attributes)
- Behavioral profiling resistant to spoofing

### 🌐 DNS Security Layer
- EDNS-aware metadata validation  
- DNS spoofing & poisoning detection  
- Resolver trust verification  
- Domain reputation scoring  

### 🤖 AI Risk Engine
- Ensemble ML models (RF, GBoost, Neural Nets)
- Real-time dynamic risk scoring: Low → Critical
- Context-aware decisions (behavior + device + DNS)
- Continuous learning over time

### 🔑 Adaptive Multi-Factor Authentication
| Risk Level | Action |
|-----------|--------|
| Low       | Password only |
| Medium    | Email OTP |
| High      | TOTP |
| Critical  | Block login |

Additional features:
- TOTP support (Google Authenticator, Authy)
- Backup recovery codes

### 📊 Real-Time Monitoring
- Live dashboard with risk analytics
- Attack trends and login history
- WebSocket-powered event streaming

---

## 🏗️ Architecture

```

┌─────────────┐
│   Browser   │  (Keystrokes + Fingerprint)
└──────┬──────┘
│ HTTPS / WebSocket
▼
┌─────────────────────────────────────────┐
│               Flask API                 │
│  ┌───────────────────────────────────┐ │
│  │ Authentication Engine             │ │
│  │ - ML Risk Scoring                │ │
│  │ - Behavioral Profiling           │ │
│  │ - Adaptive MFA Logic             │ │
│  └───────────────────────────────────┘ │
│  ┌───────────────────────────────────┐ │
│  │ DNS Security Layer                │ │
│  │ - EDNS Analysis                   │ │
│  │ - Spoof Detection                 │ │
│  └───────────────────────────────────┘ │
└──────┬──────────────────┬──────────────┘
│                  │
▼                  ▼
┌─────────┐       ┌──────────────┐
│  MySQL  │       │ Email Service│
└─────────┘       └──────────────┘

````

---

## 🛠️ Tech Stack

### Backend
- Python 3.x  
- Flask (REST API, WebSockets)  
- Flask-CORS, Flask-Limiter, SocketIO, Bcrypt  
- scikit-learn  
- PyJWT  
- pyotp  

### Frontend
- HTML5, CSS3, JavaScript  
- FingerprintJS  
- Socket.IO  
- Font Awesome  

### Infra & Services
- MySQL / Aiven  
- SendGrid / Resend  
- Optional: IP geolocation APIs  

---

## 📦 Installation

### 1. Clone Repository
```sh
git clone https://github.com/yourusername/securenet.git
cd securenet
````

### 2. Create Virtual Environment

```sh
python -m venv venv
source venv/bin/activate    # Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```sh
pip install -r requirements.txt
```

### 4. Setup Database

```sh
mysql -u root -p < schema.sql
```

---

## ⚙️ Configuration

Create a `.env` file:

```
DB_HOST=localhost
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_NAME=securenet

SECRET_KEY=your-secret-key
JWT_SECRET=your-jwt-secret

SENDGRID_API_KEY=your-sendgrid-api-key
FROM_EMAIL=noreply@securenet.com

IPAPI_KEY=your-ipapi-key
```

### ML Model

Ensure your trained model exists at:

```
models/risk_model.pkl
```

Or train it:

```sh
python train_model.py
```

---

## 🚀 Usage

### Run the App

```sh
python app.py
```

### Access Pages

* Home: `/`
* Register: `/register.html`
* Login: `/login.html`
* Dashboard: `/dashboard.html`

### API Endpoints

```
POST /api/register
POST /api/login
POST /api/mfa/verify
GET  /api/user/profile
GET  /api/user/auth-history
```

---

## 🧪 Testing

### Run All Scenarios

```sh
python test_scenarios.py
```

### Performance Summary

* **35 scenarios tested**
* **91.4% success**
* **100% attack detection**
* **0 false negatives**
* **<100ms total authentication cycle**

---

## 📁 Project Structure

```
securenet/
├── app.py
├── config.py
├── requirements.txt
├── schema.sql
├── train_model.py
├── test_scenarios.py
├── auth/
│   ├── auth_engine.py
│   ├── risk_scorer.py
│   └── mfa_handler.py
├── db/
│   └── db.py
├── models/
│   └── risk_model.pkl
├── static/
│   ├── css/style.css
│   └── js/keystroke.js
├── templates/
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   └── mfa-verify.html
└── README.md
```

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/MyFeature`)
3. Commit your changes
4. Push to your branch
5. Open a Pull Request

Please follow:

* PEP 8
* Write tests for new features
* Update documentation

---

## 📄 License

This project is licensed under the **MIT License**.

---

## 🙏 Acknowledgments

* Research contributions in adaptive authentication
* Flask & scikit-learn communities
* FingerprintJS
* SendGrid

---

## 📧 Contact

For issues or collaboration opportunities:

**Email:** [securenet220@gmail.com](mailto:securenet220@gmail.com)
**GitHub Issues:** Open a ticket anytime



