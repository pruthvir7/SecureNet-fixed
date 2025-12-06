```markdown
# 🛡️ SecureNet: Adaptive Authentication with DNS Intelligence

[![Python](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.x-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> An intelligent, AI-driven adaptive authentication system that combines behavioral biometrics, DNS security, and real-time risk assessment to deliver context-aware multi-factor authentication.

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

---

## 🎯 Overview

SecureNet addresses critical vulnerabilities in traditional password and static MFA systems by integrating **behavioral biometrics**, **DNS threat intelligence**, and **machine learning-based risk scoring**. The system dynamically adapts authentication requirements based on real-time context, balancing security with user experience.

### The Problem

Traditional authentication systems face:
- Vulnerability to credential stuffing and phishing
- DNS spoofing and cache poisoning attacks
- Unnecessary user friction from static MFA rules
- Limited visibility into behavioral anomalies

### The Solution

SecureNet provides:
- **98% ML accuracy** in distinguishing legitimate users from attackers
- **Zero false negatives** in attack detection across 35+ test scenarios
- **<100ms authentication cycles** for seamless user experience
- **Adaptive MFA** that triggers only when risk warrants it

---

## ✨ Key Features

### 🔐 Behavioral Biometrics
- **Keystroke Dynamics Analysis**: Captures dwell time, flight time, digraph/trigraph patterns
- **Device Fingerprinting**: Multi-attribute identification (user-agent, OS, browser, network config)
- **Behavioral Profiling**: Builds unique user signatures resistant to spoofing

### 🌐 DNS Security Layer
- **EDNS Integration**: Enhanced DNS queries with metadata validation
- **DNS Threat Detection**: Spoofing and cache poisoning prevention
- **Resolver Validation**: Ensures requests reach legitimate servers
- **Domain Trust Scoring**: Quantitative reputation assessment

### 🤖 AI-Driven Risk Engine
- **Ensemble ML Models**: Random Forest, Gradient Boosting, Neural Network
- **Dynamic Risk Scoring**: Real-time evaluation (Low/Medium/High/Critical)
- **Context-Aware Decisions**: Considers behavior, device, network, and DNS signals
- **Continuous Learning**: Adapts to evolving threat patterns

### 🔑 Adaptive Multi-Factor Authentication
- **Risk-Based MFA**: Low risk → password only; Medium → email OTP; High → TOTP; Critical → block
- **TOTP Support**: Integration with Google Authenticator, Authy, etc.
- **Backup Codes**: Secure recovery options

### 📊 Real-Time Monitoring
- **Admin Dashboard**: Live login statistics, risk distribution, attack trends
- **WebSocket Streaming**: Real-time event updates
- **Historical Analytics**: Authentication logs and behavioral trends

---

## 🏗️ Architecture

```
┌─────────────┐
│   Browser   │  (Keystroke capture, Device fingerprint)
└──────┬──────┘
       │ HTTPS + WebSocket
       ▼
┌─────────────────────────────────────────┐
│          Flask API Server               │
│  ┌─────────────────────────────────┐   │
│  │  Authentication Engine          │   │
│  │  -  ML Risk Scoring              │   │
│  │  -  Behavioral Profiling         │   │
│  │  -  Adaptive MFA Logic           │   │
│  └─────────────────────────────────┘   │
│  ┌─────────────────────────────────┐   │
│  │  EDNS / DNS Security Layer      │   │
│  │  -  Threat Detection             │   │
│  │  -  Domain Validation            │   │
│  └─────────────────────────────────┘   │
└──────┬──────────────────┬───────────────┘
       │                  │
       ▼                  ▼
  ┌─────────┐      ┌──────────────┐
  │  MySQL  │      │ Email Service│
  │ Database│      │ (SendGrid)   │
  └─────────┘      └──────────────┘
```

---

## 🛠️ Tech Stack

### Backend
- **Python 3.x**: Core language
- **Flask**: Web framework with REST API
- **Flask Extensions**: CORS, Limiter, SocketIO, Bcrypt
- **scikit-learn**: ML model training and inference
- **PyJWT**: Token-based authentication
- **pyotp**: TOTP generation and verification

### Frontend
- **HTML5, CSS3, JavaScript**: UI components
- **FingerprintJS**: Device fingerprinting
- **Socket.IO**: Real-time dashboard updates
- **Font Awesome**: Icons and visual elements

### Data & Services
- **MySQL / Aiven**: User profiles, logs, behavioral data
- **SendGrid / Resend**: Email OTP and security alerts
- **Network Info API** (e.g., ipapi.co): IP geolocation and ASN enrichment

---

## 📦 Installation

### Prerequisites
- Python 3.10+
- MySQL 8.0+ (or Aiven-managed MySQL)
- Modern web browser (Chrome, Firefox, Edge)

### Step 1: Clone the Repository
```
git clone https://github.com/yourusername/securenet.git
cd securenet
```

### Step 2: Create Virtual Environment
```
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### Step 3: Install Dependencies
```
pip install -r requirements.txt
```

### Step 4: Set Up Database
```
mysql -u root -p < schema.sql
```

Or use the included `db.py` initialization functions.

---

## ⚙️ Configuration

### Environment Variables
Create a `.env` file in the project root:

```
# Database
DB_HOST=localhost
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_NAME=securenet

# Security
SECRET_KEY=your-secret-key-here
JWT_SECRET=your-jwt-secret-here

# Email Service (SendGrid or Resend)
SENDGRID_API_KEY=your-sendgrid-api-key
FROM_EMAIL=noreply@securenet.com

# Network API (optional)
IPAPI_KEY=your-ipapi-key
```

### ML Model Setup
Ensure the trained model file is in place:
```
# Model should be at: models/risk_model.pkl
# Or train a new model using:
python train_model.py
```

---

## 🚀 Usage

### Start the Application
```
python app.py
```

The server will start on `http://localhost:5000`

### Access the Application
- **Home Page**: `http://localhost:5000/`
- **Registration**: `http://localhost:5000/register.html`
- **Login**: `http://localhost:5000/login.html`
- **Dashboard**: `http://localhost:5000/dashboard.html` (after login)

### API Endpoints
```
POST /api/register          - User registration with biometric setup
POST /api/login             - Adaptive authentication login
POST /api/mfa/verify        - TOTP/backup code verification
GET  /api/user/profile      - User profile and statistics
GET  /api/user/auth-history - Authentication history
```

---

## 🧪 Testing

### Run Scenario Tests
```
python test_scenarios.py
```

### Test Results Summary
- **Total Scenarios**: 35
- **Success Rate**: 91.4%
- **Attack Detection**: 100% (8/8 attacks blocked)
- **False Negatives**: 0%
- **Performance**: <100ms average authentication cycle

### Performance Metrics
```
Input preprocessing:        < 10 ms
DNS evaluation (cached):    8-12 ms
ML inference:              20-35 ms
Total auth cycle:          < 100 ms
```

---

## 📁 Project Structure

```
securenet/
├── app.py                    # Main Flask application
├── config.py                 # Configuration management
├── requirements.txt          # Python dependencies
├── schema.sql               # Database schema
├── train_model.py           # ML model training script
├── test_scenarios.py        # Comprehensive test suite
├── auth/
│   ├── auth_engine.py       # Authentication logic
│   ├── risk_scorer.py       # ML-based risk assessment
│   └── mfa_handler.py       # MFA management
├── db/
│   └── db.py                # Database operations
├── models/
│   └── risk_model.pkl       # Trained ML model
├── static/
│   ├── css/
│   │   └── style.css        # Application styles
│   └── js/
│       └── keystroke.js     # Behavioral capture
├── templates/
│   ├── index.html           # Landing page
│   ├── login.html           # Login interface
│   ├── register.html        # Registration flow
│   ├── dashboard.html       # User dashboard
│   └── mfa-verify.html      # MFA verification
└── README.md                # This file
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/YourFeature`)
3. Commit your changes (`git commit -m 'Add YourFeature'`)
4. Push to the branch (`git push origin feature/YourFeature`)
5. Open a Pull Request

### Development Guidelines
- Follow PEP 8 style guidelines
- Add unit tests for new features
- Update documentation as needed
- Ensure all tests pass before submitting PR

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- Research papers on adaptive authentication and DNS security
- Flask and scikit-learn communities
- FingerprintJS for device identification
- SendGrid for email delivery infrastructure

---

## 📧 Contact

For questions, issues, or collaboration opportunities:
- **GitHub Issues**: [Report a bug](https://github.com/yourusername/securenet/issues)
- **Email**: your.email@example.com

---

<p align="center">Made with ❤️ for secure digital experiences</p>
```
