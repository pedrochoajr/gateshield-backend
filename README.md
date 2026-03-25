# 🛡️ GateShield — API Security Gateway

GateShield is a prototype **API security gateway** that inspects inbound requests, detects malicious patterns, tracks client behavior over time, and enforces dynamic access control based on risk.

It sits in front of an upstream API and acts as a protective layer, blocking or flagging suspicious traffic before it reaches the application.

---

## 🚀 Live Demo

- 🔐 Gateway: https://gateshield-gateway.onrender.com  
- 🧪 Protected API: https://gateshield-backend.onrender.com  

---

## 🧠 What It Does

GateShield analyzes each incoming request and:

- Detects common attack patterns:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Path Traversal
  - Oversized payloads
  - Suspicious headers
  - Missing authentication on sensitive endpoints

- Assigns a **risk score** to each request

- Tracks **recent request history per client**

- Dynamically escalates enforcement:
  - ✅ Allow
  - ⚠️ Flag
  - ❌ Block

- Maintains a **live client risk level** based on behavior over time

---

## 🔥 Key Feature: Behavior-Based Blocking

GateShield doesn’t just evaluate requests in isolation.

It answers:

> “Is this request suspicious given what this client has been doing recently?”

### Example:
1. A client sends multiple suspicious requests  
2. Each one increases their **live risk score**  
3. Even a normal request can be **blocked** once the risk threshold is exceeded  

This mimics how real-world API security systems detect evolving attacks.

---

## 🖥️ Dashboard Features

The built-in dashboard allows you to:

- Send test requests (safe and malicious)
- View:
  - decision (allow / flag / block)
  - matched rules
  - request details
- Track:
  - total events
  - flagged / blocked requests
- Monitor:
  - **live client risk level**
- Reset your history for testing

---

## 🏗️ Architecture
Client
↓
GateShield (FastAPI Gateway)
↓
Protected API (Upstream Service)


### Components

- **Gateway (FastAPI)**
  - Request inspection engine
  - Rule-based detection
  - Risk scoring
  - Behavior tracking
  - Proxy forwarding via `httpx`

- **Protected API**
  - Simple backend service
  - Represents the application being protected

- **SQLite Database**
  - Stores request history
  - Enables behavior-based analysis

---

## ⚙️ Tech Stack

- Python
- FastAPI
- Uvicorn
- HTTPX
- SQLite
- Pydantic
- HTML / CSS / Vanilla JavaScript

---

## 🧪 How to Run Locally

```bash
git clone https://github.com/your-username/gateshield-backend.git
cd gateshield-backend

pip install -r requirements.txt  //Install Dependencies

uvicorn protected_api.main:app --reload --port 8001  //Run Protected API

uvicorn gateway.main:app --reload --port 8000     //Run the Gateway

http://127.0.0.1:8000     //Open Dashboard
```

## 📌 Key Engineering Concepts Demonstrated
 - API Gateway design
 - Request inspection pipelines
 - Rule-based threat detection
 - Risk scoring systems
 - Stateful security (history-aware decisions)
 - Proxy forwarding
 - Observability and dashboards

## 💡 Future Improvements
 - Rate limiting per client/IP
 - API key authentication
 - Role-based access control
 - Persistent database (Postgres)
 - Machine learning–based anomaly detection
 - Distributed deployment

## 👤 Author
Pedro Ochoa
UC Berkeley — Computer Science
