# 🔐 Secure Web Application

This is a simple Flask-based web application designed to demonstrate common web security vulnerabilities and how to mitigate them. Built as part of a hands-on security course project.

---

## 🚀 Features

- User registration and login
- Role-based access (admin vs regular user)
- Comment submission with XSS protection
- SQL Injection demo and fix
- Secure password storage (bcrypt)
- Local HTTPS with TLS/SSL encryption

---

## ⚠️ Demonstrated Vulnerabilities

| Vulnerability       | Status  | Fixed With         |
|---------------------|---------|--------------------|
| SQL Injection        | ✅ Simulated + Fixed | ORM parameterized queries |
| Weak Password Storage | ✅ Simulated + Fixed | bcrypt hashing |
| Cross-Site Scripting (XSS) | ✅ Simulated + Fixed | HTML escaping (no `|safe`) |
| Access Control       | ✅ Implemented         | Role checking + `@login_required` |
| TLS/SSL Encryption   | ✅ Simulated           | Self-signed cert with OpenSSL |

---

## 💻 How to Run

### 1. Clone the Repo

```bash
git clone https://github.com/manal-ak/secure-web-app.git
cd secure-web-app
