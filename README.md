# CSC2031 – Secure Flask Application

## Overview
This project is part of the **CSC2031 Security Programming** module.

The starting point was a deliberately insecure Flask application designed to simulate common real-world web vulnerabilities. The task was to **identify, remediate, and justify security fixes** using secure coding practices in Python and Flask, with reference to the **OWASP Top 10** and **CWE Top 25** vulnerability lists.

---

## Development Philosophy
This project was developed with the principle that **code should communicate care, intent, and responsibility**.

The structure, naming, and separation of concerns are influenced by:
- **Bjarne Stroustrup** – writing code that is clear, direct, and respectful of the reader
- **Clean Code (Robert C. Martin)** – small, focused functions, meaningful naming, and explicit intent

Security decisions were implemented deliberately and documented to demonstrate *why* protections exist, not just *that* they exist.

---

## Security Objectives
The application was secured with the following goals:

- Identify and mitigate common web vulnerabilities
- Apply secure authentication and session management
- Enforce role-based authorisation
- Prevent injection and cross-site scripting attacks
- Implement defence-in-depth with monitoring and logging
- Avoid information leakage through error handling and configuration

---

## Key Security Measures Implemented

### Input Validation & Sanitisation
- WTForms validators for all user input
- Length, format, and logical constraints enforced
- HTML sanitisation using `bleach` for free-text fields
- Server-side validation only (client-side checks not trusted)

### Authentication & Session Management
- Passwords stored using secure hashing (`werkzeug.security`)
- Session fixation mitigation via session regeneration on login
- Secure session cookie configuration (`HttpOnly`, `SameSite`)
- Automatic session expiry after inactivity

### Authorisation & Route Protection
- Role-based access control using custom decorators
- Server-side enforcement (cannot be bypassed client-side)
- Clear separation between authentication and authorisation logic

### Injection & XSS Protection
- SQLAlchemy ORM used exclusively for database access
- Content Security Policy applied globally
- Jinja2 auto-escaping enabled by default
- Defensive sanitisation for stored user content

### CSRF Protection
- Flask-WTF CSRF protection enabled globally
- All state-changing actions require POST requests and CSRF tokens
- Logout implemented as a POST request

### HTTP Security Headers
- Content Security Policy (CSP)
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`
- `Strict-Transport-Security` (enabled outside debug mode)

### Secure Logging & Monitoring
- Dedicated security logger with rotating log files
- Logging of:
  - failed login attempts
  - brute-force suspicion
  - unauthorised access attempts
  - suspicious input patterns
- No sensitive data (passwords or secrets) written to logs

### Error Handling & Configuration
- Debug mode disabled
- Custom 403 / 404 / 500 error pages
- No stack traces or internal details exposed to users
- Environment-based configuration for secrets

---

## Architecture Overview
The project is structured to ensure security logic is **centralised, auditable, and maintainable**:

- `app/main/` – application routes
- `app/security/` – decorators, logging, monitoring, repositories
- `app/forms/` – WTForms validation and sanitisation
- `app/models.py` – database models
- `config.py` – secure configuration
- `static/` and `templates/` – presentation layer

---

## Use of Generative AI
Generative AI tools were used to **support understanding of Flask security concepts**, architectural patterns, and documentation clarity.

All code was:
- reviewed manually
- adapted to the project requirements
- written to reflect the author’s understanding
- structured to prioritise clarity, security, and maintainability

No code was submitted without comprehension or critical evaluation.

## Author
**Gabriel Erzah**  
CSC2031 – Security Programming  
Newcastle University

---

## Running the Application
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 run.py


