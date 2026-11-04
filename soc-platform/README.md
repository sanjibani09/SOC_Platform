# Sentinel: AI-Powered SOC Platform

Sentinel is a small Security Operations Center (SOC) you can run on your own machine. It takes in login and file-access events, spots suspicious behavior with both hand-written rules and a machine learning model, and shows the results on a live dashboard where an analyst can work through each alert.

I built it to see how the pieces of a real SOC fit together: log ingestion, detection, risk scoring, incident handling, and an audit trail.

## What it does

- **Collects events** through a REST API (logins, file access, and similar activity).
- **Detects trouble in two ways:**
  - Rules, mapped to MITRE ATT&CK: repeated failed logins from one IP (T1110), activity at unusual hours (T1078), and unusually heavy file access (T1005).
  - An Isolation Forest model that scores how far an event is from normal behavior.
- **Scores risk** from 0 to 100 and labels each alert LOW, MEDIUM or HIGH.
- **Pushes alerts live** to the dashboard over WebSocket, so they appear without a refresh.
- **Lets analysts work incidents:** change an alert's status, add investigation notes, and browse the raw logs.
- **Keeps an audit trail** of administrative actions, and has two roles (ADMIN and ANALYST).

If the ML service is down, the backend keeps working and falls back to rule-only detection.

## Tech stack

| Part | Built with |
|---|---|
| Frontend | React, Vite, Tailwind CSS, Chart.js |
| Backend | Spring Boot (Java 21), Spring Security, JWT, BCrypt |
| ML service | Python, FastAPI, scikit-learn |
| Data | PostgreSQL (Flyway migrations), Redis |
| Simulator | Python script that generates harmless fake events |
| Packaging | Docker Compose (five containers) |

## How the pieces connect

```
Simulator / log source
        |
        v
   Spring Boot API  --->  ML service (Isolation Forest score)
     |        |
     |        +--> Redis (failed-login counters)
     v
 PostgreSQL (events, alerts, notes, audit)
     |
     v
  React dashboard  <--- live alerts over WebSocket
```

In Docker, the frontend's nginx proxies `/api` and `/ws` to the backend, so only one port needs to be open.

## Run it locally

You need Docker Desktop with Docker Compose v2. You do not need Java, Node or Python installed for this part.

1. Copy `.env.example` to `.env` and set your own values.
2. From the project folder, start everything:

   ```bash
   docker compose up -d --build
   ```

3. Open **http://localhost:5173** and sign in.

The first start creates an admin account from `SOC_ADMIN_EMAIL` and `SOC_ADMIN_PASSWORD` in your `.env` file.

Handy links while it runs:
- Backend health: http://localhost:8080/api/health
- ML service health: http://localhost:8000/health

## Try it with demo data

The simulator needs Python 3. It signs in as the admin account and sends fake events, so it needs your admin email and password.

```bash
pip install -r simulator/requirements.txt

python simulator/simulate.py --mode normal --count 30
python simulator/simulate.py --mode bruteforce --count 8 --delay 0.5
python simulator/simulate.py --mode offhours --count 2
python simulator/simulate.py --mode bulk --count 2
```

If you changed the admin credentials, add `--email you@example.com --password "your password"`. To point it at a deployed copy, add `--url http://<server>/api/logs/single`.

What you should see:

| Mode | Result |
|---|---|
| `normal` | Events appear in the Log Viewer, no alerts |
| `bruteforce` | MEDIUM alerts: "N failed logins from one IP in 5 minutes" |
| `offhours` | LOW alerts: activity at unusual UTC hours |
| `bulk` | HIGH alerts: heavy file access plus an ML anomaly score |

Keep the dashboard open while the simulator runs and new alerts will show up live. The simulator only sends synthetic data to your own instance. Brute-force mode is a detection test pattern, not an attack on anything real.

## Using the dashboard

- **Overview:** totals, severity breakdown, and recent alerts.
- **Alerts:** the full queue. Filter by severity, change an alert's status, or add a note.
- **Log Viewer:** every event that was ingested.
- **Users & Rules (admin):** change user roles and switch detection rules on or off.
- **Audit Trail (admin):** who changed what, and when.

## API reference

Sign in first, then send `Authorization: Bearer <token>` with every other request.

| Method | Route | Purpose |
|---|---|---|
| GET | `/api/health` | Backend health (no login needed) |
| POST | `/api/auth/register` | Create an ANALYST account |
| POST | `/api/auth/login` | Get a JWT |
| POST | `/api/logs/single` | Ingest one event |
| POST | `/api/logs` | Ingest a batch of events |
| GET | `/api/logs` | Recent events |
| GET | `/api/alerts` | Alert queue (optional severity and status filters) |
| GET | `/api/dashboard` | Dashboard numbers |
| PATCH | `/api/alerts/{id}/status` | Update an alert's status |
| POST, GET | `/api/alerts/{id}/notes` | Add or list investigation notes |
| GET | `/api/admin/users` | Admin: list users |
| PATCH | `/api/admin/users/{id}/role` | Admin: change a role |
| GET | `/api/admin/rules` | Admin: list detection rules |
| PUT | `/api/admin/rules/{id}` | Admin: enable or disable a rule |
| GET | `/api/admin/audit` | Admin: audit records |
| POST | `http://localhost:8000/score` | ML scoring service |

Quick example in PowerShell:

```powershell
$body = @{ email = "admin@soc.local"; password = "your password" } | ConvertTo-Json
$token = (Invoke-RestMethod -Method Post -Uri "http://localhost:8080/api/auth/login" -ContentType "application/json" -Body $body).token
Invoke-RestMethod -Uri "http://localhost:8080/api/alerts" -Headers @{ Authorization = "Bearer $token" }
```

### Event format

```json
{
  "timestamp": "2026-11-04T10:30:00Z",
  "sourceType": "LOGIN",
  "username": "analyst-demo",
  "ip": "198.51.100.23",
  "host": "workstation-01",
  "action": "login",
  "outcome": "FAILURE",
  "extra": { "filesAccessed": 0, "bytesTransferred": 0 }
}
```

`sourceType` can be `LOGIN`, `FILE`, `NETWORK` or `SYSTEM`. `outcome` is usually `SUCCESS` or `FAILURE`.

## Deploying to a server

A ready-made `docker-compose.prod.yml` exposes only port 80 and restarts containers automatically. On a Linux VM with Docker (at least 2 vCPU and 4 GB RAM is comfortable):

```bash
cp .env.example .env        # then edit it with strong secrets
docker compose -f docker-compose.prod.yml up -d --build
```

Before sharing the link:
- Set a strong `SOC_ADMIN_PASSWORD`, `POSTGRES_PASSWORD`, and a random `JWT_SECRET` (`openssl rand -base64 48`).
- Set `APP_CORS_ORIGIN` to your public URL.
- Keep the database, Redis and ML ports closed to the internet. The production file already does this.
- Remember that `/api/auth/register` is open, so anyone with the link can create an analyst account. Disable it if the site stays up.

## Project layout

```
backend/       Spring Boot API, security, detection logic, Flyway migrations
frontend/      React dashboard and its nginx config
ml-service/    FastAPI service and the Isolation Forest training script
simulator/     Fake event generator
docs/          Demo script and roadmap
docker-compose.yml        Local development
docker-compose.prod.yml   Server deployment
```

## Stop and reset

```bash
docker compose down        # stop, keep the data
docker compose down -v     # stop and delete the database too
```

Rebuild one service after changing its code, without losing data:

```bash
docker compose up -d --build backend frontend
```

## Limitations

This is a working demo and a learning project, not a production SOC.

- The ML model is trained on generated "normal" data, so it shows the idea but has not been validated on real traffic.
- Login tokens are kept in the browser's local storage, which is fine for a demo but not for production.
- The brute-force rule raises a new alert for each failed attempt past the threshold, instead of grouping them into one incident.
- Not built yet: two-factor login, WebSocket authentication, status-transition rules, automated tests, and precision/recall evaluation. See `docs/ROADMAP.md`.

Do not point this at real company data or production networks without a proper security review.
