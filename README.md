# ATERS — Ambulance Tracking and Emergency Response System

This project is an upgraded starting point based on the uploaded React/Vite ATERS project. It adds a persistent SQLite backend, server-side validation, authenticated staff sessions, role checks, audit events, dispatch workflows, ambulance and hospital records, and a public incident intake/reference lookup.

## Important safety boundary

**This is a production-oriented prototype, not a certified emergency-dispatch system. Do not use it to dispatch real ambulances or handle real patient information until it has been security-reviewed, load-tested, integrated with verified fleet/location systems, and approved by the responsible emergency-service operator.** The public form explicitly warns that it does not dispatch an ambulance. For a real emergency, users should contact their local emergency number. Demo hospital/fleet records are placeholders.

## Requirements
- Node.js 20 LTS or newer (Node 20+ recommended for Vite 6)
- npm
- Build tools required by `better-sqlite3` if a prebuilt binary is unavailable

## Install and run locally
```bash
npm install
npm run dev
```
Vite runs the front end (normally `http://localhost:5173`) and proxies `/api` requests to the backend at `http://localhost:3000`.

## Create the first administrator
In another terminal, run:
```bash
npm run create-admin
```
Enter a name, email, and a strong password of at least 12 characters. Do not use shared/default credentials. Then sign in via **Staff login** in the website.

The database is created in `./data/aters.sqlite` by default. To use another durable directory, set `ATERS_DATA_DIR`.

## Production build and start
```bash
npm run build
NODE_ENV=production npm start
```
The Express server serves the built React app and API from the same origin at `http://localhost:3000`.

For a real deployment:
1. Terminate TLS at a trusted reverse proxy or managed hosting provider.
2. Set `NODE_ENV=production` and store the SQLite directory on persistent encrypted storage with restricted OS permissions and tested backups.
3. Add monitoring, alerting, backup/restore drills, retention rules, incident response procedures, and an operational support plan.
4. Configure staff identity lifecycle, MFA/SSO, password reset, account disablement, and per-hospital scoping before exposing staff access publicly.
5. Integrate actual GPS hardware/mobile devices and validate freshness, authorization, spoofing defenses, location consent, and outage behavior. Current coordinates are editable manually and are not real-time GPS.
6. Review privacy and legal requirements for contact details and sensitive incident descriptions; establish access logs, minimization, retention and deletion policy.
7. Conduct independent security review and operational safety testing, including concurrency, failover, accessibility, and dispatcher workflow drills.

## Included capabilities
- Public incident form with field validation, rate limiting, and a generated reference ID
- Public status lookup by reference ID (limited fields only)
- Staff login with hashed passwords, HttpOnly/SameSite cookies, eight-hour sessions, and logout
- Role gates for admin, dispatcher, driver, and hospital
- Persistent incident, ambulance, hospital, user, session, and audit tables
- Dispatch assignment with ambulance availability checks and incident status transition validation
- Ambulance coordinate update endpoint and hospital capacity validation
- Audit events for key staff actions
- Responsive dashboard, incidents, fleet, hospitals, and audit view

## Current limitations / known gaps
- No actual ambulance GPS device integration, route optimization, reliable ETA, SMS/call gateway, push notifications, or hospital/EMS integration.
- No MFA, password reset, staff invite flow, automated account lockout, hospital-specific data scoping, or per-field permissions yet.
- No CSRF token mechanism; cookie SameSite strict and same-origin checks are basic mitigations, not a complete security assessment.
- Public reference lookup only returns status and timestamps; it is not proof of identity.
- SQLite is suitable for a small controlled pilot, not a high-availability multi-region emergency service. Use a managed relational database and tested failover for serious production use.
- Demo seed records use placeholder hospital and ambulance details and must be replaced.
- The dashboard refreshes periodically; it is not a guaranteed real-time feed.
