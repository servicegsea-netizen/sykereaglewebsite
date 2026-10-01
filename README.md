# G.S.E.A Syker Eagle — Production Website

Bilingual Arabic/French website with a production-oriented Node.js API for quote requests, contact messages and job applications.

## What is included

- Responsive Arabic RTL / French LTR website.
- Secure `/api/submitSiteForm` endpoint for all three forms.
- SQLite database in `data/gsea.sqlite`.
- CV uploads stored outside `public/` in `uploads/`.
- 8 MB CV limit with extension/MIME/signature checks.
- CSRF token, honeypot anti-bot field and API rate limiting.
- Helmet security headers and Content Security Policy.
- SMTP notifications to the company inbox; applicants can reply through the notification's Reply-To.
- SEO metadata, canonical URL, robots.txt, sitemap.xml, web manifest and JSON-LD local business data.
- Dockerfile and Docker Compose configuration.
- Backup script for database + CV storage.
- `/api/health` health endpoint.

## Requirements

- Node.js 20+ for direct deployment, or Docker.
- An SMTP account for email notifications.
- A domain pointing to the server/reverse proxy.

## Local setup

```bash
cp .env.example .env
npm install
npm start
```

Then open `http://localhost:3000`.

The forms are stored in SQLite even when SMTP is not configured. For production, configure SMTP before launch so every submission also triggers an email notification.

## Required production environment

Edit `.env` and set at minimum:

- `PUBLIC_BASE_URL=https://www.gsea.ma`
- `COMPANY_EMAIL=...`
- `SMTP_HOST=...`
- `SMTP_PORT=587`
- `SMTP_SECURE=false` (use `true` for providers requiring implicit TLS)
- `SMTP_USER=...`
- `SMTP_PASS=...`
- `SMTP_FROM=...`
- `IP_HASH_SALT=` — set a long random secret in production

Do not commit `.env`.

## Docker

```bash
docker compose up -d --build
```

Persistent Docker volumes keep `data/` and `uploads/` outside the container lifecycle.

## HTTPS / domain

The Node process listens on port 3000. Put it behind a managed HTTPS reverse proxy or hosting platform that provides TLS. Do not expose port 3000 directly to the public internet without a firewall/reverse proxy strategy.

The current public metadata uses `https://www.gsea.ma/` because that domain is already referenced by the website content. Change the canonical/OG/sitemap URLs if the final domain differs.

## Backups

Run periodically:

```bash
./scripts-backup.sh
```

Copy the resulting archive to separate storage. For a real production deployment, automate this daily and retain multiple historical copies.

## Email and CV security

CVs are never served by the static web server. They are written with restrictive permissions and randomized storage names. The server checks the uploaded document signature, but this is **not a malware scanner**. For high-volume recruitment, add ClamAV or a managed malware-scanning/object-storage pipeline before opening CV files.

## Before launch

1. Confirm the exact office address and Google Maps pin.
2. Replace the three sample testimonials with approved real testimonials, or remove them.
3. Configure SMTP and send test submissions for all three forms.
4. Verify the receiving mailbox, Reply-To behavior and CV attachment.
5. Configure HTTPS and the final domain.
6. Submit the sitemap in Google Search Console after DNS/HTTPS are live.
7. Set up automated off-server backups.
8. If recruitment traffic is significant, add malware scanning for CVs.
