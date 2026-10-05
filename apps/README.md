# Pencheff — Web API + Neo-Brutalism UI

This directory adds a SaaS-ready web product on top of the existing
`plugins/pencheff` MCP engine. The engine is reused as a library — no
changes needed. Everything new lives here:

```
apps/
├── api/        FastAPI + Celery + SQLAlchemy (async) + Alembic
└── web/        Next.js 15 (App Router) + Tailwind + neo-brutalism UI
```

## Quick start (Docker)

```bash
# From the repo root
cp apps/api/.env.example apps/api/.env     # already committed with dev defaults
cp apps/web/.env.local.example apps/web/.env.local

docker compose up --build
```

Then open **http://localhost:3000**.

- Sign up with email+password, or configure Google OAuth via env.
- Click **Register Target**, paste a URL (+ optional creds), pick a profile,
  hit go.
- Watch the scan stream live (server-sent events from the Celery worker).
- Triage findings, click **Recheck** to re-run the narrowest scanner against
  a single finding, mark items fixed/false-positive, suppress with a reason.
- Click **Generate report** to download DOCX / PDF / CSV / JSON. The DOCX
  and PDF reports are formatted for SOC 2 audit evidence packages.

## Local dev (without Docker)

Requires: Python 3.12, Node 20, Postgres, Redis.

```bash
# API
cd apps/api
python -m venv .venv && source .venv/bin/activate
pip install -e ../../plugins/pencheff
pip install -e '.[dev]'
alembic upgrade head
uvicorn pencheff_api.main:app --reload --port 8000

# Worker (separate shell)
celery -A pencheff_api.tasks.celery_app.celery_app worker --loglevel=info --concurrency=2

# Web (separate shell)
cd apps/web
npm install --legacy-peer-deps
npm run dev
```

## Environment

All API config is in `apps/api/.env`. The critical keys:

| var | purpose |
|---|---|
| `DATABASE_URL` | async SQLAlchemy URL (`postgresql+asyncpg://…`) |
| `REDIS_URL` | Celery broker + SSE pub/sub |
| `JWT_SECRET` | signs access/refresh tokens |
| `FERNET_KEY` | encrypts stored target credentials. Generate with `python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'`. If blank, a dev key is derived from `JWT_SECRET` — do NOT use in production. |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | OAuth. Optional. |
| `STRIPE_*` | billing. Optional. |

## API surface (summary)

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/auth/signup` | email + password |
| `POST` | `/auth/login` | returns JWT pair |
| `POST` | `/auth/refresh` | rotate tokens |
| `GET`  | `/auth/me` | current user |
| `GET`  | `/auth/oauth/google/start` | begin Google OAuth |
| `GET`  | `/auth/oauth/google/callback` | finalize → redirects to web |
| `GET`  | `/targets` · `POST` `/targets` · `DELETE` `/targets/{id}` | target CRUD |
| `POST` | `/scans` | start a scan (returns `scan_id`) |
| `GET`  | `/scans` · `/scans/{id}` | list / detail |
| `GET`  | `/scans/{id}/stream` | SSE live progress (`?token=…` for EventSource) |
| `GET`  | `/findings?scan_id=…` | findings for a scan |
| `POST` | `/findings/{id}/recheck` | re-run the scanner for this finding |
| `POST` | `/findings/{id}/status` | set `fixed` / `true_positive` / `false_positive` |
| `POST` | `/findings/{id}/suppress` · `/unsuppress` | suppression lifecycle |
| `POST` | `/scans/{id}/reports` | generate DOCX/PDF/CSV/JSON |
| `GET`  | `/reports/{id}/download` | stream the file |
| `POST` | `/billing/checkout?plan=pro` | Stripe Checkout URL |
| `POST` | `/billing/webhook` | Stripe webhook receiver |

## Grading

`services/grader.py`. Deterministic, documented:

```
weights = {critical:40, high:15, medium:5, low:1, info:0}
score   = max(0, 100 - sum(weights[f] for f unsuppressed))
grade   = A >=90, B >=80, C >=65, D >=50, else F
# A or B + any unsuppressed critical → forced to C
```

## Self-hosting

The stack is a standard four-service Compose app (postgres, redis, api,
worker, web). There's no hard SaaS dependency:

- Billing is optional — omit `STRIPE_*` vars, set org plan to `self_hosted`
  in the DB to unlock unlimited quotas (`services/quota.py`).
- Google OAuth is optional — email+password works alone.
- Reports are written to the `reports` volume (`/tmp/pencheff-reports`).

## Testing

```bash
cd apps/api
pytest tests
```

The web app has no automated UI tests yet — see the plan for Playwright
e2e coverage as a follow-up.

## Neo-brutalism tokens

`apps/web/tailwind.config.ts` + `styles/globals.css`:

- colors: `ink` #0A0A0A, `paper` #FDFBF5, `lemon` #FFD23F, `hotpink` #FF3E88,
  `cyan` #00E0D4, `lime` #C6F432, `danger` #FF2E2E
- shadows: `shadow-brutal` = `6px 6px 0 0 #0A0A0A` (+ `brutalSm`, `brutalLg`)
- components: `Button`, `Card`, `Input`, `Label`, `Badge`, `SeverityPill`,
  `GradeBadge` in `components/brutal.tsx`
