# Deploying Sentinel on Vercel

The root `vercel.json` defines a frontend service, a containerized FastAPI
gateway, and a background event-consumer daemon. Vercel Services, Container
Runtime, and Daemons must be enabled for the Vercel account.

## Persistent services

Add managed PostgreSQL and Redis through the Vercel Marketplace. The app reads
`DATABASE_URL` (or `POSTGRES_URL`) and a Redis connection URL from
`SENTINEL_REDIS_URL`, `UPSTASH_REDIS_URL`, or `REDIS_URL`. The Redis URL must
use `rediss://` and include username/password credentials in production.

The SQLite database in the repository is local development data. Vercel
deployments use the managed PostgreSQL database and start with its own data;
copying existing local records requires a separate database migration.

## Environment variables

Set these in Vercel Project Settings for Preview and Production:

- `DATABASE_URL`: pooled PostgreSQL connection URL from the Vercel Marketplace
- `SENTINEL_REDIS_URL`: TLS Redis URL from the Vercel Marketplace
- `SECRET_KEY`: a newly generated, high-entropy application secret
- `SENTINEL_ENVIRONMENT`: `production`
- `SENTINEL_ALLOWED_HOSTS`: `*.vercel.app,*.vercel.sh,localhost,127.0.0.1`
- `SENTINEL_EVENT_TRANSPORTS`: `redis`

Set `SENTINEL_RUN_EVENT_WORKERS=false` in Production because the Vercel Daemon
owns the continuous event loops. Set it to `true` in Preview because Daemons
run only in Production during beta.

If you use a custom domain, add that hostname to
`SENTINEL_ALLOWED_HOSTS` before deploying it.
