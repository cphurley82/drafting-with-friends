# Drafting With Friends

Drafting With Friends is a web application for running remote Magic: The Gathering drafts. The current codebase uses Flask and SQLAlchemy to host configurable pick-one or pick-two draft tables and serves a Vintage Cube card list.

This guide walks through deploying the application to Google Cloud Run so you can host the service for your playgroup. Cloud Run builds the project from source, runs it in a managed container, and can connect to a managed Cloud SQL database for persistent storage.

## Prerequisites

Before you deploy, make sure you have:

- A Google Cloud project with billing enabled.
- The [Google Cloud CLI](https://cloud.google.com/sdk/docs/install) installed and initialized (`gcloud init`).
- The Cloud Run, Cloud Build, and Cloud SQL Admin APIs enabled: `gcloud services enable run.googleapis.com sqladmin.googleapis.com cloudbuild.googleapis.com`.
- A Cloud SQL instance running PostgreSQL 13+ or MySQL 8+ (examples below assume PostgreSQL).

## Configure your database

1. **Create a database and user.** In the Cloud Console or via `gcloud sql`, create a database (e.g. `drafting`) and a user with a strong password.
2. **Allow Cloud Run to connect.** If you will connect over the Cloud SQL proxy, note the instance connection name (`PROJECT:REGION:INSTANCE`). For public IP connections, add an authorized network for Cloud Build (optional) and Cloud Run if required.
3. **Construct the SQLAlchemy URL.** Use the form `postgresql+pg8000://USERNAME:PASSWORD@/DATABASE?host=/cloudsql/INSTANCE_CONNECTION_NAME` when using the Cloud SQL proxy sidecar that Cloud Run provides. For public IPs, replace the host query parameter with `@HOST:PORT`.

## Prepare the environment variables

The service relies on two environment variables:

- `DWF_SECRET_KEY`: an arbitrary secret string used to sign session cookies. Generate one with `python -c "import secrets; print(secrets.token_hex(32))"`.
- `DATABASE_URL`: an SQLAlchemy database URL pointing at your Cloud SQL instance (see above).

Store these values so you can pass them to Cloud Run during deployment.

## Deploy to Cloud Run from source

Cloud Run can build the container image directly from this repository.

```bash
# Set up some helpers
PROJECT_ID="your-gcp-project"
REGION="us-central1"            # choose any Cloud Run region
SERVICE_NAME="drafting-with-friends"
INSTANCE="project:region:instance"  # Cloud SQL instance connection name

# Deploy straight from the current directory
gcloud run deploy "$SERVICE_NAME" \
  --source . \
  --region "$REGION" \
  --project "$PROJECT_ID" \
  --set-env-vars DWF_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')" \
  --set-env-vars DATABASE_URL="postgresql+pg8000://USER:PASSWORD@/drafting?host=/cloudsql/$INSTANCE" \
  --add-cloudsql-instances "$INSTANCE" \
  --allow-unauthenticated
```

The command above performs three tasks:

1. Uploads the source to Cloud Build, which uses Google Cloud Buildpacks to produce a container image (the buildpack installs dependencies from `requirements.txt`).
2. Deploys that image to Cloud Run and wires up the Cloud SQL connection.
3. Configures runtime environment variables so the app can secure sessions and reach the database.

When the service starts for the first time it automatically creates the required tables via SQLAlchemy's `Base.metadata.create_all` call in `app.py`.

## Verify the deployment

After deployment completes, Cloud Run prints a service URL. Visit that URL in your browser and create an account to confirm the application is reachable. Any persistent draft or user data will be stored inside the Cloud SQL database configured above.

If you need to update the service later, rerun the same `gcloud run deploy` command from the repository root to rebuild and redeploy the latest code.

## Optional: local development

You can experiment locally before deploying:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export FLASK_APP=app:create_app
export DWF_SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')
export DATABASE_URL=sqlite:///local.db
flask run
```

The local run uses SQLite by default; delete `local.db` between test runs if you want a clean slate.

## Hosting from a home network (e.g., Raspberry Pi behind NAT)

If you prefer to self-host for friends without using a cloud provider, you can run the Flask application on a small computer
like a Raspberry Pi and expose it over the internet. The high-level workflow is:

1. **Provision the Pi.** Install a 64-bit Raspberry Pi OS (Lite is fine) and apply system updates (`sudo apt update && sudo apt
   upgrade`). Install Python 3.10+ and build tooling: `sudo apt install python3 python3-venv build-essential libpq-dev`.
2. **Clone the repository and set up the virtual environment.**

   ```bash
   git clone https://github.com/your-user/drafting-with-friends.git
   cd drafting-with-friends
   python3 -m venv .venv
   source .venv/bin/activate
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

3. **Choose a database.** For a few friends, SQLite is sufficient. For better durability, install PostgreSQL on the Pi and use
   a local Unix socket connection (e.g. `postgresql+psycopg://draft:password@/drafting`). Whichever backend you pick, export the
   `DATABASE_URL` and `DWF_SECRET_KEY` environment variables.
4. **Run a production server.** Use Gunicorn to serve Flask on an internal port:

   ```bash
   export FLASK_APP=app:create_app
   export DWF_SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')
   export DATABASE_URL=sqlite:////home/pi/drafting-with-friends/drafting.db  # or your PostgreSQL URL
   exec gunicorn "app:create_app()" --bind 0.0.0.0:8000 --workers 2
   ```

   You can wrap this command in a `systemd` unit (e.g. `/etc/systemd/system/dwf.service`) so it restarts on boot or crashes.
5. **Expose the service through NAT.** There are two common approaches:

   - **Port forwarding:** Log in to your router and forward external TCP port 80/443 (or an alternate port) to the Pi’s IP and
     Gunicorn port (8000). Combine this with a dynamic DNS record (DuckDNS, No-IP, etc.) so friends can reach your home IP. Use
     a lightweight reverse proxy such as Caddy or nginx on the Pi to terminate HTTPS certificates from Let’s Encrypt.
   - **Reverse tunnels:** If your ISP blocks inbound connections or you prefer not to manage port forwarding, run a tunnel such
     as [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/) or
     [Tailscale Funnel](https://tailscale.com/kb/1223/funnel) on the Pi. These services create an outbound connection from your
     network and provide a public URL that forwards traffic securely to Gunicorn.

6. **Harden and monitor.** Create a dedicated `dwf` user on the Pi, keep the OS patched, and watch logs (`journalctl -u dwf`)
   for crashes or suspicious traffic. Because the application handles logins, ensure the `DWF_SECRET_KEY` stays private and
   encourage friends to use strong passwords.

With these steps, you can run Drafting With Friends from your home hardware while still providing a stable URL for remote
players. The same application code works whether it’s hosted locally or in the cloud.

## Troubleshooting

- **Authentication errors to Cloud SQL:** Ensure the Cloud Run service account has the `Cloud SQL Client` role and that you passed `--add-cloudsql-instances` with the correct connection name.
- **Build failures:** Verify `requirements.txt` includes all dependencies and that the repository contains no stray system-specific artifacts.
- **HTTP 500 responses:** Check the Cloud Run logs (`gcloud logs read --project "$PROJECT_ID" --region "$REGION" --service "$SERVICE_NAME"`) for stack traces. Most errors during startup relate to a misconfigured `DATABASE_URL` or missing migrations (the app will create tables automatically, so mismatched credentials are the usual culprit).

With these steps you can host Drafting With Friends in the cloud and invite friends to draft together again.
