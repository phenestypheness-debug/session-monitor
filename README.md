# Session Monitor

Standalone, invitation-only multi-user page-load monitor. Each account can run one background check for a public HTTP(S) URL: 57 isolated page visits per cycle, two minutes apart, repeating until stopped. It only loads pages; it does not click page controls or submit forms.

Use only websites you own or are authorized to monitor. Local, private, and reserved addresses, local hostnames, unsupported ports, and non-HTTP(S) URLs are blocked. Each account can only view and stop its own job and visit history. Passwords are stored as hashes; registration requires the service owner's invite code.

## Deploy on Render

1. Sign in to the Render account that should own the service.
2. Choose **New + → Blueprint**.
3. Connect GitHub and select `phenestypheness-debug/session-monitor`, branch `main`.
4. Review the Blueprint. It creates one paid **Starter** web service and a 1-GB persistent disk. Review Render's current charges before deploying.
5. Set `SIGNUP_INVITE_CODE` to a long, random, private value. Render generates `SECRET_KEY` and configures `DATABASE_PATH`.
6. Click **Apply** and wait for the Docker build and deployment.
7. Open the Render URL, create an account with the invite code, then sign in.
8. Enter a URL you are authorized to monitor and press **Start / update my check**. The job continues after sign-out. Press **Stop my check** to stop it.

Keep the service at one instance: the scheduler and SQLite database are designed for a single process with the attached disk. The scheduler reloads active jobs after service restarts. A free service may sleep or restart, so use the configured paid always-on service for background runs.

This repository is standalone and does not depend on the previous `2543ty/Automation` project.

## Run locally

Install dependencies and Chromium:

```powershell
python -m pip install -r requirements.txt
python -m playwright install chromium
```

Set configuration and start the app:

```powershell
$env:SECRET_KEY = "replace-with-a-long-random-secret"
$env:SIGNUP_INVITE_CODE = "set-a-private-invite-code"
$env:DATABASE_PATH = ".\session_monitor.db"
python app.py
```

Open `http://127.0.0.1:5000`. Do not commit secrets or the database file.
