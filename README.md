# ANA-Quest (Local Web App)

A local, dependency-free habit tracker for Anaaya with child/parent login, parent approvals, and editable scoring/reward settings.

## Run locally

```bash
python3 app.py
```

Then open:

- `http://127.0.0.1:8000`

## Mobile + PWA

- The app now includes a web manifest and service worker.
- On mobile browsers that support install prompts, you can add it to the home screen as an app.
- PWA assets are served at:
  - `/manifest.webmanifest`
  - `/sw.js`
  - `/icon.svg`

## Publish Online (Simple Beginner Path)

This app can be published with **GitHub + Render**.

### Step 1: Put this project on GitHub

1. Create a new private repository on GitHub (example name: `ana-quest`).
2. Upload all files from this folder to that repository.
3. Make sure these files are included:
   - `app.py`
   - `render.yaml`
   - `README.md`

### Step 2: Create the online app on Render

1. Go to [https://render.com](https://render.com) and sign in.
2. Click **New** -> **Blueprint**.
3. Connect your GitHub account and select your `ana-quest` repository.
4. Click **Apply** / **Create**.
5. Wait for deploy to finish.

Render will read `render.yaml` and automatically set:
- start command
- secure cookie setting
- secret key
- persistent disk for the database

### Step 3: Open your live link

After deploy, Render gives you a URL like:
- `https://ana-quest.onrender.com`

Open it on desktop or mobile and log in.

### Step 4 (optional): Add your own domain

In Render service settings:
1. Open **Custom Domains**
2. Add your domain (example: `anaquest.yourdomain.com`)
3. Follow the DNS steps shown by Render

### Important notes for online use

- Keep `SECURE_COOKIES=1` in production (already set in `render.yaml`).
- Keep `ANAQUEST_SECRET` private (Render auto-generates one).
- Database is saved on Render disk via:
  - `ANAQUEST_DB_PATH=/opt/render/project/data/habit_tracker.db`
- If you redeploy, your data stays on that disk.

## Login flow

When the app opens, choose a role and enter password.

Default first-run passwords:

- Child: `anaaya123`
- Parent: `parent123`

Parent can change both passwords in **Parent -> General Settings -> Passwords**.

## What this version does

- Login gate with role selection (`Anaaya` or `Parent`)
- Child submits daily goal status with selected score option
- Parent approves/rejects submissions (with optional note)
- Parent edits:
  - Goal names
  - Goal scoring options and points
  - Reward tiers (Bronze/Silver/Gold minimum points + reward text)
  - App name and child name
  - Passwords
- Progress Report page (`/progress`) with:
  - Current week score and level progress
  - Day-by-day weekly point bars
  - 8-week trend chart
  - Dynamic background mood based on current progress
- Parent-only reset action to clear all progress entries and start fresh
- Weekly approved points + current level shown on child and parent views

## Default goals preloaded

1. Get ready on time in the morning
2. Lunch finished on time (20/15/10/0 tiered points)
3. Dinner finished on time (20/15/10/0 tiered points)
4. Sleep on time at night
5. Room clean before sleeping

## Data storage

All data is stored in:

- `habit_tracker.db`

Delete this file to reset data.

## Local now, online later

The app runs locally today (single Python file + SQLite). Later, this can be moved online by hosting behind a production web server and setting a strong `ANAQUEST_SECRET` environment variable.
