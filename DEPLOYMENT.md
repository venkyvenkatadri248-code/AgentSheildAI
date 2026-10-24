# AgentShieldAI — Production Deployment & Hosting Guide

This guide covers all recommended methods to deploy and host the **AgentShieldAI** platform, from 1-click Docker setups on a VPS to modern cloud PaaS hosting (Vercel + Render / Railway / Supabase).

---

## 📋 Architecture Overview

AgentShieldAI is comprised of three core components:
1. **Frontend**: React 19 + TypeScript + Vite SPA served via Nginx (or Vercel / Netlify).
2. **Backend**: Python 3.11 FastAPI application running on Uvicorn with WebSocket support (`/ws`) and SSE (`/messages/stream`).
3. **Database**: PostgreSQL 16 (or SQLite for small local testing). Schema creation and default accounts (`admin@agentshield.ai`) are automatically initialized on application startup.

---

## 🚀 Option 1: Docker Compose on VPS / Cloud Server (Recommended)

Best for: **DigitalOcean Droplet, AWS EC2, Linode, Hetzner, GCP Compute Engine, or Ubuntu VM.**

### Step 1: Provision Server & Install Docker
On your Ubuntu/Debian server:
```bash
sudo apt-get update
sudo apt-get install -y docker.io docker-compose curl git
sudo systemctl enable --now docker
```

### Step 2: Clone Repository & Configure Environment
```bash
git clone <your-repo-url> /opt/agentshieldai
cd /opt/agentshieldai

# Create production environment file
cp .env.example .env
nano .env
```

Set your production variables in `.env`:
```env
APP_ENV=production
APP_NAME=AgentShieldAI

# PostgreSQL credentials
DATABASE_URL=postgresql+psycopg://app_user:YourStrongPassword123@db:5432/agentshieldai

# Google Gemini API Key from Google AI Studio
GEMINI_API_KEY=AIzaSy...
GEMINI_MODEL=gemini-1.5-flash

# Frontend URL (domain name or server IP)
FRONTEND_ORIGIN=https://shield.yourdomain.com

# 64-char random secret for JWT
AUTH_SECRET_KEY=9a8f7c6e5d4b3a210fedcba9876543210123456789abcdef0123456789abcdef
```

### Step 3: Launch with Docker Compose
```bash
docker-compose up --build -d
```

Check container health:
```bash
docker-compose ps
docker-compose logs -f backend
```

Your services are live:
- Frontend & Reverse Proxy: `http://<SERVER_IP>:80`
- Backend API & Swagger: `http://<SERVER_IP>:8000/docs`
- Health check: `http://<SERVER_IP>:8000/health`

### Step 4: Add Free HTTPS (Let's Encrypt / Certbot)
If you have a domain pointing to your server, set up Nginx with Certbot:
```bash
sudo apt-get install -y certbot python3-certbot-nginx
```
Point Nginx to port 80 of the Docker frontend container, or run Certbot directly with your domain.

---

## ☁️ Option 2: Cloud PaaS (Frontend on Vercel + Backend on Render / Railway)

Best for: **Serverless scaling, automated CI/CD git deploys, and free/low-cost tiers.**

### 1. Database (Neon / Supabase / Railway Postgres)
1. Create a free PostgreSQL database at [Neon.tech](https://neon.tech) or [Supabase.com](https://supabase.com).
2. Copy the connection string. Ensure it uses `postgresql+psycopg://`:
   ```
   postgresql+psycopg://user:password@ep-cool-db.us-east-2.aws.neon.tech/agentshieldai?sslmode=require
   ```

### 2. Backend Deployment (Render or Railway)

#### On Render.com:
1. Click **New +** &rarr; **Web Service**.
2. Connect your GitHub repository.
3. Configure settings:
   - **Root Directory**: `backend`
   - **Environment**: `Docker` (Render will automatically detect `backend/Dockerfile`)
   - Or **Python 3**:
     - **Build Command**: `pip install -r requirements.txt`
     - **Start Command**: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
4. Set Environment Variables:
   - `APP_ENV`: `production`
   - `DATABASE_URL`: `postgresql+psycopg://...`
   - `GEMINI_API_KEY`: `<Your_Google_AI_Studio_Key>`
   - `GEMINI_MODEL`: `gemini-1.5-flash`
   - `AUTH_SECRET_KEY`: `<Generate_Random_64_Char_Key>`
   - `FRONTEND_ORIGIN`: `https://your-frontend.vercel.app`
5. Click **Deploy Web Service**.
6. Note your backend URL (e.g., `https://agentshield-backend.onrender.com`).

### 3. Frontend Deployment (Vercel)
1. Import repository on [Vercel.com](https://vercel.com).
2. Set **Root Directory** to `frontend`.
3. Framework Preset: **Vite**.
4. Add Environment Variables:
   - `VITE_API_BASE_URL`: `https://agentshield-backend.onrender.com/api`
   - `VITE_WS_URL`: `wss://agentshield-backend.onrender.com/ws`
5. Click **Deploy**.
   *(SPA client routes like `/agents`, `/chat`, and `/alerts` are automatically routed thanks to `vercel.json`).*

---

## 🐧 Option 3: Traditional Bare-Metal / Linux VM (Systemd + Nginx)

Best for: **Dedicated servers without Docker.**

### 1. Backend Service (`/etc/systemd/system/agentshield-backend.service`)
```ini
[Unit]
Description=AgentShieldAI FastAPI Backend
After=network.target postgresql.service

[Service]
User=www-data
WorkingDirectory=/var/www/agentshieldai/backend
EnvironmentFile=/var/www/agentshieldai/.env
ExecStart=/var/www/agentshieldai/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
```
Start service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now agentshield-backend
```

### 2. Frontend Build
```bash
cd /var/www/agentshieldai/frontend
npm ci
npm run build
# Files will be in /var/www/agentshieldai/frontend/dist
```

### 3. Nginx Server Block (`/etc/nginx/sites-available/agentshield`)
```nginx
server {
    listen 80;
    server_name shield.yourdomain.com;

    # Static frontend assets
    location / {
        root /var/www/agentshieldai/frontend/dist;
        index index.html;
        try_files $uri $uri/ /index.html;
    }

    # API endpoints
    location /api/ {
        proxy_pass http://127.0.0.1:8000/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket real-time monitor
    location /ws {
        proxy_pass http://127.0.0.1:8000/ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
    }
}
```
Enable and reload:
```bash
sudo ln -s /etc/nginx/sites-available/agentshield /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d shield.yourdomain.com
```

---

## 🔑 Environment Variables Reference

| Variable | Default / Example | Purpose |
| :--- | :--- | :--- |
| `APP_ENV` | `production` | Switches app from dev mode to strict CORS security |
| `DATABASE_URL` | `postgresql+psycopg://...` | Database connection string |
| `GEMINI_API_KEY` | `AIzaSy...` | Google AI Studio Gemini API key |
| `GEMINI_MODEL` | `gemini-1.5-flash` | Gemini model name (`gemini-1.5-flash`, `gemini-1.5-pro`) |
| `FRONTEND_ORIGIN` | `https://shield.yourdomain.com` | Allowed CORS origins (comma-separated for multiple) |
| `AUTH_SECRET_KEY` | *(64-character random string)* | Secret for signing JWT authentication tokens |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `1440` (24h) | Token lifespan |
| `UPLOAD_DIR` | `./uploads` | Persistent directory for document uploads |
| `VITE_API_BASE_URL` | `/api` *(or full URL for split hosting)* | Target API endpoint for frontend |
| `VITE_WS_URL` | `wss://...` *(or automatic host derivation)* | WebSocket endpoint for live monitoring |

---

## 👥 Default Seed Accounts

The platform automatically seeds initial administrator and analyst credentials on first run:
- **Admin**: `admin@agentshield.ai` / `Admin@123456`
- **SOC Analyst**: `analyst@analyst.ai` (or `analyst@agentshield.ai`) / `Analyst@123456`

> **Security Tip**: Once deployed to production, log in to the web console and navigate to **Settings** to rotate default administrative passwords.
