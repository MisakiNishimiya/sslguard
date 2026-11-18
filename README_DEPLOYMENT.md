# SSLGuard Deployment Guide

## 🚀 Free Deployment Options

### Option 1: Railway.app (RECOMMENDED)

**Free Tier**: 500 hours/month (~20 days uptime) + $5 credit

**Steps**:
1. Go to [railway.app](https://railway.app)
2. Sign in with GitHub
3. Click "New Project" → "Deploy from GitHub repo"
4. Select your `sslguard` repository
5. Railway auto-detects Python and deploys!

**Configure Environment Variables**:
- Go to your project → Variables tab
- Add these:
  ```
  SSLGUARD_SECRET_KEY=<generate-random-32-char-string>
  FLASK_ENV=production
  SMTP_SERVER=smtp.gmail.com
  SMTP_PORT=587
  SMTP_USERNAME=your-email@gmail.com
  SMTP_PASSWORD=your-app-password
  ```

**Create Admin User**:
```bash
# In Railway dashboard, go to project → Settings → Connect
railway run python create_admin.py
```

---

### Option 2: Render.com

**Free Tier**: 750 hours/month (sleeps after 15 min inactivity)

**Steps**:
1. Go to [render.com](https://render.com)
2. Sign in with GitHub
3. Click "New +" → "Web Service"
4. Connect your GitHub repo
5. Configure:
   - **Name**: sslguard
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn wsgi:application`
   - **Environment**: Add variables (same as Railway)

⚠️ **Note**: Free tier sleeps after 15 min. First request takes 30-60s to wake up.

---

### Option 3: Fly.io

**Free Tier**: 3 small VMs, 160GB bandwidth

**Steps**:
1. Install Fly CLI: `curl -L https://fly.io/install.sh | sh`
2. Sign up: `fly auth signup`
3. Deploy:
   ```bash
   cd sslguard
   fly launch
   # Follow prompts, select region
   fly deploy
   ```

---

## 🔐 Security Checklist

Before deploying:
- [ ] Change `SSLGUARD_SECRET_KEY` to random 32+ character string
- [ ] Set `FLASK_ENV=production`
- [ ] Never commit `.env` file (it's in `.gitignore`)
- [ ] Use strong admin password
- [ ] Configure SMTP with app-specific password (not main password)

---

## 🗄️ Database

**SQLite** (default):
- ✅ Works out of the box
- ❌ Data lost on restart (Railway/Render don't persist files)

**PostgreSQL** (recommended for production):
- Railway: Automatically provides PostgreSQL (free)
- Render: Add PostgreSQL service (free)
- Fly.io: Can add managed Postgres

Railway will set `DATABASE_URL` automatically if you add PostgreSQL.

---

## 👤 Creating First Admin User

**After deployment**:

**Railway**:
```bash
railway run python create_admin.py
```

**Render** (use SSH from dashboard):
```bash
python create_admin.py
```

**Or use Render's console**: Go to your service → Shell → run the command

---

## 🔄 Auto-Deploy from GitHub

Both Railway and Render auto-deploy when you push to `main` branch:

```bash
git add .
git commit -m "Update feature"
git push origin main
# Automatically deploys!
```

---

## 📊 Monitoring

**Railway**: Project → Metrics (CPU, Memory, Bandwidth)
**Render**: Service → Metrics tab
**Fly.io**: `fly logs` command

---

## 💰 Cost Breakdown

| Platform | Free Tier | Paid Tier | Best For |
|----------|-----------|-----------|----------|
| Railway | 500 hrs/mo | $5/mo (24/7) | Best overall |
| Render | 750 hrs/mo (sleeps) | $7/mo (no sleep) | Side projects |
| Fly.io | 3 VMs | $2-5/mo | Advanced users |

---

## 🐛 Troubleshooting

**App won't start**:
- Check logs in platform dashboard
- Verify all environment variables are set
- Make sure `requirements.txt` is correct

**Database errors**:
- Railway: Make sure PostgreSQL plugin is added
- Check `DATABASE_URL` is set correctly

**Can't login**:
- Make sure you created admin user: `python create_admin.py`
- Check logs for authentication errors

---

## 📞 Support

- Railway: [Discord](https://discord.gg/railway)
- Render: [Community Forum](https://community.render.com)
- Fly.io: [Community Forum](https://community.fly.io)
