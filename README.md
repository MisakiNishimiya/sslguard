# 🔐 SSLGuard - TLS Certificate Monitoring System

A professional web application for monitoring SSL/TLS certificate expiry and managing certificate lifecycle.

![SSLGuard Dashboard](https://img.shields.io/badge/Status-Production%20Ready-brightgreen)
![Python](https://img.shields.io/badge/Python-3.11+-blue)
![Flask](https://img.shields.io/badge/Flask-3.1-lightgrey)
![License](https://img.shields.io/badge/License-MIT-yellow)

## ✨ Features

- 📊 **Real-time Dashboard** - Monitor all domains at a glance with severity badges
- 🔔 **Smart Alerts** - Email notifications for expiring certificates (30, 14, 7, 1 day thresholds)
- 📅 **Automated Scanning** - Schedule daily scans for all monitored domains
- 📈 **Certificate Status** - Track expired, critical, warning, and valid certificates
- 📄 **Reports** - Export CSV/PDF remediation reports
- 👥 **User Management** - Role-based access (Admin, Viewer)
- 🎨 **Professional UI** - Bootstrap 5 with responsive design
- 🔐 **Secure** - Flask-Login authentication, password hashing, session management

## 🚀 Quick Start

### Local Development

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/sslguard.git
cd sslguard

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Create environment file
cp .env.example .env
# Edit .env and set your SECRET_KEY

# Create admin user
python create_admin.py

# Run application
python app.py
```

Visit: `http://127.0.0.1:8000`

## 🌐 Deployment

**Free Deployment Options**:
- ⭐ [Railway.app](https://railway.app) - 500 hrs/month free
- [Render.com](https://render.com) - 750 hrs/month free  
- [Fly.io](https://fly.io) - 3 VMs free

👉 **See [README_DEPLOYMENT.md](README_DEPLOYMENT.md) for detailed deployment instructions**

## 📋 Requirements

- Python 3.11+
- Flask 3.1+
- SQLAlchemy (SQLite or PostgreSQL)
- APScheduler for automated scans
- SMTP server for email alerts

## 🔧 Configuration

Edit `.env` file:

```bash
SSLGUARD_SECRET_KEY=your-secret-key-here
FLASK_ENV=production
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
```

## 📖 Usage

1. **Add Domains**: Click "Add Domain" → Enter hostname, port, owner
2. **Scan Certificates**: Click "Scan" on individual domains or "Scan All"
3. **Monitor Status**: Dashboard shows color-coded certificate status
4. **View History**: Click "History" to see scan timeline
5. **Export Reports**: Generate CSV/PDF reports with remediation steps
6. **Manage Users**: Admin can add/edit/delete users with different roles

## 🎨 Pages

- **Dashboard** - Overview of all certificates with filters and search
- **Domains** - Manage monitored domains (add/edit/delete)
- **Reports** - Export reports and view common issues
- **Users** - User management (admin only)

## 🔐 Security Features

- ✅ Password hashing with Werkzeug
- ✅ Flask-Login session management
- ✅ CSRF protection
- ✅ Environment-based secrets
- ✅ Role-based access control
- ✅ Secure password reset (placeholder)

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📝 License

MIT License - See LICENSE file for details

## 👨‍💻 Author

Built with ❤️ for certificate lifecycle management

## 🐛 Known Issues

- Password reset feature requires email configuration
- User disable/enable needs database migration (see TODO in code)

## 🗺️ Roadmap

- [ ] Add 2FA authentication
- [ ] Implement password reset via email
- [ ] Add Slack/Teams webhook notifications
- [ ] Certificate chain validation
- [ ] Multi-tenant support
- [ ] API for external integrations

## 📞 Support

For issues and questions:
- Open an issue on GitHub
- Check [README_DEPLOYMENT.md](README_DEPLOYMENT.md) for deployment help
- See [STYLE_GUIDE.md](STYLE_GUIDE.md) for UI component usage

---

⭐ Star this repository if you find it useful!
