# Linode Setup + Deployment Log (Step-by-Step for Beginners)

This file is a **copy/paste checklist + command guide** to get this exact repo running on your fresh Linode server and live on your domain.

---

## 0) What you are setting up (plain English)

You will do 5 things:
1. Connect to your Linode over SSH.
2. Install required software (Python, Git, Nginx).
3. Copy this repo onto the server.
4. Run the app in the background with `systemd`.
5. Put Nginx in front so your domain points to the app on port 80 (and then add HTTPS).

Your server info:
- Linode IP: `172.237.131.20`
- Your domain A record: already pointed to this IP ✅

---

## 1) Before you start

### 1.1 On your local machine, make sure you can open a terminal
- macOS: Terminal app
- Windows: PowerShell (or Windows Terminal)

### 1.2 You need one of these to log into Linode
- **Best:** SSH key already added to Linode at create time.
- **Alternative:** root password from Linode dashboard.

### 1.3 Know your Git repo URL
You need a clone URL, such as:
- HTTPS: `https://github.com/<your-user>/<your-repo>.git`
- SSH: `git@github.com:<your-user>/<your-repo>.git`

If your repo is private and cloning with HTTPS, you may need a GitHub Personal Access Token.

---

## 2) Connect to the server for the first time

From your local terminal:

```bash
ssh root@172.237.131.20
```

If asked "Are you sure you want to continue connecting", type:

```text
yes
```

If successful, your prompt changes and you are now inside Linode.

---

## 3) Update server and install software

Run these commands on Linode exactly:

```bash
apt update && apt upgrade -y
apt install -y python3 python3-venv python3-pip git nginx ufw
```

Optional but recommended: allow firewall traffic:

```bash
ufw allow OpenSSH
ufw allow 'Nginx Full'
ufw --force enable
ufw status
```

---

## 4) Create a dedicated app folder and clone this repo

Still on Linode:

```bash
mkdir -p /opt/monolith-task-tracker
cd /opt/monolith-task-tracker
```

Clone your repo (replace URL):

```bash
git clone <YOUR_REPO_URL> .
```

Verify files are present:

```bash
ls
```

You should see `app.py`, `requirements.txt`, etc.

If `ls` only shows a single folder name (for example `temp`), then the repo was cloned into a nested directory instead of directly into `/opt/monolith-task-tracker`.

**Recommended fix (best long-term): move files up one level so your app runs from `/opt/monolith-task-tracker`.**

```bash
cd /opt/monolith-task-tracker
mv temp/* .
mv temp/.[!.]* . 2>/dev/null || true
rmdir temp
ls
```

After moving files, you should see `app.py` and `requirements.txt` directly in `/opt/monolith-task-tracker`.

---

## 5) Create Python virtual environment and install dependencies

```bash
cd /opt/monolith-task-tracker
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

If you previously created a venv in the nested folder, rebuild it at the top level after moving files:

```bash
cd /opt/monolith-task-tracker
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Run tests (optional but recommended):

```bash
python -m unittest tests/test_app.py
```

---

## 6) Set a production SECRET_KEY

Generate a strong key:

```bash
python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
```

Copy the printed value. You will paste it into the service file in the next step.

---

## 7) Create a systemd service so app stays running

Before creating the service, **confirm where the repo actually lives**. A common cause of `502 Bad Gateway` is systemd pointing at a path that does not exist.

```bash
pwd
ls -la
```

You should see `app.py` and `requirements.txt` in your current directory. This guide assumes the app lives directly in `/opt/monolith-task-tracker`.

Create service file:

```bash
cat > /etc/systemd/system/monolith-task-tracker.service <<'EOF_SERVICE'
[Unit]
Description=Monolith Task Tracker App
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/monolith-task-tracker
Environment=SECRET_KEY=PASTE_YOUR_GENERATED_SECRET_KEY_HERE
ExecStart=/opt/monolith-task-tracker/.venv/bin/python /opt/monolith-task-tracker/app.py
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF_SERVICE
```

Start and enable service:

```bash
systemctl daemon-reload
systemctl enable monolith-task-tracker
systemctl start monolith-task-tracker
systemctl status monolith-task-tracker --no-pager
```

If status shows `active (running)`, app is running on internal port `8000`.

### Quick fix for `can't open file '/opt/monolith-task-tracker/app.py'`

If you see this in `journalctl`, your service paths are wrong for where the repo was actually cloned.

1) Find the real app path:

```bash
find /opt -maxdepth 4 -name app.py -path '*monolith-task-tracker*'
```

2) If the app is under a nested folder today, either move files to `/opt/monolith-task-tracker` (recommended) or temporarily point the unit file at the nested path.

Recommended cleanup (move files up, then keep unit file simple):

```bash
cd /opt/monolith-task-tracker
mv temp/* .
mv temp/.[!.]* . 2>/dev/null || true
rmdir temp
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Then ensure your service uses top-level paths:

```bash
cat > /etc/systemd/system/monolith-task-tracker.service <<'EOF_SERVICE'
[Unit]
Description=Monolith Task Tracker App
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/monolith-task-tracker
Environment=SECRET_KEY=PASTE_YOUR_GENERATED_SECRET_KEY_HERE
ExecStart=/opt/monolith-task-tracker/.venv/bin/python /opt/monolith-task-tracker/app.py
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF_SERVICE

systemctl daemon-reload
systemctl restart monolith-task-tracker
systemctl status monolith-task-tracker --no-pager
```

Temporary alternative (if you cannot move files right now):

```bash
cat > /etc/systemd/system/monolith-task-tracker.service <<'EOF_SERVICE'
[Unit]
Description=Monolith Task Tracker App
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/monolith-task-tracker/temp
Environment=SECRET_KEY=PASTE_YOUR_GENERATED_SECRET_KEY_HERE
ExecStart=/opt/monolith-task-tracker/temp/.venv/bin/python /opt/monolith-task-tracker/temp/app.py
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF_SERVICE

systemctl daemon-reload
systemctl restart monolith-task-tracker
systemctl status monolith-task-tracker --no-pager
```

3) Confirm app is listening before checking nginx:

```bash
ss -ltnp | grep ':8000'
curl -I http://127.0.0.1:8000/
```

Only after those succeed should you test `http://your-domain/`.

---

## 8) Configure Nginx to expose app on your domain

Create Nginx config:

```bash
cat > /etc/nginx/sites-available/monolith-task-tracker <<'EOF_NGINX'
server {
    listen 80;
    server_name www.yourdomain.com yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF_NGINX
```

Enable site:

```bash
ln -sf /etc/nginx/sites-available/monolith-task-tracker /etc/nginx/sites-enabled/monolith-task-tracker
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl restart nginx
systemctl status nginx --no-pager
```

⚠️ Replace `www.yourdomain.com` and `yourdomain.com` with your real domain before running.


If `nginx -t` passes but `systemctl restart nginx` fails with `status=208/STDIN` and a message like `Failed to set up standard input: No such file or directory`, your system is missing a valid `/dev/null` device (common in broken/chrooted environments).

Quick fix:

```bash
ls -l /dev/null
# expected: crw-rw-rw- ... /dev/null

# If /dev/null is missing or not a character device:
rm -f /dev/null
mknod -m 666 /dev/null c 1 3
chown root:root /dev/null

systemctl daemon-reexec
systemctl restart nginx
systemctl status nginx --no-pager
```

If `mknod` is blocked by your environment/provider image, reboot the VM from the provider panel and retry.

---

## 9) Test live site

From your local browser, visit:
- `http://yourdomain.com`
- `http://www.yourdomain.com`

Login credentials in this app:
- user: `alex` / pass: `password123`
- user: `sam` / pass: `password123`

Validation flow:
1. Login as alex, mark task complete.
2. Logout, login as sam.
3. Confirm Alex shows completed.
4. Mark sam complete and verify both completed.

---

## 10) Add HTTPS (strongly recommended)

Install Certbot:

```bash
apt install -y certbot python3-certbot-nginx
```

Request certificate (replace domain):

```bash
certbot --nginx -d yourdomain.com -d www.yourdomain.com
```

Test auto-renew:

```bash
certbot renew --dry-run
```

Now test:
- `https://yourdomain.com`
- `https://www.yourdomain.com`

---

## 11) How to deploy future updates from this repo

Whenever you make changes in this repo and want them live, do both parts below.

### 11A) Push your latest app files from your local machine to GitHub

Run these commands locally (inside your repo):

```bash
git status
git add .
git commit -m "Describe your change"
git push origin <your-branch>
```

If you work directly from `main`, replace `<your-branch>` with `main`.

### 11B) Pull and restart on Linode

```bash
ssh root@172.237.131.20
cd /opt/monolith-task-tracker
git pull origin main
source .venv/bin/activate
pip install -r requirements.txt
systemctl restart monolith-task-tracker
systemctl status monolith-task-tracker --no-pager
```

If your deployment folder is `/opt/monolith-task-tracker/temp`, switch to that path before running the commands.

---

## 12) Troubleshooting (copy/paste checks)

### 12A) If you get **502 Bad Gateway**

A 502 usually means Nginx is up, but your Python app service is down or not reachable on `127.0.0.1:8000`.

Run in this exact order:

```bash
systemctl status monolith-task-tracker --no-pager
journalctl -u monolith-task-tracker -n 200 --no-pager
ss -ltnp | rg ':8000'
nginx -t
systemctl status nginx --no-pager
tail -n 100 /var/log/nginx/error.log
```

Quick recover sequence:

```bash
cd /opt/monolith-task-tracker
git pull origin main
source .venv/bin/activate
pip install -r requirements.txt
systemctl restart monolith-task-tracker
systemctl restart nginx
systemctl status monolith-task-tracker --no-pager
systemctl status nginx --no-pager
```

If the app service keeps failing, check these common causes:
- Wrong `WorkingDirectory` or `ExecStart` path in `/etc/systemd/system/monolith-task-tracker.service`.
- Missing Python dependencies (fix with `pip install -r requirements.txt`).
- Port mismatch (`proxy_pass http://127.0.0.1:8000;` in Nginx must match app port).
- Syntax errors introduced in recent commits (inspect `journalctl` output).

### 12B) General checks

If app not loading:

```bash
systemctl status monolith-task-tracker --no-pager
journalctl -u monolith-task-tracker -n 100 --no-pager
nginx -t
systemctl status nginx --no-pager
tail -n 100 /var/log/nginx/error.log
```

If DNS/domain not resolving yet:
- DNS can take a little time to propagate.
- Confirm A record is exactly `172.237.131.20`.

If Git clone of private repo fails:
- Use a GitHub token with HTTPS clone.
- Or set up SSH deploy key for the server.

---

## 13) Progress tracker (check boxes)

- [ ] SSH into Linode works.
- [ ] Base packages installed.
- [ ] Repo cloned to `/opt/monolith-task-tracker`.
- [ ] Virtualenv created and dependencies installed.
- [ ] systemd service created and running.
- [ ] Nginx configured and running.
- [ ] Domain opens app on HTTP.
- [ ] HTTPS certificate installed.
- [ ] Login flow verified for alex + sam.

---

## 14) Session notes

Date:

What worked:

What failed:

Next action:
