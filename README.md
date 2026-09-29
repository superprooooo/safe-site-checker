# SafeSite – website safety checker

Type in a website address and SafeSite tells you if it is **safe**, **suspicious** or **dangerous**.

It checks the address against three databases plus some built-in scam-pattern checks:

| Source | Detects | Key needed? |
|---|---|---|
| OpenPhish community feed | Phishing sites | No |
| Google Safe Browsing | Malware, phishing, unwanted software | Free key |
| URLhaus (abuse.ch) | Malware distribution hosts | Free key |
| Built-in checks | IP-address URLs, look-alike characters, no HTTPS, etc. | No |

The app works out of the box with OpenPhish only. Adding the two free keys makes it much stronger.

## Step-by-step setup

### 1. Install the basics
- Install **Python 3.9+** from https://www.python.org/downloads/ (tick "Add Python to PATH" on Windows).
- Install **Git** from https://git-scm.com/downloads.

### 2. Open the project folder in a terminal
```bash
cd safe-site-checker
```

### 3. Create a virtual environment and install packages
```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# Mac / Linux:
source venv/bin/activate

pip install -r requirements.txt
```

### 4. (Recommended) Get the free API keys
**Google Safe Browsing**
1. Go to https://console.cloud.google.com/ and create a project.
2. Search for "Safe Browsing API" and click **Enable**.
3. Go to **APIs & Services → Credentials → Create credentials → API key**. Copy it.

**URLhaus**
1. Sign in at https://auth.abuse.ch/ (free account).
2. Copy your **Auth-Key** from your profile.

### 5. Add the keys
Copy `.env.example` to a new file named `.env` and paste the keys after the `=` signs:
```
GOOGLE_SAFE_BROWSING_KEY=your_key_here
URLHAUS_AUTH_KEY=your_key_here
```
Skip this step if you only want OpenPhish.

### 6. Run it
```bash
python app.py
```
Open http://127.0.0.1:5001 in your browser, type a site (for example `example.com`) and press **Check**.

### 7. Put it on GitHub
1. Create a new empty repository on https://github.com/new (do not add a README).
2. Run:
```bash
git init
git add .
git commit -m "SafeSite website safety checker"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/safe-site-checker.git
git push -u origin main
```
`.gitignore` already keeps your `.env` (your secret keys) out of GitHub. Never upload it.

### 8. (Optional) Publish it online for free
**Before you publish:** keep the site non-commercial (no ads, sales or subscriptions). Google's Safe Browsing API and the free OpenPhish feed are for non-commercial use only. Read each provider's terms first. The app already includes the required credit line and a rate limit (10 checks per minute per visitor, 300 per hour overall) to protect your free quota. You can change these numbers at the top of `app.py`.

1. Push the project to GitHub (step 7). Make sure `.env` is not uploaded.
2. Go to https://render.com and sign up with your GitHub account.
3. Click **New → Web Service** and choose your `safe-site-checker` repository.
4. Fill in:
   - Runtime: **Python**
   - Build command: `pip install -r requirements.txt`
   - Start command: `gunicorn app:app`
   - Instance type: **Free**
5. Under **Environment**, add `GOOGLE_SAFE_BROWSING_KEY` and `URLHAUS_AUTH_KEY` with your keys. Put keys here, never in the code.
6. Click **Deploy**. After a few minutes you get a public link like `https://safe-site-checker.onrender.com`.

On the free plan the site sleeps when unused, so the first visit can take about a minute to load.

## How to read the result
- **Looks safe**: no database lists it. This is not a guarantee, since brand-new scam sites may not be listed yet.
- **Be careful**: not listed anywhere, but the address has warning signs (for example an IP address or look-alike characters).
- **Dangerous**: at least one database lists it. Don't visit it.

## Troubleshooting
- A check says **error**: your internet is down, or the API key is wrong or rate-limited. The other checks still run.
- Port already in use: change `port=5001` at the bottom of `app.py`.
