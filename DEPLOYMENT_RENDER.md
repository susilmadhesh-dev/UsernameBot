# Deploying Your Discord Bot to Render.com (24/7 Free Hosting)

This guide walks you through deploying your Discord License Key Generator bot to [Render.com](https://render.com) as a **Background Worker** so it stays online 24/7 for free.

---

## Step 1: Upload Your Code to GitHub

1. Go to [GitHub.com](https://github.com) and create a **New Repository** (e.g., `discord-license-bot`).
2. Open a terminal in your project directory (`discord_license_bot`) and run:

```bash
git init
git add bot.py requirements.txt render.yaml Procfile README.md .env.example
git commit -m "Initial bot commit for Render deployment"
git branch -M main
git remote add origin https://github.com/YOUR_GITHUB_USERNAME/discord-license-bot.git
git push -u origin main
```

> ⚠️ **IMPORTANT SECURITY NOTE**: Do **NOT** commit your `.env` file or hardcode your `DISCORD_TOKEN` in public code. Your token will be set securely inside Render's dashboard.

---

## Step 2: Sign Up & Create a Background Worker on Render

1. Log in to [Render.com](https://render.com) (you can log in directly with your GitHub account).
2. Click **New +** in the top right corner and select **Background Worker**.
3. Select your GitHub repository (`discord-license-bot`) and click **Connect**.

---

## Step 3: Configure Deployment Settings

Fill in the settings on the Render setup screen:

| Setting | Value |
| :--- | :--- |
| **Name** | `discord-license-bot` |
| **Region** | Select closest region (e.g., Singapore, Oregon, Frankfurt) |
| **Runtime** | `Python 3` |
| **Build Command** | `pip install -r requirements.txt` |
| **Start Command** | `python bot.py` |
| **Instance Type** | **Free** |

---

## Step 4: Add Environment Variables

Scroll down to the **Environment Variables** section on Render and add the following key-value pairs:

| Key | Value |
| :--- | :--- |
| `DISCORD_TOKEN` | `YOUR_ACTUAL_BOT_TOKEN_HERE` |
| `KEY_PREFIX` | `ADAMCORP` |
| `KEY_LENGTH` | `5` |
| `REQUIRED_ROLE_NAME` | `Reseller` |

---

## Step 5: Deploy Bot

Click **Create Background Worker**.

Render will automatically install `discord.py` and `python-dotenv`, build your project, and start `python bot.py`.

### Checking Deployment Logs
You will see output in Render's **Logs** tab:
```text
==> Running 'pip install -r requirements.txt'
==> Running 'python bot.py'
[*] Starting Discord License Generator Bot...
Logged in as License Generator Bot (ID: 1551309916029984809)
[+] Synced 3 slash command(s) globally.
```

Your bot is now live and hosted 24/7 on Render! 🚀
