"""
Discord License Key Management Bot
-----------------------------------
A discord.py bot with an interactive button panel, product selection dropdown,
pop-up modals, SQLite database persistence, Xiters Auth Seller API integration,
custom username/password generation, HWID protection, and DM delivery.

Supports:
- Xiters Auth Seller API (https://xiter.in/api/seller/)
- Commands: !genkey, !setsecwl, /panel, /generate, /genkey, /setsecwl, /stats
- 3 Product Types:
  - INTERNAL   (Mask: ADAM CORP INTERNAL-******-******)
  - SILENT AIM (Mask: ADAM CORP SILENT AIM-******-******)
  - AIMKILL    (Mask: ADAM CORP AIMKILL-******-******)
"""

import sys
import os
import re
import json
import string
import secrets
import sqlite3
import asyncio
import aiohttp
import requests
from datetime import datetime, timedelta, timezone
from typing import Optional, Set, Tuple, List, Dict, Any
import discord
from discord import app_commands
from discord.ext import commands
from dotenv import load_dotenv

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ==========================================
# CONFIGURATION & ENVIRONMENT VARIABLES
# ==========================================
load_dotenv()

DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
GUILD_ID = os.getenv("GUILD_ID", "").strip()

# Key Generation Settings
BASE_PREFIX = os.getenv("KEY_PREFIX", "ADAMCORP")
KEY_LENGTH = int(os.getenv("KEY_LENGTH", "5"))
ALLOWED_CHARACTERS = string.ascii_uppercase + string.digits

# ------------------------------------------
# Xiters Auth Configuration (https://xiter.in)
# ------------------------------------------
API_URL = os.getenv("API_URL", "https://xiter.in/api/seller/")
API_KEY = (
    os.getenv("API_KEY", "").strip()
    or os.getenv("XITERS_API_KEY", "").strip()
    or os.getenv("KEYAUTH_SELLER_KEY", "").strip()
)
DEFAULT_KEY_MASK = os.getenv("KEY_MASK", "ADAM CORP INTERNAL-******-******")

# Product Masks for Xiters Auth
PRODUCT_MASKS = {
    "INTERNAL": os.getenv("MASK_INTERNAL", "ADAM CORP INTERNAL-******-******"),
    "SILENT AIM": os.getenv("MASK_SILENTAIM", "ADAM CORP SILENT AIM-******-******"),
    "AIMKILL": os.getenv("MASK_AIMKILL", "ADAM CORP AIMKILL-******-******")
}

# Local Key Fallback Prefixes
PRODUCT_PREFIXES = {
    "INTERNAL": f"{BASE_PREFIX}-INT",
    "SILENT AIM": f"{BASE_PREFIX}-SIA",
    "AIMKILL": f"{BASE_PREFIX}-AMK"
}

# SQLite Database Path
DB_PATH = "licenses.db"

# In-memory storage for duplicate prevention
generated_keys: Set[str] = set()


# ==========================================
# XITERS AUTH SELLER API ENGINE
# ==========================================
def seller_api_sync(**data) -> str:
    """
    Synchronous call to Xiters Auth Seller API (https://xiter.in/api/seller/).
    Matches the official snippet:
      data["sellerkey"] = API_KEY
      r = requests.post(API_URL, data=data, timeout=20)
      r.raise_for_status()
      return r.text
    """
    if not API_KEY or API_KEY == "YOUR_API_KEY":
        raise ValueError("API_KEY is not configured in .env (add API_KEY=your_xiter_seller_key)")

    data["sellerkey"] = API_KEY
    r = requests.post(API_URL, data=data, timeout=20)
    r.raise_for_status()
    return r.text


async def seller_api(**data) -> str:
    """Non-blocking asynchronous wrapper for seller_api_sync."""
    return await asyncio.to_thread(seller_api_sync, **data)


def extract_key_from_response(body: str, default_mask: str = "") -> str:
    """Extracts the actual generated license key from Xiters Auth API response."""
    cleaned = body.strip()
    try:
        data = json.loads(cleaned)
        if isinstance(data, dict):
            for field in ["key", "license", "licence"]:
                if field in data and isinstance(data[field], str) and data[field].strip():
                    return data[field].strip()
            if "keys" in data and isinstance(data["keys"], list) and len(data["keys"]) > 0:
                return str(data["keys"][0]).strip()
            if "data" in data and isinstance(data["data"], str):
                return data["data"].strip()
            if "message" in data and isinstance(data["message"], str) and "-" in data["message"]:
                return data["message"].strip()
    except Exception:
        pass

    for line in cleaned.splitlines():
        line = line.strip()
        if "-" in line and not line.startswith("{") and not line.startswith("<") and not line.startswith("["):
            return line

    return cleaned


# ==========================================
# HELPER FUNCTIONS
# ==========================================
def parse_expiration(raw_str: str) -> Tuple[Optional[datetime], str, int]:
    """
    Parses expiration input.
    Supports:
    1. Exact Date and Time in DD/MM/YYYY HH:MM or DD/MM/YYYY
       e.g. '25/12/2026 18:30' or '25/12/2026'
    2. Relative durations like '1d', '7d', '30d', '12h', '1y'
    3. 'lifetime', 'never', 'perm'
    Returns: (expires_at_datetime, display_label_dd_mm_yyyy_hh_mm, expiry_days)
    """
    cleaned = raw_str.strip()

    # 1. Exact Date / Time check: DD/MM/YYYY HH:MM or DD/MM/YYYY or DD-MM-YYYY
    date_match = re.match(r"^(\d{1,2})[/.-](\d{1,2})[/.-](\d{4})(?:\s+(\d{1,2}):(\d{2}))?$", cleaned)
    if date_match:
        day = int(date_match.group(1))
        month = int(date_match.group(2))
        year = int(date_match.group(3))
        hour = int(date_match.group(4)) if date_match.group(4) is not None else 23
        minute = int(date_match.group(5)) if date_match.group(5) is not None else 59
        try:
            exp_dt = datetime(year, month, day, hour, minute, tzinfo=timezone.utc)
        except ValueError as ve:
            raise ValueError(f"Invalid date/time value: {ve}")

        now = datetime.now(timezone.utc)
        if exp_dt < now:
            raise ValueError("Expiration date/time cannot be in the past!")

        diff_days = max(1, (exp_dt - now).days)
        return exp_dt, exp_dt.strftime("%d/%m/%Y %H:%M"), diff_days

    # 2. Lifetime check
    lower = cleaned.lower()
    if lower in ["lifetime", "never", "perm", "permanent"]:
        return None, "Lifetime (Never Expires)", 99999

    # 3. Relative duration check
    rel_match = re.match(r"^(\d+)\s*([dhmy]?)$", lower)
    if not rel_match:
        if lower.isdigit():
            num = int(lower)
            exp_dt = datetime.now(timezone.utc) + timedelta(days=num)
            return exp_dt, exp_dt.strftime("%d/%m/%Y %H:%M"), num
        raise ValueError("Invalid format. Use DD/MM/YYYY HH:MM (e.g. 25/12/2026 18:30) or '7d', '30d', 'lifetime'.")

    num = int(rel_match.group(1))
    unit = rel_match.group(2) or "d"
    now = datetime.now(timezone.utc)
    if unit == "h":
        exp_dt = now + timedelta(hours=num)
        days = max(1, num // 24)
    elif unit == "d":
        exp_dt = now + timedelta(days=num)
        days = num
    elif unit == "m":
        exp_dt = now + timedelta(days=num * 30)
        days = num * 30
    elif unit == "y":
        exp_dt = now + timedelta(days=num * 365)
        days = num * 365
    else:
        exp_dt = now + timedelta(days=num)
        days = num

    return exp_dt, exp_dt.strftime("%d/%m/%Y %H:%M"), days


async def check_admin(interaction: discord.Interaction) -> bool:
    """Checks if the interacting user has Administrator permissions in the server or is Server Owner."""
    if not interaction.guild:
        return True

    # 1. Server Owner is always Administrator
    if interaction.user.id == interaction.guild.owner_id:
        return True

    # 2. Check interaction permissions directly evaluated by Discord
    if getattr(interaction.permissions, "administrator", False):
        return True

    # 3. Check guild_permissions on cached member
    member = interaction.user
    if getattr(member, "guild_permissions", None) and member.guild_permissions.administrator:
        return True

    # 4. Fetch live member from Discord API to verify fresh permissions
    try:
        member = await interaction.guild.fetch_member(interaction.user.id)
        if member.guild_permissions.administrator:
            return True
    except Exception:
        pass

    return False


# ==========================================
# DATABASE ENGINE
# ==========================================
def get_db_connection():
    """Returns a connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes SQLite database, auto-migrates missing columns, and loads keys."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS keys (
                key TEXT PRIMARY KEY,
                product_type TEXT DEFAULT 'INTERNAL',
                assigned_username TEXT,
                password TEXT,
                hwid TEXT DEFAULT 'Yes (Locked on First Use)',
                duration TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                created_by_id INTEGER NOT NULL,
                created_by_name TEXT NOT NULL,
                status TEXT DEFAULT 'active',
                keyauth_synced INTEGER DEFAULT 0
            )
        """)
        conn.commit()

        # Database Migration Check: ensure all required columns exist
        cursor.execute("PRAGMA table_info(keys)")
        existing_cols = {col["name"] for col in cursor.fetchall()}

        required_columns = {
            "product_type": "TEXT DEFAULT 'INTERNAL'",
            "assigned_username": "TEXT",
            "password": "TEXT",
            "hwid": "TEXT DEFAULT 'Yes (Locked on First Use)'",
            "duration": "TEXT",
            "expires_at": "TEXT",
            "status": "TEXT DEFAULT 'active'",
            "keyauth_synced": "INTEGER DEFAULT 0"
        }

        for col_name, col_type in required_columns.items():
            if col_name not in existing_cols:
                try:
                    cursor.execute(f"ALTER TABLE keys ADD COLUMN {col_name} {col_type}")
                    print(f"[*] Migrated database: Added column '{col_name}'")
                except Exception as e:
                    print(f"[!] Migration notice for '{col_name}': {e}")
        conn.commit()

        # Load existing keys into memory set
        cursor.execute("SELECT key FROM keys")
        rows = cursor.fetchall()
        for row in rows:
            generated_keys.add(row["key"])

    print(f"[*] Database initialized: {len(generated_keys)} existing keys loaded.")


def save_key_to_db(
    key: str,
    product_type: str,
    assigned_username: str,
    password: str,
    hwid: str,
    duration_label: str,
    expires_at: Optional[datetime],
    user_id: int,
    user_name: str,
    keyauth_synced: int = 0
):
    """Saves a generated key and account credentials to SQLite."""
    now_str = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M:%S")
    expires_str = expires_at.strftime("%d/%m/%Y %H:%M") if expires_at else "Lifetime"

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO keys (key, product_type, assigned_username, password, hwid, duration, created_at, expires_at, created_by_id, created_by_name, status, keyauth_synced)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)
        """, (key, product_type, assigned_username, password, hwid, duration_label, now_str, expires_str, user_id, str(user_name), keyauth_synced))
        conn.commit()

    generated_keys.add(key)


def get_key_info(key_str: str) -> Optional[sqlite3.Row]:
    """Retrieves key details from SQLite."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM keys WHERE key = ?", (key_str.strip(),))
        return cursor.fetchone()


def delete_key_from_db(key_str: str) -> bool:
    """Deletes a key from SQLite and removes it from memory."""
    target_key = key_str.strip()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM keys WHERE key = ?", (target_key,))
        deleted = cursor.rowcount > 0
        conn.commit()

    if deleted and target_key in generated_keys:
        generated_keys.remove(target_key)

    return deleted


def fetch_database_stats() -> Tuple[int, int, int]:
    """Returns (total, active, expired) count from database."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM keys")
        total = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM keys WHERE status = 'active'")
        active = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM keys WHERE status = 'expired'")
        expired = cursor.fetchone()[0]

    return total, active, expired


# ==========================================
# LOCAL KEY GENERATOR FALLBACK
# ==========================================
def generate_single_key(prefix: str) -> str:
    """Generates a cryptographically secure, unique license key fallback."""
    max_attempts = 1000
    attempts = 0

    while attempts < max_attempts:
        random_section = "".join(
            secrets.choice(ALLOWED_CHARACTERS) for _ in range(KEY_LENGTH)
        )
        full_key = f"{prefix}{random_section}"

        if full_key not in generated_keys:
            generated_keys.add(full_key)
            return full_key

        attempts += 1

    raise RuntimeError("Key space exhausted or too many collisions occurred.")


# ==========================================
# DISCORD MODALS (POP-UP DIALOGS)
# ==========================================
class GenerateKeyModal(discord.ui.Modal):
    username_input = discord.ui.TextInput(
        label="Username (Optional)",
        placeholder="Leave blank to use License Key",
        required=False,
        max_length=50
    )
    password_input = discord.ui.TextInput(
        label="Password (Optional)",
        placeholder="Leave blank to use License Key",
        required=False,
        max_length=50
    )
    expiration_input = discord.ui.TextInput(
        label="Expiration (DD/MM/YYYY HH:MM or 7d)",
        placeholder="e.g. 25/12/2026 18:30 or 7d, 30d, lifetime",
        default="7d",
        required=True,
        max_length=30
    )
    hwid_input = discord.ui.TextInput(
        label="HWID Lock / Affected",
        placeholder="Leave blank for default (Locked on 1st Login)",
        default="Yes (Locked on First Use)",
        required=False,
        max_length=50
    )

    def __init__(self, product_type: str, prefix: str):
        super().__init__(title=f"Generate Key ({product_type})")
        self.product_type = product_type
        self.prefix = prefix

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)

        user_input_val = self.username_input.value.strip() if self.username_input.value else ""
        pass_input_val = self.password_input.value.strip() if self.password_input.value else ""
        hwid_val = self.hwid_input.value.strip() if self.hwid_input.value else "Yes (Locked on First Use)"
        raw_expiration = self.expiration_input.value.strip()

        try:
            expires_at, expires_display, expiry_days = parse_expiration(raw_expiration)
        except Exception as err:
            await interaction.followup.send(f"❌ Error: {err}", ephemeral=True)
            return

        # Attempt to create key via Xiters Auth API if configured
        key = None
        auth_synced = 0
        auth_info = "Local Key Storage (API_KEY not configured)"
        mask = PRODUCT_MASKS.get(self.product_type, DEFAULT_KEY_MASK)

        if API_KEY and API_KEY != "YOUR_API_KEY":
            try:
                body = await seller_api(
                    type="add",
                    amount=1,
                    duration=expiry_days,
                    expiry=86400,
                    mask=mask,
                    note=f"discord:{interaction.user.id}"
                )
                key = extract_key_from_response(body, mask)
                auth_synced = 1
                auth_info = "✅ Created on Xiters Auth (xiter.in)"
            except Exception as err:
                print(f"[!] Xiters Auth notice: {err}")
                key = generate_single_key(self.prefix)
                auth_synced = 0
                auth_info = f"⚠️ Xiters Auth notice: {err}"
        else:
            key = generate_single_key(self.prefix)

        # License key is used as username and password if not explicitly provided
        username = user_input_val if user_input_val else key
        password = pass_input_val if pass_input_val else (user_input_val if user_input_val else key)

        # Save to SQLite database
        try:
            save_key_to_db(
                key=key,
                product_type=self.product_type,
                assigned_username=username,
                password=password,
                hwid=hwid_val,
                duration_label=expires_display,
                expires_at=expires_at,
                user_id=interaction.user.id,
                user_name=str(interaction.user),
                keyauth_synced=auth_synced
            )
        except Exception as db_err:
            await interaction.followup.send(f"❌ Database error: {db_err}", ephemeral=True)
            return

        # Build DM credentials embed
        dm_delivered = True
        try:
            embed_dm = discord.Embed(
                title="🔑 Your License Key & Account Credentials",
                color=discord.Color.green(),
                timestamp=datetime.now(timezone.utc)
            )
            embed_dm.add_field(name="Product Type", value=f"**{self.product_type}**", inline=True)
            embed_dm.add_field(name="License Key", value=f"`{key}`", inline=False)
            embed_dm.add_field(name="👤 Username", value=f"`{username}`", inline=True)
            embed_dm.add_field(name="🔒 Password", value=f"`{password}`", inline=True)
            embed_dm.add_field(name="📅 Expiration (DD/MM/YYYY HH:MM)", value=f"`{expires_display}`", inline=False)
            embed_dm.add_field(name="💻 HWID Affected", value=f"`{hwid_val}`", inline=True)
            embed_dm.add_field(name="🌐 Auth Status", value=auth_info, inline=True)
            embed_dm.add_field(
                name="📋 Quick Copy Credentials",
                value=f"```text\nKey:      {key}\nUsername: {username}\nPassword: {password}\nExpires:  {expires_display}\nHWID:     {hwid_val}\n```",
                inline=False
            )
            embed_dm.set_footer(text="Keep your credentials safe! Do not share your password.")
            await interaction.user.send(embed=embed_dm)
        except Exception as dme:
            dm_delivered = False
            print(f"[!] DM delivery notice for {interaction.user}: {dme}")

        # Send response in channel (visible privately to user)
        embed_channel = discord.Embed(
            title="🔑 License Key & Credentials Generated",
            color=discord.Color.green(),
            timestamp=datetime.now(timezone.utc)
        )
        embed_channel.add_field(name="Product Type", value=f"**{self.product_type}**", inline=True)
        embed_channel.add_field(name="License Key", value=f"`{key}`", inline=False)
        embed_channel.add_field(name="👤 Username", value=f"`{username}`", inline=True)
        embed_channel.add_field(name="🔒 Password", value=f"`{password}`", inline=True)
        embed_channel.add_field(name="📅 Expiration (DD/MM/YYYY HH:MM)", value=f"`{expires_display}`", inline=False)
        embed_channel.add_field(name="💻 HWID Affected", value=f"`{hwid_val}`", inline=True)
        embed_channel.add_field(name="🌐 Auth Status", value=auth_info, inline=True)
        embed_channel.add_field(
            name="📋 Quick Copy Credentials",
            value=f"```text\nKey:      {key}\nUsername: {username}\nPassword: {password}\nExpires:  {expires_display}\nHWID:     {hwid_val}\n```",
            inline=False
        )

        footer_text = f"Generated by {interaction.user}"
        if dm_delivered:
            footer_text += " • ✅ Also sent to your DMs"
        else:
            footer_text += " • ⚠️ DM delivery failed (check privacy settings)"
        embed_channel.set_footer(text=footer_text)

        await interaction.followup.send(embed=embed_channel, ephemeral=True)


class KeyInfoModal(discord.ui.Modal, title="Check Key Information"):
    key_input = discord.ui.TextInput(
        label="License Key",
        placeholder="Enter key (e.g. ADAM CORP INTERNAL-xxxxxx-xxxxxx)",
        required=True,
        max_length=60
    )

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        key_str = self.key_input.value.strip()

        row = get_key_info(key_str)
        if not row:
            await interaction.followup.send(f"❌ License key `{key_str}` was not found in database.", ephemeral=True)
            return

        row_dict = dict(row)
        embed = discord.Embed(
            title=f"🔍 Key Details: {row['key']}",
            color=discord.Color.blue(),
            timestamp=datetime.now(timezone.utc)
        )
        product_label = row_dict.get("product_type") or "INTERNAL"
        username_val = row_dict.get("assigned_username") or "N/A"
        password_val = row_dict.get("password") or "N/A"
        hwid_val = row_dict.get("hwid") or "Yes (Locked on First Use)"
        duration_val = row_dict.get("duration") or "N/A"
        expires_val = row_dict.get("expires_at") or duration_val
        synced_val = "✅ Synced to Xiters Auth" if row_dict.get("keyauth_synced") else "Local Mode"

        embed.add_field(name="Product Type", value=f"**{product_label}**", inline=True)
        embed.add_field(name="Status", value=f"**{str(row['status']).upper()}**", inline=True)
        embed.add_field(name="HWID Affected", value=f"`{hwid_val}`", inline=True)
        embed.add_field(name="👤 Username", value=f"`{username_val}`", inline=True)
        embed.add_field(name="🔒 Password", value=f"`{password_val}`", inline=True)
        embed.add_field(name="🌐 Xiters Sync", value=synced_val, inline=True)
        embed.add_field(name="📅 Expiration (DD/MM/YYYY HH:MM)", value=f"`{expires_val}`", inline=True)
        embed.add_field(name="Created At", value=str(row['created_at'])[:19], inline=True)
        embed.add_field(name="Created By", value=str(row['created_by_name']), inline=True)

        await interaction.followup.send(embed=embed, ephemeral=True)


class DeleteKeyModal(discord.ui.Modal, title="Delete License Key"):
    key_input = discord.ui.TextInput(
        label="License Key to Delete",
        placeholder="Enter key to remove",
        required=True,
        max_length=60
    )

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        key_str = self.key_input.value.strip()

        deleted = delete_key_from_db(key_str)
        if deleted:
            await interaction.followup.send(f"✅ License key `{key_str}` has been deleted from database.", ephemeral=True)
        else:
            await interaction.followup.send(f"❌ License key `{key_str}` was not found in database.", ephemeral=True)


# ==========================================
# DISCORD CONTROL PANEL VIEW WITH INTEGRATED DROPDOWN
# ==========================================
class LicensePanelView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)  # Persistent view across restarts

    @discord.ui.select(
        placeholder="Select Product Type to Generate Key...",
        custom_id="select_product_type_panel",
        options=[
            discord.SelectOption(
                label="INTERNAL",
                value="INTERNAL",
                description="Mask: ADAM CORP INTERNAL-******-******",
                emoji="🎯"
            ),
            discord.SelectOption(
                label="SILENT AIM",
                value="SILENT AIM",
                description="Mask: ADAM CORP SILENT AIM-******-******",
                emoji="🎯"
            ),
            discord.SelectOption(
                label="AIMKILL",
                value="AIMKILL",
                description="Mask: ADAM CORP AIMKILL-******-******",
                emoji="🎯"
            )
        ],
        row=0
    )
    async def select_product_callback(self, interaction: discord.Interaction, select: discord.ui.Select):
        if not await check_admin(interaction):
            await interaction.response.send_message("❌ You need Administrator permissions to generate keys.", ephemeral=True)
            return
        product_type = select.values[0]
        prefix = PRODUCT_PREFIXES.get(product_type, f"{BASE_PREFIX}-INT")
        await interaction.response.send_modal(GenerateKeyModal(product_type, prefix))

    @discord.ui.button(
        label="Generate Key",
        style=discord.ButtonStyle.success,
        emoji="🔑",
        custom_id="btn_generate_key",
        row=1
    )
    async def btn_generate_key(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not await check_admin(interaction):
            await interaction.response.send_message("❌ You need Administrator permissions to generate keys.", ephemeral=True)
            return
        prefix = PRODUCT_PREFIXES.get("INTERNAL", f"{BASE_PREFIX}-INT")
        await interaction.response.send_modal(GenerateKeyModal("INTERNAL", prefix))

    @discord.ui.button(
        label="Key Info",
        style=discord.ButtonStyle.primary,
        emoji="🔍",
        custom_id="btn_key_info",
        row=1
    )
    async def btn_key_info(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(KeyInfoModal())

    @discord.ui.button(
        label="Delete Key",
        style=discord.ButtonStyle.danger,
        emoji="🗑️",
        custom_id="btn_delete_key",
        row=2
    )
    async def btn_delete_key(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not await check_admin(interaction):
            await interaction.response.send_message("❌ You need Administrator permissions to delete keys.", ephemeral=True)
            return
        await interaction.response.send_modal(DeleteKeyModal())


# ==========================================
# WEB SERVER FOR RENDER FREE TIER
# ==========================================
async def start_web_server():
    """Starts a lightweight HTTP server so Render Web Service (Free Tier) stays healthy."""
    from aiohttp import web
    app = web.Application()
    app.router.add_get('/', lambda req: web.Response(text="Discord License Bot is Online 24/7!"))
    runner = web.AppRunner(app)
    await runner.setup()
    port = int(os.getenv("PORT", 8080))
    site = web.TCPSite(runner, '0.0.0.0', port)
    await site.start()
    print(f"[*] HTTP health server started on port {port}")


# ==========================================
# BOT INITIALIZATION & EVENTS
# ==========================================
intents = discord.Intents.default()
if os.getenv("ENABLE_MESSAGE_CONTENT", "false").lower() == "true":
    intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)


@bot.event
async def on_ready():
    """Fired when the bot connects to Discord. Syncs slash commands instantly."""
    print(f"Logged in as {bot.user} (ID: {bot.user.id})")
    print("--------------------------------------------------")

    # Start HTTP server for Render free web service
    try:
        await start_web_server()
    except Exception as we:
        print(f"[!] Web server notice: {we}")

    # Register persistent button view
    bot.add_view(LicensePanelView())

    # Sync slash commands
    try:
        if GUILD_ID and str(GUILD_ID).isdigit() and int(GUILD_ID) > 0:
            guild = discord.Object(id=int(GUILD_ID))
            bot.tree.copy_global_to(guild=guild)
            await bot.tree.sync(guild=guild)
            print(f"[+] Synced slash commands to Guild ID: {GUILD_ID}")
        else:
            synced_global = await bot.tree.sync()
            print(f"[+] Synced {len(synced_global)} slash command(s) globally.")
            for guild in bot.guilds:
                safe_name = guild.name.encode("ascii", errors="replace").decode()
                try:
                    bot.tree.copy_global_to(guild=guild)
                    await bot.tree.sync(guild=guild)
                    print(f"[+] Synced slash commands to Guild '{safe_name}' (ID: {guild.id})")
                except Exception as ge:
                    print(f"[!] Guild sync warning for '{safe_name}': {ge}")
    except Exception as e:
        print(f"[!] Failed to sync slash commands: {e}")


# ==========================================
# PREFIX COMMANDS (XITERS AUTH SPEC)
# ==========================================
@bot.command(name="genkey")
@commands.has_permissions(administrator=True)
async def genkey_prefix(ctx: commands.Context, days: int = 1):
    """Create a license key via Xiters Auth (default 1 day). Example: !genkey 7"""
    try:
        body = await seller_api(
            type="add",
            amount=1,
            duration=days,
            expiry=86400,
            mask=DEFAULT_KEY_MASK,
            note=f"discord:{ctx.author.id}",
        )
        key = extract_key_from_response(body, DEFAULT_KEY_MASK)
        expires_at = datetime.now(timezone.utc) + timedelta(days=days)
        expires_display = expires_at.strftime("%d/%m/%Y %H:%M")

        # Save to SQLite database
        save_key_to_db(
            key=key,
            product_type="INTERNAL",
            assigned_username=key,
            password=key,
            hwid="Yes (Locked on First Use)",
            duration_label=f"{days} Day(s)",
            expires_at=expires_at,
            user_id=ctx.author.id,
            user_name=str(ctx.author),
            keyauth_synced=1
        )

        await ctx.reply(f"```{body}```", mention_author=False)

        # Also send credentials to DM
        try:
            await ctx.author.send(
                f"🔑 **License Key:** `{key}`\n"
                f"👤 **Username:** `{key}`\n"
                f"🔒 **Password:** `{key}`\n"
                f"📅 **Expires:** `{expires_display}`"
            )
        except Exception:
            pass
    except Exception as e:
        await ctx.reply(f"❌ Error generating key: `{e}`", mention_author=False)


@bot.command(name="setsecwl")
@commands.has_permissions(administrator=True)
async def setsecwl_prefix(ctx: commands.Context, key: str, enabled: int = 1):
    """Security whitelist a key (1=on, 0=off). Example: !setsecwl KEY 1"""
    try:
        body = await seller_api(type="setsecwl", key=key.strip(), enabled=enabled)
        await ctx.reply(f"```{body}```", mention_author=False)
    except Exception as e:
        await ctx.reply(f"❌ Error: `{e}`", mention_author=False)


@genkey_prefix.error
@setsecwl_prefix.error
async def prefix_error_handler(ctx: commands.Context, error: commands.CommandError):
    """Handles permission and argument errors for prefix commands."""
    if isinstance(error, commands.MissingPermissions):
        await ctx.reply("❌ You need Administrator permissions to use this command.", mention_author=False)
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.reply(f"❌ Missing required argument: `{error.param.name}`", mention_author=False)
    else:
        await ctx.reply(f"❌ Error: {error}", mention_author=False)


# ==========================================
# SLASH COMMANDS
# ==========================================
@bot.tree.command(
    name="panel",
    description="Display the License Management Control Panel."
)
async def panel_command(interaction: discord.Interaction):
    """Slash command to post the license management control panel embed with dropdown & buttons."""
    if not await check_admin(interaction):
        await interaction.response.send_message(
            "❌ You need Administrator permissions to use `/panel`.",
            ephemeral=True
        )
        return

    embed = discord.Embed(
        description=(
            "All key actions in one place — results are **private** to you.\n\n"
            "> **Select Product** — Choose (INTERNAL / SILENT AIM / AIMKILL) to generate\n"
            "> **Key Info** — Check status, username, password, HWID, and expiration\n"
            "> **Delete Key** — Remove a key\n\n"
            "*Only Administrators can generate keys.*"
        ),
        color=discord.Color.dark_theme()
    )

    await interaction.response.send_message(
        embed=embed,
        view=LicensePanelView()
    )


@bot.tree.command(
    name="genkey",
    description="Create a license key via Xiters Auth API."
)
@app_commands.describe(
    days="Duration in days (default 1).",
    product="Select product type (default INTERNAL)."
)
@app_commands.choices(product=[
    app_commands.Choice(name="INTERNAL (ADAM CORP INTERNAL-******-******)", value="INTERNAL"),
    app_commands.Choice(name="SILENT AIM (ADAM CORP SILENT AIM-******-******)", value="SILENT AIM"),
    app_commands.Choice(name="AIMKILL (ADAM CORP AIMKILL-******-******)", value="AIMKILL")
])
async def genkey_slash_command(
    interaction: discord.Interaction,
    days: Optional[int] = 1,
    product: Optional[app_commands.Choice[str]] = None
):
    """Slash command: /genkey [days] [product]"""
    if not await check_admin(interaction):
        await interaction.response.send_message("❌ You need Administrator permissions to generate keys.", ephemeral=True)
        return

    await interaction.response.defer(ephemeral=True)
    product_type = product.value if product else "INTERNAL"
    mask = PRODUCT_MASKS.get(product_type, DEFAULT_KEY_MASK)
    days_val = days if days is not None and days > 0 else 1

    try:
        body = await seller_api(
            type="add",
            amount=1,
            duration=days_val,
            expiry=86400,
            mask=mask,
            note=f"discord:{interaction.user.id}",
        )
        key = extract_key_from_response(body, mask)
        expires_at = datetime.now(timezone.utc) + timedelta(days=days_val)
        expires_display = expires_at.strftime("%d/%m/%Y %H:%M")

        save_key_to_db(
            key=key,
            product_type=product_type,
            assigned_username=key,
            password=key,
            hwid="Yes (Locked on First Use)",
            duration_label=f"{days_val} Day(s)",
            expires_at=expires_at,
            user_id=interaction.user.id,
            user_name=str(interaction.user),
            keyauth_synced=1
        )

        response_msg = (
            f"```{body}```\n"
            f"🔑 **Key:** `{key}`\n"
            f"👤 **Username:** `{key}`\n"
            f"🔒 **Password:** `{key}`\n"
            f"📅 **Expires:** `{expires_display}`"
        )
        await interaction.followup.send(response_msg, ephemeral=True)

        try:
            await interaction.user.send(response_msg)
        except Exception:
            pass
    except Exception as e:
        await interaction.followup.send(f"❌ Error from Xiters Auth: `{e}`", ephemeral=True)


@bot.tree.command(
    name="setsecwl",
    description="Security whitelist a key in Xiters Auth (1=on, 0=off)."
)
@app_commands.describe(
    key="The license key to whitelist.",
    enabled="1 for on, 0 for off (default 1)."
)
async def setsecwl_slash_command(
    interaction: discord.Interaction,
    key: str,
    enabled: Optional[int] = 1
):
    """Slash command: /setsecwl [key] [enabled]"""
    if not await check_admin(interaction):
        await interaction.response.send_message("❌ You need Administrator permissions to use `/setsecwl`.", ephemeral=True)
        return

    await interaction.response.defer(ephemeral=True)
    try:
        body = await seller_api(type="setsecwl", key=key.strip(), enabled=enabled if enabled is not None else 1)
        await interaction.followup.send(f"```{body}```", ephemeral=True)
    except Exception as e:
        await interaction.followup.send(f"❌ Error from Xiters Auth: `{e}`", ephemeral=True)


@bot.tree.command(
    name="generate",
    description="Generate unique license keys and credentials for a specific product."
)
@app_commands.choices(product=[
    app_commands.Choice(name="INTERNAL", value="INTERNAL"),
    app_commands.Choice(name="SILENT AIM", value="SILENT AIM"),
    app_commands.Choice(name="AIMKILL", value="AIMKILL")
])
@app_commands.describe(
    product="Select product type (INTERNAL, SILENT AIM, or AIMKILL).",
    amount="Number of unique keys to generate (1 to 20). Default is 1.",
    expiration="Expiration e.g. '25/12/2026 18:30' or '7d', '30d', 'lifetime'. Default is '7d'."
)
async def generate_command(
    interaction: discord.Interaction,
    product: app_commands.Choice[str],
    amount: Optional[app_commands.Range[int, 1, 20]] = 1,
    expiration: Optional[str] = "7d"
):
    """Slash command: /generate [product] [amount] [expiration]"""
    if not await check_admin(interaction):
        await interaction.response.send_message(
            "❌ You need Administrator permissions to generate keys.",
            ephemeral=True
        )
        return

    product_type = product.value
    prefix = PRODUCT_PREFIXES.get(product_type, f"{BASE_PREFIX}-INT")
    mask = PRODUCT_MASKS.get(product_type, DEFAULT_KEY_MASK)
    amount_val = amount if amount is not None else 1
    exp_str = expiration if expiration else "7d"

    await interaction.response.defer(ephemeral=True)

    try:
        expires_at, expires_display, expiry_days = parse_expiration(exp_str)
    except Exception as err:
        await interaction.followup.send(f"❌ Invalid expiration format: {err}", ephemeral=True)
        return

    generated_items = []
    hwid_val = "Yes (Locked on First Use)"

    for _ in range(amount_val):
        key = None
        auth_synced = 0
        if API_KEY and API_KEY != "YOUR_API_KEY":
            try:
                body = await seller_api(
                    type="add",
                    amount=1,
                    duration=expiry_days,
                    expiry=86400,
                    mask=mask,
                    note=f"discord:{interaction.user.id}"
                )
                key = extract_key_from_response(body, mask)
                auth_synced = 1
            except Exception as err:
                print(f"[!] Xiters Auth notice: {err}")
                key = generate_single_key(prefix)
        else:
            key = generate_single_key(prefix)

        username = key
        password = key

        save_key_to_db(
            key=key,
            product_type=product_type,
            assigned_username=username,
            password=password,
            hwid=hwid_val,
            duration_label=expires_display,
            expires_at=expires_at,
            user_id=interaction.user.id,
            user_name=str(interaction.user),
            keyauth_synced=auth_synced
        )

        generated_items.append({
            "key": key,
            "username": username,
            "password": password,
            "expires": expires_display,
            "hwid": hwid_val
        })

    if amount_val == 1:
        item = generated_items[0]
        embed = discord.Embed(
            title="🔑 License Key & Credentials Generated",
            color=discord.Color.green(),
            timestamp=datetime.now(timezone.utc)
        )
        embed.add_field(name="Product Type", value=f"**{product_type}**", inline=True)
        embed.add_field(name="License Key", value=f"`{item['key']}`", inline=False)
        embed.add_field(name="👤 Username", value=f"`{item['username']}`", inline=True)
        embed.add_field(name="🔒 Password", value=f"`{item['password']}`", inline=True)
        embed.add_field(name="📅 Expiration (DD/MM/YYYY HH:MM)", value=f"`{item['expires']}`", inline=False)
        embed.add_field(name="💻 HWID Affected", value=f"`{item['hwid']}`", inline=True)
        embed.add_field(
            name="📋 Quick Copy Credentials",
            value=f"```text\nKey:      {item['key']}\nUsername: {item['username']}\nPassword: {item['password']}\nExpires:  {item['expires']}\nHWID:     {item['hwid']}\n```",
            inline=False
        )
        embed.set_footer(text=f"Generated for {interaction.user}")
        await interaction.followup.send(embed=embed, ephemeral=True)
        try:
            await interaction.user.send(embed=embed)
        except Exception:
            pass
    else:
        text_lines = []
        for i, item in enumerate(generated_items, 1):
            text_lines.append(f"[{i}] Key: {item['key']} | User: {item['username']} | Pass: {item['password']} | Exp: {item['expires']} | HWID: {item['hwid']}")

        result_text = f"**Generated {amount_val} {product_type} Licenses & Accounts:**\n```text\n" + "\n".join(text_lines) + "\n```"
        await interaction.followup.send(result_text, ephemeral=True)
        try:
            await interaction.user.send(result_text)
        except Exception:
            pass


@bot.tree.command(
    name="stats",
    description="View license key database statistics."
)
async def stats_command(interaction: discord.Interaction):
    """Slash command: /stats"""
    if not await check_admin(interaction):
        await interaction.response.send_message(
            "❌ You need Administrator permissions to view stats.",
            ephemeral=True
        )
        return

    total, active, expired = fetch_database_stats()

    embed = discord.Embed(
        title="🔑 License Key Statistics",
        color=discord.Color.blue(),
        timestamp=datetime.now(timezone.utc)
    )
    embed.add_field(name="Total Keys Generated", value=str(total), inline=True)
    embed.add_field(name="Active Keys", value=str(active), inline=True)
    embed.add_field(name="Expired Keys", value=str(expired), inline=True)
    embed.add_field(name="Xiters Auth Integration", value="Active" if API_KEY and API_KEY != "YOUR_API_KEY" else "Local Mode", inline=True)
    embed.set_footer(text=f"Requested by {interaction.user}")

    await interaction.response.send_message(embed=embed, ephemeral=True)


# ==========================================
# BOT ENTRY POINT
# ==========================================
if __name__ == "__main__":
    if not DISCORD_TOKEN or DISCORD_TOKEN.strip() == "" or DISCORD_TOKEN == "YOUR_BOT_TOKEN_HERE":
        print("[!] CRITICAL ERROR: Discord bot token not found in environment!")
        print("Please set DISCORD_TOKEN in .env")
    else:
        init_db()
        print("[*] Starting Discord License Generator Bot (Xiters Auth Integrated)...")
        bot.run(DISCORD_TOKEN)
