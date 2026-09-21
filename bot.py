"""
Discord License Key Management Bot
-----------------------------------
A discord.py bot with an interactive button panel & pop-up modals for license key management.
Matches exact design: Generate Key, Key Info, Delete Key, Reseller role enforcement.
"""

import os
import re
import string
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional, Set, Tuple, List, Dict, Any
import discord
from discord import app_commands
from discord.ext import commands
from dotenv import load_dotenv

# ==========================================
# CONFIGURATION & ENVIRONMENT VARIABLES
# ==========================================
load_dotenv()

DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
GUILD_ID = os.getenv("GUILD_ID", "").strip()

# Key Generation Settings
KEY_PREFIX = os.getenv("KEY_PREFIX", "ADAMCORP")
KEY_LENGTH = int(os.getenv("KEY_LENGTH", "5"))
ALLOWED_CHARACTERS = string.ascii_uppercase + string.digits  # Uppercase A-Z and 0-9

# Role requirement configuration
env_role = os.getenv("REQUIRED_ROLE_NAME", "").strip()
REQUIRED_ROLE_NAME = env_role if env_role else "Reseller"

# SQLite Database Path
DB_PATH = "licenses.db"

# In-memory storage for duplicate prevention
generated_keys: Set[str] = set()


# ==========================================
# HELPER FUNCTIONS
# ==========================================
def parse_duration(duration_str: str) -> Tuple[Optional[datetime], str]:
    """
    Parses duration string like '1d', '7d', '30d', '12h', '1y', 'lifetime'.
    Returns (expiration_datetime, formatted_duration_label).
    """
    cleaned = duration_str.strip().lower()
    if cleaned in ["lifetime", "never", "perm", "permanent"]:
        return None, "Lifetime"

    match = re.match(r"^(\d+)\s*([dhmy]?)$", cleaned)
    if not match:
        if cleaned.isdigit():
            days = int(cleaned)
            return datetime.now(timezone.utc) + timedelta(days=days), f"{days} Day(s)"
        raise ValueError("Invalid duration format. Use e.g. '7d', '30d', '12h', '1y', or 'lifetime'.")

    num = int(match.group(1))
    unit = match.group(2) or "d"

    now = datetime.now(timezone.utc)
    if unit == "h":
        return now + timedelta(hours=num), f"{num} Hour(s)"
    elif unit == "d":
        return now + timedelta(days=num), f"{num} Day(s)"
    elif unit == "m":
        return now + timedelta(days=num * 30), f"{num} Month(s)"
    elif unit == "y":
        return now + timedelta(days=num * 365), f"{num} Year(s)"

    return now + timedelta(days=num), f"{num} Day(s)"


def check_user_permission(member: discord.Member) -> bool:
    """Checks if the user has Administrator permissions or the REQUIRED_ROLE_NAME role."""
    if getattr(member.guild_permissions, "administrator", False):
        return True

    if REQUIRED_ROLE_NAME:
        return any(
            role.name.lower() == REQUIRED_ROLE_NAME.lower()
            for role in getattr(member, "roles", [])
        )

    return True


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
                assigned_username TEXT,
                duration TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                created_by_id INTEGER NOT NULL,
                created_by_name TEXT NOT NULL,
                status TEXT DEFAULT 'active'
            )
        """)
        conn.commit()

        # Database Migration Check: ensure all required columns exist in older tables
        cursor.execute("PRAGMA table_info(keys)")
        existing_cols = {col["name"] for col in cursor.fetchall()}

        required_columns = {
            "assigned_username": "TEXT",
            "duration": "TEXT",
            "expires_at": "TEXT",
            "status": "TEXT DEFAULT 'active'"
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


def save_key_to_db(key: str, assigned_username: str, duration_label: str, expires_at: Optional[datetime], user_id: int, user_name: str):
    """Saves a generated key to SQLite."""
    now_str = datetime.now(timezone.utc).isoformat()
    expires_str = expires_at.isoformat() if expires_at else "Lifetime"

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO keys (key, assigned_username, duration, created_at, expires_at, created_by_id, created_by_name, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'active')
        """, (key, assigned_username, duration_label, now_str, expires_str, user_id, str(user_name)))
        conn.commit()


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
# KEY GENERATOR ENGINE
# ==========================================
def generate_single_key() -> str:
    """Generates a cryptographically secure, unique license key."""
    max_attempts = 1000
    attempts = 0

    while attempts < max_attempts:
        random_section = "".join(
            secrets.choice(ALLOWED_CHARACTERS) for _ in range(KEY_LENGTH)
        )
        full_key = f"{KEY_PREFIX}-{random_section}"

        if full_key not in generated_keys:
            generated_keys.add(full_key)
            return full_key

        attempts += 1

    raise RuntimeError("Key space exhausted or too many collisions occurred.")


# ==========================================
# DISCORD MODALS (POP-UP DIALOGS)
# ==========================================
class GenerateKeyModal(discord.ui.Modal, title="Generate License Key"):
    username_input = discord.ui.TextInput(
        label="Custom Username / Name (Optional)",
        placeholder="Leave blank to auto-generate username",
        required=False,
        max_length=50
    )

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)

        user_input_val = self.username_input.value.strip() if self.username_input.value else ""
        if not user_input_val:
            auto_tag = "".join(secrets.choice(ALLOWED_CHARACTERS) for _ in range(4))
            username = f"User-{auto_tag}"
        else:
            username = user_input_val

        try:
            expires_at = None
            duration_label = "Lifetime"
            key = generate_single_key()
            save_key_to_db(key, username, duration_label, expires_at, interaction.user.id, str(interaction.user))
        except Exception as err:
            await interaction.followup.send(f"❌ Error: {err}", ephemeral=True)
            return

        embed = discord.Embed(
            title="🔑 Key Generated Successfully",
            color=discord.Color.green(),
            timestamp=datetime.now(timezone.utc)
        )
        embed.add_field(name="License Key", value=f"`{key}`", inline=False)
        embed.add_field(name="Assigned User", value=username, inline=True)
        embed.add_field(name="Status", value="Active (Lifetime)", inline=True)
        embed.set_footer(text=f"Generated by {interaction.user}")

        await interaction.followup.send(embed=embed, ephemeral=True)


class KeyInfoModal(discord.ui.Modal, title="Check Key Information"):
    key_input = discord.ui.TextInput(
        label="License Key",
        placeholder="Enter key (e.g. ADAMCORP-7K2P9)",
        required=True,
        max_length=40
    )

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        key_str = self.key_input.value.strip()

        row = get_key_info(key_str)
        if not row:
            await interaction.followup.send(f"❌ License key `{key_str}` was not found in database.", ephemeral=True)
            return

        embed = discord.Embed(
            title=f"🔍 Key Information: {row['key']}",
            color=discord.Color.blue(),
            timestamp=datetime.now(timezone.utc)
        )
        embed.add_field(name="Status", value=f"**{str(row['status']).upper()}**", inline=True)
        embed.add_field(name="Assigned User", value=str(row['assigned_username']), inline=True)
        embed.add_field(name="Duration", value=str(row['duration']), inline=True)
        embed.add_field(name="Created At", value=str(row['created_at'])[:19], inline=True)
        embed.add_field(name="Expires At", value=str(row['expires_at'])[:19], inline=True)
        embed.add_field(name="Created By", value=str(row['created_by_name']), inline=True)

        await interaction.followup.send(embed=embed, ephemeral=True)


class DeleteKeyModal(discord.ui.Modal, title="Delete License Key"):
    key_input = discord.ui.TextInput(
        label="License Key to Delete",
        placeholder="Enter key (e.g. ADAMCORP-7K2P9)",
        required=True,
        max_length=40
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
# DISCORD BUTTON PANEL VIEW
# ==========================================
class LicensePanelView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)  # Persistent view across restarts

    @discord.ui.button(
        label="Generate Key",
        style=discord.ButtonStyle.success,
        emoji="🔑",
        custom_id="btn_generate_key",
        row=0
    )
    async def btn_generate_key(self, interaction: discord.Interaction, button: discord.ui.Button):
        if isinstance(interaction.user, discord.Member) and not check_user_permission(interaction.user):
            await interaction.response.send_message(
                f"❌ You need the **{REQUIRED_ROLE_NAME}** role to generate keys.",
                ephemeral=True
            )
            return
        await interaction.response.send_modal(GenerateKeyModal())

    @discord.ui.button(
        label="Key Info",
        style=discord.ButtonStyle.primary,
        emoji="🔍",
        custom_id="btn_key_info",
        row=0
    )
    async def btn_key_info(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(KeyInfoModal())

    @discord.ui.button(
        label="Delete Key",
        style=discord.ButtonStyle.danger,
        emoji="🗑️",
        custom_id="btn_delete_key",
        row=1
    )
    async def btn_delete_key(self, interaction: discord.Interaction, button: discord.ui.Button):
        if isinstance(interaction.user, discord.Member) and not check_user_permission(interaction.user):
            await interaction.response.send_message(
                f"❌ You need the **{REQUIRED_ROLE_NAME}** role or Administrator permissions to delete keys.",
                ephemeral=True
            )
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

    try:
        # Sync globally first
        synced_global = await bot.tree.sync()
        print(f"[+] Synced {len(synced_global)} slash command(s) globally.")

        # Sync instantly to all joined guilds so commands appear immediately
        for guild in bot.guilds:
            try:
                bot.tree.copy_global_to(guild=guild)
                synced_guild = await bot.tree.sync(guild=guild)
                print(f"[+] Synced {len(synced_guild)} slash command(s) instantly to Guild '{guild.name}' (ID: {guild.id})")
            except Exception as ge:
                print(f"[!] Guild sync warning for {guild.name}: {ge}")
    except Exception as e:
        print(f"[!] Failed to sync slash commands: {e}")


# ==========================================
# SLASH COMMANDS
# ==========================================
@bot.tree.command(
    name="panel",
    description="Display the License Management Control Panel."
)
async def panel_command(interaction: discord.Interaction):
    """Slash command to post the license management control panel embed with buttons."""
    if isinstance(interaction.user, discord.Member) and not check_user_permission(interaction.user):
        await interaction.response.send_message(
            f"❌ You need Administrator permissions or the **{REQUIRED_ROLE_NAME}** role to use `/panel`.",
            ephemeral=True
        )
        return

    embed = discord.Embed(
        description=(
            "All key actions in one place — results are **private** to you.\n\n"
            "> **Generate** — username ➔ duration ➔ confirm generate\n"
            "> **Key Info** — check status and expiry\n"
            "> **Delete Key** — remove a key *(owner / admin)*\n\n"
            f"*You need the **{REQUIRED_ROLE_NAME}** role to generate keys.*"
        ),
        color=discord.Color.dark_theme()
    )

    await interaction.response.send_message(
        embed=embed,
        view=LicensePanelView()
    )


@bot.tree.command(
    name="generate",
    description="Generate unique license keys (e.g. ADAMCORP-7K2P9)."
)
@app_commands.describe(
    amount="Number of unique keys to generate (1 to 20). Default is 1."
)
async def generate_command(
    interaction: discord.Interaction,
    amount: Optional[app_commands.Range[int, 1, 20]] = 1
):
    """Slash command: /generate [amount]"""
    if isinstance(interaction.user, discord.Member) and not check_user_permission(interaction.user):
        await interaction.response.send_message(
            f"❌ You need Administrator permissions or the **{REQUIRED_ROLE_NAME}** role to generate keys.",
            ephemeral=True
        )
        return

    amount_val = amount if amount is not None else 1
    await interaction.response.defer(ephemeral=True)

    try:
        keys = []
        for _ in range(amount_val):
            k = generate_single_key()
            save_key_to_db(k, "Unassigned", "Lifetime", None, interaction.user.id, str(interaction.user))
            keys.append(k)
    except Exception as err:
        await interaction.followup.send(f"❌ Error generating keys: {err}", ephemeral=True)
        return

    if amount_val == 1:
        response_text = f"Your generated key: `{keys[0]}`"
    else:
        formatted_list = "\n".join(keys)
        response_text = (
            f"Generated **{amount_val}** unique keys:\n"
            f"```text\n{formatted_list}\n```"
        )

    await interaction.followup.send(response_text, ephemeral=True)


@bot.tree.command(
    name="stats",
    description="View license key database statistics."
)
async def stats_command(interaction: discord.Interaction):
    """Slash command: /stats"""
    if isinstance(interaction.user, discord.Member) and not check_user_permission(interaction.user):
        await interaction.response.send_message(
            f"❌ You need Administrator permissions or the **{REQUIRED_ROLE_NAME}** role to view stats.",
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
    embed.set_footer(text=f"Requested by {interaction.user}")

    await interaction.response.send_message(embed=embed, ephemeral=True)


# ==========================================
# BOT ENTRY POINT
# ==========================================
if __name__ == "__main__":
    if not DISCORD_TOKEN or DISCORD_TOKEN.strip() == "" or DISCORD_TOKEN == "YOUR_BOT_TOKEN_HERE":
        print("[!] CRITICAL ERROR: Discord bot token not found in environment!")
        print("Please copy `.env.example` to `.env` and set DISCORD_TOKEN=your_bot_token")
    else:
        init_db()
        print("[*] Starting Discord License Generator Bot...")
        bot.run(DISCORD_TOKEN)
