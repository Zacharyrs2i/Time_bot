import os

from dotenv import load_dotenv

load_dotenv()  # loads .env from current working directory

import re
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from typing import Optional, List, Tuple, Dict

import discord
from discord import app_commands

TOKEN = os.getenv("DISCORD_BOT_TOKEN")
GUILD_ID = int(os.getenv("GUILD_ID", "0"))
SCHED_PARENT_CHANNEL_ID = int(os.getenv("SCHED_PARENT_CHANNEL_ID", "0"))
ADMIN_ROLE_ID = int(os.getenv("ADMIN_ROLE_ID", "0"))
ADMIN_CHANNEL_ID = int(os.getenv("ADMIN_CHANNEL_ID", "0"))  # optional

if not TOKEN or not GUILD_ID or not SCHED_PARENT_CHANNEL_ID or not ADMIN_ROLE_ID:
    raise RuntimeError(
        "Missing required env vars: DISCORD_BOT_TOKEN, GUILD_ID, SCHED_PARENT_CHANNEL_ID, ADMIN_ROLE_ID"
    )

CT_TZ = ZoneInfo("America/Chicago")
LEAD_TIME_HOURS = 6
ROUND_MAX = 2
INVALID_LIMIT = 10
DEADLINE_HOURS = 36
REMINDER_HOURS = 12
MIDPOINT_MAX_GAP = timedelta(hours=2)  # your default
TIME_INCREMENT_MINUTES = 30

# Captain input format: "MM/DD/YYYY HH:MM, MM/DD/YYYY HH:MM, MM/DD/YYYY HH:MM"
ENTRY_RE = re.compile(r"^\s*(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2})\s*$")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(dt: datetime) -> str:
    # store as UTC ISO
    return dt.astimezone(timezone.utc).isoformat()


def from_iso(s: str) -> datetime:
    return datetime.fromisoformat(s)


def round_to_increment(dt: datetime, minutes: int) -> datetime:
    """Round to nearest increment minutes. Halfway rounds up."""
    # dt is timezone-aware
    secs = dt.timestamp()
    inc = minutes * 60
    rem = secs % inc
    if rem == 0:
        return dt
    # nearest with half-up
    down = secs - rem
    up = down + inc
    if rem < inc / 2:
        return datetime.fromtimestamp(down, tz=dt.tzinfo)
    else:
        return datetime.fromtimestamp(up, tz=dt.tzinfo)


def parse_three_times(
    raw: str,
    captain_tz: ZoneInfo,
) -> Tuple[Optional[List[datetime]], Optional[str]]:
    """
    Parse captain input into 3 timezone-aware datetimes in captain's timezone.
    Then validation & conversion will happen separately.
    """
    parts = [p.strip() for p in raw.split(",")]
    if len(parts) != 3:
        return None, "Exactly 3 times are required, separated by commas."

    parsed: List[datetime] = []
    for p in parts:
        m = ENTRY_RE.match(p)
        if not m:
            return None, "Invalid format."
        text = m.group(1)
        try:
            dt_naive = datetime.strptime(text, "%m/%d/%Y %H:%M")
        except ValueError:
            return None, "Invalid date/time value."
        dt_local = dt_naive.replace(tzinfo=captain_tz)
        parsed.append(dt_local)

    # uniqueness
    if len({d.isoformat() for d in parsed}) != 3:
        return None, "Times must be 3 unique entries."

    return parsed, None


def validate_times(
    times_local: List[datetime],
    now_utc: datetime,
) -> Optional[str]:
    """Validate lead time + 30-min increments + future."""
    now_ct = now_utc.astimezone(CT_TZ)
    for dt_local in times_local:
        dt_ct = dt_local.astimezone(CT_TZ)

        # 30-min increments: minutes must be 00 or 30
        if dt_ct.minute not in (0, 30) or dt_ct.second != 0:
            return "Times must be in 30-minute increments (HH:00 or HH:30)."

        # future + lead-time rule (>= 6 hours from submission time)
        if dt_ct <= now_ct:
            return "All times must be in the future."
        if dt_ct < (now_ct + timedelta(hours=LEAD_TIME_HOURS)):
            return f"All times must be at least {LEAD_TIME_HOURS} hours from now."

    return None


def fmt_ct(dt_any_tz: datetime) -> str:
    dt_ct = dt_any_tz.astimezone(CT_TZ)
    return dt_ct.strftime("%m/%d/%Y %I:%M %p CT")


def find_exact_match(a_ct: List[datetime], b_ct: List[datetime]) -> Optional[datetime]:
    set_a = {d.isoformat() for d in a_ct}
    common = [d for d in b_ct if d.isoformat() in set_a]
    if not common:
        return None
    return min(common)  # earliest


def closest_pair(a_ct: List[datetime], b_ct: List[datetime]) -> Tuple[datetime, datetime, timedelta]:
    best = None
    for a in a_ct:
        for b in b_ct:
            diff = abs(a - b)
            if best is None or diff < best[2]:
                best = (a, b, diff)
            elif diff == best[2]:
                # tie-break: prefer same-date
                same_date_new = (a.date() == b.date())
                same_date_old = (best[0].date() == best[1].date())
                if same_date_new and not same_date_old:
                    best = (a, b, diff)
                elif same_date_new == same_date_old:
                    # tie-break: earlier midpoint
                    mid_new = min(a, b) + diff / 2
                    mid_old = min(best[0], best[1]) + best[2] / 2
                    if mid_new < mid_old:
                        best = (a, b, diff)
    assert best is not None
    return best


class DB:
    def __init__(self, path: str = "scheduler.db"):
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self._init()

    def _init(self):
        cur = self.conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS timezones (
                user_id TEXT PRIMARY KEY,
                tz_name TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                session_id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id TEXT NOT NULL,
                creator_id TEXT NOT NULL,
                team_a TEXT NOT NULL,
                team_b TEXT NOT NULL,
                captain_a_id TEXT NOT NULL,
                captain_b_id TEXT NOT NULL,
                division INTEGER NOT NULL,
                parent_channel_id TEXT NOT NULL,
                thread_id TEXT,
                status TEXT NOT NULL, -- active, scheduled, escalated, cancelled, needs_admin
                mode TEXT NOT NULL,   -- dm, thread
                round INTEGER NOT NULL,
                created_at_utc TEXT NOT NULL,
                deadline_at_utc TEXT NOT NULL,
                reminder_sent INTEGER NOT NULL DEFAULT 0,
                scheduled_time_utc TEXT,
                invalid_a INTEGER NOT NULL DEFAULT 0,
                invalid_b INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS round_submissions (
                session_id INTEGER NOT NULL,
                round INTEGER NOT NULL,
                side TEXT NOT NULL, -- A or B
                times_ct_json TEXT NOT NULL,
                submitted_at_utc TEXT NOT NULL,
                PRIMARY KEY (session_id, round, side)
            )
            """
        )
        self.conn.commit()

    def set_timezone(self, user_id: int, tz_name: str):
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO timezones(user_id, tz_name) VALUES(?, ?) "
            "ON CONFLICT(user_id) DO UPDATE SET tz_name=excluded.tz_name",
            (str(user_id), tz_name),
        )
        self.conn.commit()

    def get_timezone(self, user_id: int) -> ZoneInfo:
        cur = self.conn.cursor()
        cur.execute("SELECT tz_name FROM timezones WHERE user_id=?", (str(user_id),))
        row = cur.fetchone()
        if not row:
            return CT_TZ
        try:
            return ZoneInfo(row["tz_name"])
        except Exception:
            return CT_TZ

    def create_session(
        self,
        guild_id: int,
        creator_id: int,
        team_a: str,
        team_b: str,
        captain_a_id: int,
        captain_b_id: int,
        division: int,
        parent_channel_id: int,
    ) -> int:
        now = utcnow()
        deadline = now + timedelta(hours=DEADLINE_HOURS)
        cur = self.conn.cursor()
        cur.execute(
            """
            INSERT INTO sessions(
                guild_id, creator_id, team_a, team_b, captain_a_id, captain_b_id, division,
                parent_channel_id, status, mode, round, created_at_utc, deadline_at_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', 'dm', 1, ?, ?)
            """,
            (
                str(guild_id),
                str(creator_id),
                team_a,
                team_b,
                str(captain_a_id),
                str(captain_b_id),
                int(division),
                str(parent_channel_id),
                to_iso(now),
                to_iso(deadline),
            ),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def set_thread(self, session_id: int, thread_id: int):
        cur = self.conn.cursor()
        cur.execute("UPDATE sessions SET thread_id=? WHERE session_id=?", (str(thread_id), session_id))
        self.conn.commit()

    def get_session(self, session_id: int) -> Optional[sqlite3.Row]:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM sessions WHERE session_id=?", (session_id,))
        return cur.fetchone()

    def find_active_session_for_user(self, user_id: int) -> Optional[sqlite3.Row]:
        cur = self.conn.cursor()
        cur.execute(
            """
            SELECT * FROM sessions
            WHERE status IN ('active','escalated','needs_admin')
              AND (captain_a_id=? OR captain_b_id=?)
            ORDER BY session_id DESC
            """,
            (str(user_id), str(user_id)),
        )
        return cur.fetchone()

    def get_submission(self, session_id: int, round_num: int, side: str) -> Optional[sqlite3.Row]:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT * FROM round_submissions WHERE session_id=? AND round=? AND side=?",
            (session_id, round_num, side),
        )
        return cur.fetchone()

    def save_submission(self, session_id: int, round_num: int, side: str, times_ct: List[datetime]):
        cur = self.conn.cursor()
        cur.execute(
            """
            INSERT INTO round_submissions(session_id, round, side, times_ct_json, submitted_at_utc)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                session_id,
                round_num,
                side,
                json.dumps([d.astimezone(CT_TZ).isoformat() for d in times_ct]),
                to_iso(utcnow()),
            ),
        )
        self.conn.commit()

    def bump_invalid(self, session_id: int, side: str) -> int:
        col = "invalid_a" if side == "A" else "invalid_b"
        cur = self.conn.cursor()
        cur.execute(f"UPDATE sessions SET {col}={col}+1 WHERE session_id=?", (session_id,))
        self.conn.commit()
        cur.execute(f"SELECT {col} FROM sessions WHERE session_id=?", (session_id,))
        return int(cur.fetchone()[0])

    def set_mode(self, session_id: int, mode: str):
        cur = self.conn.cursor()
        cur.execute("UPDATE sessions SET mode=? WHERE session_id=?", (mode, session_id))
        self.conn.commit()

    def set_round(self, session_id: int, round_num: int):
        cur = self.conn.cursor()
        cur.execute("UPDATE sessions SET round=? WHERE session_id=?", (round_num, session_id))
        self.conn.commit()

    def set_status(self, session_id: int, status: str):
        cur = self.conn.cursor()
        cur.execute("UPDATE sessions SET status=? WHERE session_id=?", (status, session_id))
        self.conn.commit()

    def set_reminder_sent(self, session_id: int):
        cur = self.conn.cursor()
        cur.execute("UPDATE sessions SET reminder_sent=1 WHERE session_id=?", (session_id,))
        self.conn.commit()

    def set_scheduled_time(self, session_id: int, when_utc: datetime):
        cur = self.conn.cursor()
        cur.execute(
            "UPDATE sessions SET status='scheduled', scheduled_time_utc=? WHERE session_id=?",
            (to_iso(when_utc), session_id),
        )
        self.conn.commit()

    def list_open_sessions(self) -> List[sqlite3.Row]:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM sessions WHERE status IN ('active','escalated','needs_admin')")
        return cur.fetchall()


db = DB()


class SchedulerBot(discord.Client):
    def __init__(self):
        intents = discord.Intents.default()
        intents.message_content = True  # needed to read DMs and thread messages
        super().__init__(intents=intents)
        self.tree = app_commands.CommandTree(self)

    async def setup_hook(self):
        guild = discord.Object(id=GUILD_ID)
        self.tree.copy_global_to(guild=guild)
        await self.tree.sync(guild=guild)
        self.loop.create_task(self.enforcement_loop())


bot = SchedulerBot()


def is_admin(interaction: discord.Interaction) -> bool:
    if not interaction.user or not isinstance(interaction.user, discord.Member):
        return False
    # allow administrators
    if interaction.user.guild_permissions.administrator:
        return True
    # allow admin role
    return any(r.id == ADMIN_ROLE_ID for r in interaction.user.roles)


async def notify_admins(guild: discord.Guild, content: str, thread: Optional[discord.Thread] = None):
    role_mention = f"<@&{ADMIN_ROLE_ID}>"
    msg = f"{role_mention} {content}"

    if ADMIN_CHANNEL_ID:
        ch = guild.get_channel(ADMIN_CHANNEL_ID)
        if isinstance(ch, discord.TextChannel):
            await ch.send(msg)
            return

    if thread:
        await thread.send(msg)


async def dm_or_fail(user: discord.User, content: str) -> bool:
    try:
        await user.send(content)
        return True
    except Exception:
        return False


def example_text() -> str:
    return "Example: `12/16/2025 20:00, 12/20/2025 21:00, 12/18/2025 20:00`"


async def post_round_summary(thread: discord.Thread, team_a: str, team_b: str, a_times: List[datetime], b_times: List[datetime], round_num: int):
    a_line = ", ".join(fmt_ct(t) for t in a_times)
    b_line = ", ".join(fmt_ct(t) for t in b_times)
    await thread.send(
        f"**Round {round_num} submissions (CT):**\n"
        f"**{team_a}:** {a_line}\n"
        f"**{team_b}:** {b_line}"
    )


async def post_match_result(thread: discord.Thread, when_ct: datetime, division: int, team_a: str, team_b: str, note: str):
    await thread.send(
        f"✅ **Scheduled** ({note})\n"
        f"**Match:** {team_a} vs {team_b} (Division {division})\n"
        f"**Start:** {fmt_ct(when_ct)}"
    )


@bot.tree.command(name="set_timezone", description="Set your timezone (IANA name), e.g. America/New_York")
async def set_timezone(interaction: discord.Interaction, tz_name: str):
    try:
        ZoneInfo(tz_name)
    except Exception:
        await interaction.response.send_message(
            "Invalid timezone. Use an IANA name like `America/Chicago` or `America/New_York`.", ephemeral=True
        )
        return
    db.set_timezone(interaction.user.id, tz_name)
    await interaction.response.send_message(f"Timezone set to `{tz_name}`.", ephemeral=True)


@bot.tree.command(name="sched_start", description="Start scheduling between two teams/captains.")
async def sched_start(
    interaction: discord.Interaction,
    team_a: str,
    team_b: str,
    captain_a: discord.Member,
    captain_b: discord.Member,
    division: int,
):
    if not is_admin(interaction):
        await interaction.response.send_message("You don't have permission to run this.", ephemeral=True)
        return

    parent = interaction.guild.get_channel(SCHED_PARENT_CHANNEL_ID)
    if not isinstance(parent, discord.TextChannel):
        await interaction.response.send_message("Scheduling parent channel misconfigured.", ephemeral=True)
        return

    session_id = db.create_session(
        guild_id=interaction.guild_id,
        creator_id=interaction.user.id,
        team_a=team_a,
        team_b=team_b,
        captain_a_id=captain_a.id,
        captain_b_id=captain_b.id,
        division=division,
        parent_channel_id=parent.id,
    )

    thread = await parent.create_thread(
        name=f"sched-{team_a}-vs-{team_b}-#{session_id}",
        type=discord.ChannelType.private_thread if parent.is_news() is False else discord.ChannelType.public_thread,
        auto_archive_duration=1440,
        reason="League scheduling session",
    )
    db.set_thread(session_id, thread.id)

    await thread.add_user(captain_a)
    await thread.add_user(captain_b)
    await thread.send(
        f"🗓️ **Scheduling opened** for **{team_a} vs {team_b}** (Division {division}).\n"
        f"Captains have been notified. **Deadline: {DEADLINE_HOURS} hours.**\n"
        f"Session ID: **{session_id}**"
    )

    # DM prompts (Round 1)
    prompt = (
        f"League Scheduling Request — **{team_a} vs {team_b}** (Division {division})\n"
        f"Reply with **exactly 3** start times (comma-separated) in this format:\n"
        f"`MM/DD/YYYY HH:MM, MM/DD/YYYY HH:MM, MM/DD/YYYY HH:MM`\n"
        f"{example_text()}\n"
        f"- 30-minute increments only (:00 or :30)\n"
        f"- At least {LEAD_TIME_HOURS} hours from now\n"
        f"Round 1 of {ROUND_MAX}."
    )

    ok_a = await dm_or_fail(captain_a, prompt)
    ok_b = await dm_or_fail(captain_b, prompt)

    if not (ok_a and ok_b):
        # Switch to thread mode immediately
        db.set_mode(session_id, "thread")
        await thread.send(
            "⚠️ **DM delivery failed** for at least one captain.\n"
            "Captains must submit their 3 times **in this thread** using:\n"
            f"`MM/DD/YYYY HH:MM, MM/DD/YYYY HH:MM, MM/DD/YYYY HH:MM`\n"
            f"{example_text()}"
        )
        await notify_admins(interaction.guild, f"DM delivery failed for session {session_id}. Scheduling moved to thread.", thread)

    await interaction.response.send_message(f"Started scheduling session **{session_id}**. Thread: {thread.mention}", ephemeral=True)


@bot.tree.command(name="sched_status", description="Show status of a scheduling session.")
async def sched_status(interaction: discord.Interaction, session_id: int):
    s = db.get_session(session_id)
    if not s:
        await interaction.response.send_message("Session not found.", ephemeral=True)
        return

    thread_id = s["thread_id"]
    round_num = int(s["round"])
    status = s["status"]
    mode = s["mode"]
    deadline = from_iso(s["deadline_at_utc"]).astimezone(CT_TZ).strftime("%m/%d/%Y %I:%M %p CT")

    sub_a = db.get_submission(session_id, round_num, "A") is not None
    sub_b = db.get_submission(session_id, round_num, "B") is not None

    await interaction.response.send_message(
        f"**Session {session_id}** — {s['team_a']} vs {s['team_b']} (Div {s['division']})\n"
        f"Status: **{status}** | Mode: **{mode}** | Round: **{round_num}**\n"
        f"Round submissions: Team A={'✅' if sub_a else '⏳'} Team B={'✅' if sub_b else '⏳'}\n"
        f"Deadline: **{deadline}**\n"
        f"Thread: <#{thread_id}>" if thread_id else "Thread: (not set)",
        ephemeral=True,
    )


@bot.tree.command(name="sched_cancel", description="Cancel a scheduling session.")
async def sched_cancel(interaction: discord.Interaction, session_id: int, reason: str = "Cancelled by admin"):
    if not is_admin(interaction):
        await interaction.response.send_message("You don't have permission to run this.", ephemeral=True)
        return
    s = db.get_session(session_id)
    if not s:
        await interaction.response.send_message("Session not found.", ephemeral=True)
        return
    db.set_status(session_id, "cancelled")
    thread = interaction.guild.get_thread(int(s["thread_id"])) if s["thread_id"] else None
    if thread:
        await thread.send(f"🛑 **Session cancelled.** Reason: {reason}")
    await interaction.response.send_message("Cancelled.", ephemeral=True)


@bot.tree.command(name="sched_assign", description="Admin: manually assign a match time (CT).")
async def sched_assign(interaction: discord.Interaction, session_id: int, start_time_ct: str):
    if not is_admin(interaction):
        await interaction.response.send_message("You don't have permission to run this.", ephemeral=True)
        return
    s = db.get_session(session_id)
    if not s:
        await interaction.response.send_message("Session not found.", ephemeral=True)
        return

    # parse CT explicitly for admin assignment
    try:
        dt_naive = datetime.strptime(start_time_ct.strip(), "%m/%d/%Y %H:%M")
        dt_ct = dt_naive.replace(tzinfo=CT_TZ)
    except ValueError:
        await interaction.response.send_message("Invalid format. Use `MM/DD/YYYY HH:MM` (CT).", ephemeral=True)
        return

    if dt_ct.minute not in (0, 30):
        await interaction.response.send_message("Time must be in 30-minute increments (:00 or :30).", ephemeral=True)
        return
    if dt_ct <= utcnow().astimezone(CT_TZ):
        await interaction.response.send_message("Time must be in the future.", ephemeral=True)
        return

    db.set_scheduled_time(session_id, dt_ct.astimezone(timezone.utc))
    thread = interaction.guild.get_thread(int(s["thread_id"])) if s["thread_id"] else None
    if thread:
        await post_match_result(thread, dt_ct, int(s["division"]), s["team_a"], s["team_b"], "admin assigned")
    await interaction.response.send_message("Assigned.", ephemeral=True)


async def handle_submission(
    author: discord.User,
    content: str,
    session: sqlite3.Row,
    source: str,  # "dm" or "thread"
    thread: Optional[discord.Thread],
):
    session_id = int(session["session_id"])
    round_num = int(session["round"])
    team_a = session["team_a"]
    team_b = session["team_b"]
    division = int(session["division"])

    side = "A" if str(author.id) == session["captain_a_id"] else "B"

    # No overrides: if already submitted this round, ignore
    if db.get_submission(session_id, round_num, side):
        if source == "dm":
            await author.send(f"Your Round {round_num} submission is already locked. Wait for the next round.")
        else:
            await thread.send(f"<@{author.id}> your Round {round_num} submission is already locked. Wait for the next round.")
        return

    cap_tz = db.get_timezone(author.id)
    times_local, err = parse_three_times(content, cap_tz)
    if err:
        invalid_count = db.bump_invalid(session_id, side)
        msg = f"{err} Please use: {example_text()}"
        if source == "dm":
            await author.send(msg)
        else:
            await thread.send(f"<@{author.id}> {msg}")

        if invalid_count >= INVALID_LIMIT:
            # notify creator
            creator_id = int(session["creator_id"])
            creator = await bot.fetch_user(creator_id)
            await dm_or_fail(
                creator,
                f"⚠️ Captain {side} ({author}) has submitted invalid scheduling input {invalid_count} times "
                f"for session {session_id}. Thread: <#{session['thread_id']}>",
            )
        return

    # Validate (in CT)
    val_err = validate_times(times_local, utcnow())
    if val_err:
        invalid_count = db.bump_invalid(session_id, side)
        msg = f"{val_err} {example_text()}"
        if source == "dm":
            await author.send(msg)
        else:
            await thread.send(f"<@{author.id}> {msg}")
        if invalid_count >= INVALID_LIMIT:
            creator_id = int(session["creator_id"])
            creator = await bot.fetch_user(creator_id)
            await dm_or_fail(
                creator,
                f"⚠️ Captain {side} ({author}) has submitted invalid scheduling input {invalid_count} times "
                f"for session {session_id}. Thread: <#{session['thread_id']}>",
            )
        return

    # Store as CT-aware
    times_ct = [t.astimezone(CT_TZ) for t in times_local]
    db.save_submission(session_id, round_num, side, times_ct)

    # Confirm receipt (DM only)
    if source == "dm":
        await author.send(f"✅ Received your Round {round_num} times (stored/displayed in CT).")

    # If both submitted this round, post summary + compare
    sub_a = db.get_submission(session_id, round_num, "A")
    sub_b = db.get_submission(session_id, round_num, "B")
    if not (sub_a and sub_b):
        # If thread exists, post status update
        if thread:
            await thread.send(
                f"✅ {team_a if side=='A' else team_b} submitted Round {round_num}. "
                f"Waiting on **{team_b if side=='A' else team_a}**."
            )
        return

    # Load stored times
    a_times = [datetime.fromisoformat(x) for x in json.loads(sub_a["times_ct_json"])]
    b_times = [datetime.fromisoformat(x) for x in json.loads(sub_b["times_ct_json"])]

    # Post both sets to thread after both submit (your rule)
    if thread:
        await post_round_summary(thread, team_a, team_b, a_times, b_times, round_num)

    # Exact match?
    match = find_exact_match(a_times, b_times)
    if match:
        db.set_scheduled_time(session_id, match.astimezone(timezone.utc))
        if thread:
            await post_match_result(thread, match, division, team_a, team_b, "exact match")
        return

    # No match
    if thread:
        await thread.send(f"❌ **No exact match found** in Round {round_num}.")

    if round_num < ROUND_MAX and session["mode"] == "dm":
        # DM round 2 request (private)
        next_round = round_num + 1
        db.set_round(session_id, next_round)
        cap_a = await bot.fetch_user(int(session["captain_a_id"]))
        cap_b = await bot.fetch_user(int(session["captain_b_id"]))
        msg = (
            f"No exact match was found. Please submit **Round {next_round}** alternate times in the same format.\n"
            f"{example_text()}\n"
            f"- 30-minute increments only (:00 or :30)\n"
            f"- At least {LEAD_TIME_HOURS} hours from now"
        )
        ok_a = await dm_or_fail(cap_a, msg)
        ok_b = await dm_or_fail(cap_b, msg)
        if not (ok_a and ok_b):
            # DM failed mid-process -> move to thread mode
            db.set_mode(session_id, "thread")
            if thread:
                await thread.send(
                    "⚠️ DM delivery failed during scheduling. "
                    "Captains must submit subsequent rounds **in this thread** using the standard format."
                )
                guild = thread.guild
                await notify_admins(guild, f"DM delivery failed for session {session_id}. Scheduling moved to thread.", thread)
        else:
            if thread:
                await thread.send(f"🔁 **Round {next_round} requested privately via DM.**")
        return

    # Round 2 failed (or thread mode): escalate
    db.set_status(session_id, "escalated")
    if thread:
        await thread.send(
            "⚠️ **No agreement after two private rounds.** Scheduling has moved to this thread. Admins have been notified."
        )
        await notify_admins(thread.guild, f"Session {session_id} escalated (no match after Round 2).", thread)


@bot.event
async def on_message(message: discord.Message):
    if message.author.bot:
        return

    # DM handling
    if isinstance(message.channel, discord.DMChannel):
        session = db.find_active_session_for_user(message.author.id)
        if not session:
            return
        # only accept DM submissions if session mode is dm
        if session["mode"] != "dm":
            return

        thread = None
        if session["thread_id"]:
            thread = bot.get_channel(int(session["thread_id"]))  # thread may be cached
            if not isinstance(thread, discord.Thread):
                try:
                    thread = await bot.fetch_channel(int(session["thread_id"]))
                except Exception:
                    thread = None

        await handle_submission(message.author, message.content, session, "dm", thread)
        return

    # Thread handling (used on DM-fail or after escalation)
    if isinstance(message.channel, discord.Thread):
        # find session by thread_id
        thread_id = message.channel.id
        # quick lookup
        # (SQLite simple query)
        cur = db.conn.cursor()
        cur.execute(
            "SELECT * FROM sessions WHERE thread_id=? AND status IN ('active','escalated','needs_admin')",
            (str(thread_id),),
        )
        session = cur.fetchone()
        if not session:
            return

        # only captains can submit
        if str(message.author.id) not in (session["captain_a_id"], session["captain_b_id"]):
            return

        # accept thread submissions only if mode==thread OR status escalated
        if session["mode"] != "thread" and session["status"] != "escalated":
            return

        await handle_submission(message.author, message.content, session, "thread", message.channel)
        return


async def enforce_12h(session: sqlite3.Row, thread: Optional[discord.Thread]):
    session_id = int(session["session_id"])
    creator_id = int(session["creator_id"])
    creator = await bot.fetch_user(creator_id)

    round_num = int(session["round"])
    sub_a = db.get_submission(session_id, round_num, "A") is not None
    sub_b = db.get_submission(session_id, round_num, "B") is not None

    if sub_a and sub_b:
        return

    missing = []
    if not sub_a:
        missing.append("Team A captain")
    if not sub_b:
        missing.append("Team B captain")

    await dm_or_fail(
        creator,
        f"⏳ **12-hour reminder**: Session {session_id} is still waiting on {', '.join(missing)}.\n"
        f"Thread: <#{session['thread_id']}>",
    )
    db.set_reminder_sent(session_id)


async def enforce_36h(session: sqlite3.Row, thread: Optional[discord.Thread]):
    session_id = int(session["session_id"])
    team_a = session["team_a"]
    team_b = session["team_b"]
    division = int(session["division"])

    # Find latest round where each side submitted (prefer current round)
    def latest_times(side: str) -> Optional[List[datetime]]:
        cur = db.conn.cursor()
        cur.execute(
            """
            SELECT * FROM round_submissions
            WHERE session_id=? AND side=?
            ORDER BY round DESC LIMIT 1
            """,
            (session_id, side),
        )
        row = cur.fetchone()
        if not row:
            return None
        return [datetime.fromisoformat(x) for x in json.loads(row["times_ct_json"])]

    a_times = latest_times("A")
    b_times = latest_times("B")

    # Case: only one side submitted
    if a_times and not b_times:
        chosen = min(a_times)
        db.set_scheduled_time(session_id, chosen.astimezone(timezone.utc))
        if thread:
            await post_match_result(thread, chosen, division, team_a, team_b, "deadline (one-side earliest)")
        return

    if b_times and not a_times:
        chosen = min(b_times)
        db.set_scheduled_time(session_id, chosen.astimezone(timezone.utc))
        if thread:
            await post_match_result(thread, chosen, division, team_a, team_b, "deadline (one-side earliest)")
        return

    if not a_times and not b_times:
        # nobody submitted; needs admin
        db.set_status(session_id, "needs_admin")
        if thread:
            await thread.send("⏰ Deadline reached, but no captain submissions exist. Admin assignment required.")
            await notify_admins(thread.guild, f"Session {session_id} needs admin assignment (no submissions).", thread)
        return

    # Both submitted: midpoint only if closest gap <= 2 hours
    a_best, b_best, gap = closest_pair(a_times, b_times)
    if gap <= MIDPOINT_MAX_GAP:
        mid = min(a_best, b_best) + gap / 2
        mid = round_to_increment(mid, TIME_INCREMENT_MINUTES)
        db.set_scheduled_time(session_id, mid.astimezone(timezone.utc))
        if thread:
            await thread.send(
                f"⏰ **Deadline reached. Auto-assigned** (closest-pair midpoint, gap {gap}).\n"
                f"Based on: {fmt_ct(a_best)} and {fmt_ct(b_best)}\n"
            )
            await post_match_result(thread, mid, division, team_a, team_b, "deadline auto-assign")
        return

    # Gap > 2 hours -> admin assignment
    db.set_status(session_id, "needs_admin")
    if thread:
        await thread.send(
            f"⏰ Deadline reached, but closest availability gap is **{gap}** (> 2 hours). Admin assignment required."
        )
        await notify_admins(thread.guild, f"Session {session_id} needs admin assignment (gap {gap} > 2h).", thread)


@bot.event
async def on_ready():
    print(f"Logged in as {bot.user} (ID: {bot.user.id})")


async def fetch_thread_for_session(session: sqlite3.Row) -> Optional[discord.Thread]:
    if not session["thread_id"]:
        return None
    tid = int(session["thread_id"])
    ch = bot.get_channel(tid)
    if isinstance(ch, discord.Thread):
        return ch
    try:
        fetched = await bot.fetch_channel(tid)
        if isinstance(fetched, discord.Thread):
            return fetched
    except Exception:
        return None
    return None


@discord.utils.copy_doc(discord.Client.wait_until_ready)
async def enforcement_loop():
    await bot.wait_until_ready()
    while not bot.is_closed():
        try:
            sessions = db.list_open_sessions()
            now = utcnow()

            for s in sessions:
                if s["status"] == "scheduled" or s["status"] == "cancelled":
                    continue

                created = from_iso(s["created_at_utc"])
                deadline = from_iso(s["deadline_at_utc"])

                thread = await fetch_thread_for_session(s)

                # 12h reminder to creator (once)
                if int(s["reminder_sent"]) == 0 and now >= (created + timedelta(hours=REMINDER_HOURS)) and now < deadline:
                    await enforce_12h(s, thread)

                # 36h enforcement
                if now >= deadline and s["status"] in ("active", "escalated", "needs_admin"):
                    # if already scheduled by previous loop, skip
                    s2 = db.get_session(int(s["session_id"]))
                    if s2 and s2["status"] != "scheduled":
                        await enforce_36h(s2, thread)

        except Exception as e:
            print("Enforcement loop error:", e)

        await discord.utils.sleep_until(datetime.now(timezone.utc) + timedelta(seconds=30))


bot.enforcement_loop = enforcement_loop  # keep reference
bot.run(TOKEN)
