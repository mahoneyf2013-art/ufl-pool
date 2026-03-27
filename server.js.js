const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cron = require("node-cron");

const app = express();
console.log("DB URL:", process.env.DATABASE_URL ? "SET" : "NOT SET");
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME_IN_PRODUCTION";
const ODDS_API_KEY = process.env.ODDS_API_KEY;
const SPORT = "americanfootball_ufl";
const PORT = process.env.PORT || 3001;
const APP_URL = process.env.APP_URL || "http://localhost:5173";

let resend = null;
try {
  const { Resend } = require("resend");
  if (process.env.RESEND_API_KEY) {
    resend = new Resend(process.env.RESEND_API_KEY);
    console.log("Resend configured");
  }
} catch (e) {
  console.log("Resend not installed — password reset emails disabled");
}

function uuid() {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    return (c === "x" ? r : (r & 0x3) | 0x8).toString(16);
  });
}

// ═══ PostgreSQL Connection ═══
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("railway") ? { rejectUnauthorized: false } : false,
});

async function query(text, params) {
  const res = await pool.query(text, params);
  return res.rows;
}

async function queryOne(text, params) {
  const res = await pool.query(text, params);
  return res.rows[0] || null;
}

// ═══ Create Tables ═══
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      display_name TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS pools (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      join_code TEXT UNIQUE NOT NULL,
      commissioner_id TEXT NOT NULL,
      starting_balance INTEGER DEFAULT 1000,
      require_approval INTEGER DEFAULT 1,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS pool_members (
      id TEXT PRIMARY KEY,
      pool_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      role TEXT DEFAULT 'member',
      status TEXT DEFAULT 'pending',
      balance INTEGER DEFAULT 1000,
      joined_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(pool_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS games (
      id TEXT PRIMARY KEY,
      week INTEGER,
      commence_time TEXT,
      home_team TEXT,
      away_team TEXT,
      spread_home REAL,
      spread_away REAL,
      total REAL,
      moneyline_home INTEGER,
      moneyline_away INTEGER,
      home_score INTEGER,
      away_score INTEGER,
      status TEXT DEFAULT 'upcoming',
      last_updated TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS bets (
      id TEXT PRIMARY KEY,
      member_id TEXT NOT NULL,
      pool_id TEXT NOT NULL,
      game_id TEXT NOT NULL,
      bet_type TEXT,
      pick TEXT,
      line REAL,
      odds INTEGER,
      wager INTEGER,
      result TEXT DEFAULT 'pending',
      payout INTEGER DEFAULT 0,
      parlay_group TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS password_resets (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      token TEXT UNIQUE NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      used INTEGER DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  console.log("Database tables ready");
}

// ═══ Auth Middleware ═══
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "No token provided" });
  const token = header.split(" ")[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid or expired token" });
  }
}

async function requireAdmin(req, res) {
  const admin = await queryOne("SELECT * FROM pool_members WHERE pool_id=$1 AND user_id=$2 AND role='admin' AND status='active'", [req.params.poolId, req.user.id]);
  if (!admin) { res.status(403).json({ error: "Admin access required" }); return null; }
  return admin;
}

// ═══ AUTH ROUTES ═══

app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, email, password, displayName } = req.body;
    if (!username || !email || !password) return res.status(400).json({ error: "Username, email, and password required" });
    if (password.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters" });
    const existing = await queryOne("SELECT id FROM users WHERE username=$1 OR email=$2", [username.toLowerCase(), email.toLowerCase()]);
    if (existing) return res.status(409).json({ error: "Username or email already taken" });
    const id = uuid();
    const hash = bcrypt.hashSync(password, 10);
    await pool.query("INSERT INTO users (id, username, email, password_hash, display_name) VALUES ($1,$2,$3,$4,$5)", [id, username.toLowerCase(), email.toLowerCase(), hash, displayName || username]);
    const token = jwt.sign({ id, username: username.toLowerCase() }, JWT_SECRET, { expiresIn: "30d" });
    res.json({ token, user: { id, username: username.toLowerCase(), displayName: displayName || username } });
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Username and password required" });
    const user = await queryOne("SELECT * FROM users WHERE username=$1 OR email=$2", [username.toLowerCase(), username.toLowerCase()]);
    if (!user || !bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ error: "Invalid credentials" });
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: "30d" });
    res.json({ token, user: { id: user.id, username: user.username, displayName: user.display_name } });
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

app.get("/api/auth/me", auth, async (req, res) => {
  try {
    const user = await queryOne("SELECT id, username, display_name, email FROM users WHERE id=$1", [req.user.id]);
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json(user);
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

// ═══ PASSWORD RESET ═══

app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email required" });
    const user = await queryOne("SELECT * FROM users WHERE email=$1", [email.toLowerCase()]);
    if (!user) return res.json({ success: true, message: "If that email exists, a reset link has been sent." });

    const token = Array.from({ length: 32 }, () => Math.random().toString(36).charAt(2)).join("");
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
    const id = uuid();

    await pool.query("UPDATE password_resets SET used=1 WHERE user_id=$1 AND used=0", [user.id]);
    await pool.query("INSERT INTO password_resets (id, user_id, token, expires_at) VALUES ($1,$2,$3,$4)", [id, user.id, token, expiresAt]);

    const resetLink = `${APP_URL}?reset=${token}`;

    if (resend) {
      try {
        await resend.emails.send({
          from: "UFL Pool <noreply@resend.dev>",
          to: email.toLowerCase(),
          subject: "Reset Your UFL Pool Password",
          html: `<div style="font-family:-apple-system,sans-serif;max-width:480px;margin:0 auto;padding:40px 20px;"><div style="text-align:center;margin-bottom:30px;"><h1 style="color:#3b82f6;font-size:28px;margin:0;">UFL POOL</h1><p style="color:#6b7280;font-size:14px;">Password Reset</p></div><p style="color:#333;font-size:15px;">Hey ${user.display_name},</p><p style="color:#333;font-size:15px;">Click below to reset your password:</p><div style="text-align:center;margin:30px 0;"><a href="${resetLink}" style="background:#3b82f6;color:white;padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:700;font-size:15px;display:inline-block;">Reset Password</a></div><p style="color:#6b7280;font-size:13px;">Expires in 1 hour.</p></div>`,
        });
      } catch (err) { console.error("Email failed:", err.message); }
    } else {
      console.log("Reset link: " + resetLink);
    }
    res.json({ success: true, message: "If that email exists, a reset link has been sent." });
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

app.get("/api/auth/verify-reset/:token", async (req, res) => {
  try {
    const reset = await queryOne("SELECT * FROM password_resets WHERE token=$1 AND used=0 AND expires_at > NOW()", [req.params.token]);
    if (!reset) return res.status(400).json({ error: "Invalid or expired reset link" });
    res.json({ valid: true });
  } catch (err) { res.status(500).json({ error: "Server error" }); }
});

app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) return res.status(400).json({ error: "Token and new password required" });
    if (newPassword.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters" });
    const reset = await queryOne("SELECT * FROM password_resets WHERE token=$1 AND used=0 AND expires_at > NOW()", [token]);
    if (!reset) return res.status(400).json({ error: "Invalid or expired reset link" });
    const hash = bcrypt.hashSync(newPassword, 10);
    await pool.query("UPDATE users SET password_hash=$1 WHERE id=$2", [hash, reset.user_id]);
    await pool.query("UPDATE password_resets SET used=1 WHERE id=$1", [reset.id]);
    const user = await queryOne("SELECT * FROM users WHERE id=$1", [reset.user_id]);
    const jwtToken = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: "30d" });
    res.json({ success: true, token: jwtToken, user: { id: user.id, username: user.username, displayName: user.display_name } });
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

// ═══ POOLS ═══

app.get("/api/my-pools", auth, async (req, res) => {
  try {
    const pools = await query(`
      SELECT p.*, pm.role, pm.status, pm.balance,
        (SELECT COUNT(*) FROM pool_members WHERE pool_id=p.id AND status='active') as member_count
      FROM pools p JOIN pool_members pm ON pm.pool_id = p.id
      WHERE pm.user_id = $1 ORDER BY p.created_at DESC
    `, [req.user.id]);
    res.json(pools);
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

app.post("/api/pools", auth, async (req, res) => {
  try {
    const { name, startingBalance, requireApproval } = req.body;
    if (!name) return res.status(400).json({ error: "Pool name required" });
    const id = uuid();
    const joinCode = Math.random().toString(36).substring(2, 8).toUpperCase();
    const bal = startingBalance || 1000;
    await pool.query("INSERT INTO pools (id, name, join_code, commissioner_id, starting_balance, require_approval) VALUES ($1,$2,$3,$4,$5,$6)", [id, name, joinCode, req.user.id, bal, requireApproval !== false ? 1 : 0]);
    const memberId = uuid();
    await pool.query("INSERT INTO pool_members (id, pool_id, user_id, role, status, balance) VALUES ($1,$2,$3,$4,$5,$6)", [memberId, id, req.user.id, "admin", "active", bal]);
    res.json({ id, joinCode, name });
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

app.post("/api/pools/:code/join", auth, async (req, res) => {
  try {
    const p = await queryOne("SELECT * FROM pools WHERE join_code=$1", [req.params.code.toUpperCase()]);
    if (!p) return res.status(404).json({ error: "Pool not found" });
    const existing = await queryOne("SELECT * FROM pool_members WHERE pool_id=$1 AND user_id=$2", [p.id, req.user.id]);
    if (existing) {
      if (existing.status === "deactivated") return res.status(403).json({ error: "You have been removed from this pool" });
      return res.status(409).json({ error: "Already a member of this pool" });
    }
    const id = uuid();
    const status = p.require_approval ? "pending" : "active";
    await pool.query("INSERT INTO pool_members (id, pool_id, user_id, role, status, balance) VALUES ($1,$2,$3,$4,$5,$6)", [id, p.id, req.user.id, "member", status, p.starting_balance]);
    res.json({ status, poolId: p.id, poolName: p.name });
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

// ═══ ADMIN ═══

app.get("/api/pools/:poolId/members", auth, async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    const members = await query(`
      SELECT pm.*, u.username, u.display_name
      FROM pool_members pm JOIN users u ON pm.user_id = u.id
      WHERE pm.pool_id = $1
      ORDER BY CASE pm.status WHEN 'pending' THEN 0 WHEN 'active' THEN 1 ELSE 2 END, pm.balance DESC
    `, [req.params.poolId]);
    res.json(members);
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

app.post("/api/pools/:poolId/members/:memberId/approve", auth, async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    await pool.query("UPDATE pool_members SET status='active' WHERE id=$1 AND pool_id=$2", [req.params.memberId, req.params.poolId]);
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

app.post("/api/pools/:poolId/members/:memberId/deactivate", auth, async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    const member = await queryOne("SELECT * FROM pool_members WHERE id=$1 AND pool_id=$2", [req.params.memberId, req.params.poolId]);
    if (!member) return res.status(404).json({ error: "Member not found" });
    if (member.role === "admin") return res.status(400).json({ error: "Cannot deactivate an admin" });
    await pool.query("UPDATE pool_members SET status='deactivated' WHERE id=$1", [req.params.memberId]);
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

app.post("/api/pools/:poolId/members/:memberId/reactivate", auth, async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    await pool.query("UPDATE pool_members SET status='active' WHERE id=$1", [req.params.memberId]);
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

// ═══ GAMES & ODDS ═══

async function fetchOdds() {
  if (!ODDS_API_KEY) { console.log("No ODDS_API_KEY set"); return 0; }
  try {
    const url = `https://api.the-odds-api.com/v4/sports/${SPORT}/odds/?apiKey=${ODDS_API_KEY}&regions=us&markets=spreads,totals,h2h&oddsFormat=american`;
    const res = await fetch(url);
    if (!res.ok) { console.error("Odds API error: " + res.status); return 0; }
    const data = await res.json();
    console.log("Odds fetched: " + data.length + " games | Remaining: " + res.headers.get("x-requests-remaining"));

    for (const event of data) {
      const book = event.bookmakers?.[0];
      if (!book) continue;
      let sh = null, sa = null, tot = null, mlh = null, mla = null;
      for (const market of book.markets) {
        if (market.key === "spreads") { for (const o of market.outcomes) { if (o.name === event.home_team) sh = o.point; else sa = o.point; } }
        if (market.key === "totals") { const ov = market.outcomes.find((o) => o.name === "Over"); if (ov) tot = ov.point; }
        if (market.key === "h2h") { for (const o of market.outcomes) { if (o.name === event.home_team) mlh = o.price; else mla = o.price; } }
      }
      await pool.query(`
        INSERT INTO games (id, commence_time, home_team, away_team, spread_home, spread_away, total, moneyline_home, moneyline_away, status, last_updated)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'upcoming',NOW())
        ON CONFLICT(id) DO UPDATE SET
          spread_home=$5, spread_away=$6, total=$7, moneyline_home=$8, moneyline_away=$9, last_updated=NOW(), commence_time=$2
      `, [event.id, event.commence_time, event.home_team, event.away_team, sh, sa, tot, mlh, mla]);
    }
    return data.length;
  } catch (err) { console.error("Odds fetch failed:", err.message); return 0; }
}

async function fetchScores() {
  if (!ODDS_API_KEY) return;
  try {
    const url = `https://api.the-odds-api.com/v4/sports/${SPORT}/scores/?apiKey=${ODDS_API_KEY}&daysFrom=3`;
    const res = await fetch(url);
    if (!res.ok) return;
    const data = await res.json();
    let graded = 0;
    for (const event of data) {
      if (event.completed && event.scores) {
        const hs = event.scores.find((s) => s.name === event.home_team);
        const as2 = event.scores.find((s) => s.name === event.away_team);
        if (hs && as2) {
          const result = await pool.query("UPDATE games SET home_score=$1, away_score=$2, status='final' WHERE id=$3 AND status='upcoming' RETURNING id", [parseInt(hs.score), parseInt(as2.score), event.id]);
          if (result.rowCount > 0) graded++;
        }
      }
    }
    if (graded > 0) { console.log(graded + " games completed — grading bets..."); await gradeBets(); }
  } catch (err) { console.error("Score fetch failed:", err.message); }
}

async function gradeBets() {
  const pending = await query(`
    SELECT b.*, g.home_team, g.away_team, g.home_score, g.away_score
    FROM bets b JOIN games g ON b.game_id = g.id
    WHERE b.result = 'pending' AND g.status = 'final' AND b.parlay_group IS NULL
  `);

  for (const bet of pending) {
    const { home_score, away_score, home_team, away_team } = bet;
    const totalScore = home_score + away_score;
    let result = "loss", payout = 0;

    if (bet.bet_type === "spread") {
      const ps = bet.pick === home_team ? home_score : away_score;
      const os = bet.pick === home_team ? away_score : home_score;
      const margin = ps - os + bet.line;
      result = margin > 0 ? "win" : margin === 0 ? "push" : "loss";
    } else if (bet.bet_type === "over") {
      result = totalScore > bet.line ? "win" : totalScore === bet.line ? "push" : "loss";
    } else if (bet.bet_type === "under") {
      result = totalScore < bet.line ? "win" : totalScore === bet.line ? "push" : "loss";
    } else if (bet.bet_type === "moneyline") {
      if (home_score === away_score) result = "push";
      else result = bet.pick === (home_score > away_score ? home_team : away_team) ? "win" : "loss";
    }

    if (result === "win") {
      if (bet.bet_type === "moneyline" && bet.odds) {
        payout = bet.odds < 0 ? bet.wager + Math.round(bet.wager * (100 / Math.abs(bet.odds))) : bet.wager + Math.round(bet.wager * (bet.odds / 100));
      } else { payout = bet.wager + Math.round(bet.wager * (100 / 110)); }
    } else if (result === "push") { payout = bet.wager; }

    await pool.query("UPDATE bets SET result=$1, payout=$2 WHERE id=$3", [result, payout, bet.id]);
    if (payout > 0) await pool.query("UPDATE pool_members SET balance = balance + $1 WHERE id=$2", [payout, bet.member_id]);
  }

  const parlayGroups = await query("SELECT DISTINCT parlay_group FROM bets WHERE parlay_group IS NOT NULL AND result = 'pending'");
  for (const { parlay_group } of parlayGroups) {
    const legs = await query("SELECT b.*, g.home_team, g.away_team, g.home_score, g.away_score, g.status as game_status FROM bets b JOIN games g ON b.game_id = g.id WHERE b.parlay_group = $1", [parlay_group]);
    if (legs.some((l) => l.game_status !== "final")) continue;
    let allWin = true, anyPush = false, multiplier = 1;
    for (const leg of legs) {
      const { home_score, away_score, home_team, away_team } = leg;
      const totalScore = home_score + away_score;
      let lr = "loss";
      if (leg.bet_type === "spread") { const ps = leg.pick === home_team ? home_score : away_score; const os = leg.pick === home_team ? away_score : home_score; const m = ps - os + leg.line; lr = m > 0 ? "win" : m === 0 ? "push" : "loss"; }
      else if (leg.bet_type === "over") { lr = totalScore > leg.line ? "win" : totalScore === leg.line ? "push" : "loss"; }
      else if (leg.bet_type === "under") { lr = totalScore < leg.line ? "win" : totalScore === leg.line ? "push" : "loss"; }
      else if (leg.bet_type === "moneyline") { if (home_score === away_score) lr = "push"; else lr = leg.pick === (home_score > away_score ? home_team : away_team) ? "win" : "loss"; }
      if (lr === "loss") allWin = false;
      if (lr === "push") anyPush = true;
      if (lr === "win") { if (leg.bet_type === "moneyline" && leg.odds) { const o = leg.odds; multiplier *= o < 0 ? 1 + 100 / Math.abs(o) : 1 + o / 100; } else { multiplier *= 1.909; } }
      await pool.query("UPDATE bets SET result=$1 WHERE id=$2", [lr, leg.id]);
    }
    const first = legs[0];
    let pp = 0;
    if (allWin || (anyPush && !legs.some((l) => l.result === "loss"))) { pp = Math.round(first.wager * multiplier); }
    if (pp > 0) await pool.query("UPDATE pool_members SET balance = balance + $1 WHERE id=$2", [pp, first.member_id]);
  }
  console.log("Bet grading complete");
}

// ═══ BETTING ROUTES ═══

app.get("/api/games", async (req, res) => {
  try { res.json(await query("SELECT * FROM games ORDER BY commence_time")); }
  catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

app.get("/api/games/upcoming", async (req, res) => {
  try { res.json(await query("SELECT * FROM games WHERE status='upcoming' ORDER BY commence_time")); }
  catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

app.post("/api/bet", auth, async (req, res) => {
  try {
    const { pool_id, game_id, bet_type, pick, line, odds, wager, parlay_group } = req.body;
    const member = await queryOne("SELECT * FROM pool_members WHERE pool_id=$1 AND user_id=$2 AND status='active'", [pool_id, req.user.id]);
    if (!member) return res.status(403).json({ error: "Not an active member" });
    const game = await queryOne("SELECT * FROM games WHERE id=$1", [game_id]);
    if (!game) return res.status(404).json({ error: "Game not found" });
    if (game.status !== "upcoming") return res.status(400).json({ error: "Game already started" });
    if (new Date(game.commence_time) <= new Date()) return res.status(400).json({ error: "Game has already kicked off" });
    if (!wager || wager <= 0) return res.status(400).json({ error: "Invalid wager" });
    if (wager > member.balance) return res.status(400).json({ error: "Insufficient balance" });
    await pool.query("UPDATE pool_members SET balance = balance - $1 WHERE id=$2", [wager, member.id]);
    const id = uuid();
    await pool.query("INSERT INTO bets (id, member_id, pool_id, game_id, bet_type, pick, line, odds, wager, parlay_group) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)", [id, member.id, pool_id, game_id, bet_type, pick, line, odds, wager, parlay_group || null]);
    res.json({ success: true, betId: id, newBalance: member.balance - wager });
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

app.get("/api/pools/:poolId/activity", auth, async (req, res) => {
  try {
    const member = await queryOne("SELECT * FROM pool_members WHERE pool_id=$1 AND user_id=$2 AND status='active'", [req.params.poolId, req.user.id]);
    if (!member) return res.status(403).json({ error: "Not in pool" });

    const bets = await query(`
      SELECT b.id, b.bet_type, b.pick, b.line, b.odds, b.wager, b.result, b.payout,
             b.parlay_group, b.created_at, b.member_id, b.game_id,
             g.home_team, g.away_team, g.commence_time, g.status as game_status,
             g.home_score, g.away_score,
             u.display_name, u.username
      FROM bets b
      JOIN games g ON b.game_id = g.id
      JOIN pool_members pm ON b.member_id = pm.id
      JOIN users u ON pm.user_id = u.id
      WHERE b.pool_id = $1
      ORDER BY b.created_at DESC
    `, [req.params.poolId]);

    const now = new Date();
    const processed = bets.map(bet => {
      const gameStarted = new Date(bet.commence_time) <= now || bet.game_status !== "upcoming";
      const isOwn = bet.member_id === member.id;
      return {
        ...bet,
        revealed: gameStarted || isOwn,
        bet_type: (gameStarted || isOwn) ? bet.bet_type : null,
        pick: (gameStarted || isOwn) ? bet.pick : null,
        line: (gameStarted || isOwn) ? bet.line : null,
        odds: (gameStarted || isOwn) ? bet.odds : null,
        is_own: isOwn,
      };
    });
    res.json(processed);
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

app.get("/api/pools/:poolId/my-bets", auth, async (req, res) => {
  try {
    const member = await queryOne("SELECT * FROM pool_members WHERE pool_id=$1 AND user_id=$2", [req.params.poolId, req.user.id]);
    if (!member) return res.status(403).json({ error: "Not in pool" });
    const bets = await query("SELECT b.*, g.home_team, g.away_team, g.home_score, g.away_score, g.commence_time FROM bets b JOIN games g ON b.game_id = g.id WHERE b.member_id = $1 ORDER BY b.created_at DESC", [member.id]);
    res.json(bets);
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

app.get("/api/pools/:poolId/leaderboard", async (req, res) => {
  try {
    const lb = await query(`
      SELECT pm.balance, pm.status, pm.role, u.display_name, u.username,
        (SELECT COUNT(*) FROM bets WHERE member_id=pm.id AND result='win') as wins,
        (SELECT COUNT(*) FROM bets WHERE member_id=pm.id AND result='loss') as losses,
        (SELECT COUNT(*) FROM bets WHERE member_id=pm.id AND result='push') as pushes,
        (SELECT COALESCE(SUM(wager), 0) FROM bets WHERE member_id=pm.id AND result='pending') as pending_amount,
        (pm.balance + (SELECT COALESCE(SUM(wager), 0) FROM bets WHERE member_id=pm.id AND result='pending')) as display_balance
      FROM pool_members pm JOIN users u ON pm.user_id = u.id
      WHERE pm.pool_id = $1 AND pm.status = 'active'
      ORDER BY (pm.balance + (SELECT COALESCE(SUM(wager), 0) FROM bets WHERE member_id=pm.id AND result='pending')) DESC
    `, [req.params.poolId]);
    res.json(lb);
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

// ═══ ADMIN TRIGGERS ═══

app.post("/api/admin/refresh-odds", auth, async (req, res) => {
  const count = await fetchOdds();
  res.json({ success: true, gamesUpdated: count });
});

app.post("/api/admin/refresh-scores", auth, async (req, res) => {
  await fetchScores();
  res.json({ success: true });
});

// ═══ HEALTH ═══

app.get("/", (req, res) => {
  res.json({ status: "ok", app: "UFL Fantasy Sportsbook Pool", oddsApiConfigured: !!ODDS_API_KEY });
});

app.get("/api/health", async (req, res) => {
  try {
    const gc = await queryOne("SELECT COUNT(*) as count FROM games");
    const uc = await queryOne("SELECT COUNT(*) as count FROM users");
    res.json({ status: "ok", games: parseInt(gc.count), users: parseInt(uc.count) });
  } catch (err) { res.json({ status: "error", message: err.message }); }
});

// ═══ CRON ═══

cron.schedule("0 */3 * * *", () => { console.log("Cron: Fetching odds..."); fetchOdds(); });
cron.schedule("*/20 * * * 6,0", () => { console.log("Cron: Checking scores..."); fetchScores(); });

// ═══ START ═══

app.listen(PORT, async () => {
  console.log("UFL Pool server running on port " + PORT);
  await initDB();
  if (ODDS_API_KEY) {
    console.log("Fetching initial odds...");
    const count = await fetchOdds();
    console.log("Loaded " + count + " games");
  }
});
