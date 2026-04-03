const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cron = require("node-cron");

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME";
const ODDS_API_KEY = process.env.ODDS_API_KEY;
const SPORT = "americanfootball_ufl";
const PORT = process.env.PORT || 3001;
const APP_URL = process.env.APP_URL || "http://localhost:5173";

let resend = null;
try { const { Resend } = require("resend"); if (process.env.RESEND_API_KEY) { resend = new Resend(process.env.RESEND_API_KEY); } } catch (e) {}

function uuid() { return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g,c=>{const r=Math.random()*16|0;return(c==="x"?r:(r&0x3|0x8)).toString(16)}); }

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_URL?.includes("railway") ? { rejectUnauthorized: false } : false });
async function q(text, params) { return (await pool.query(text, params)).rows; }
async function q1(text, params) { return (await pool.query(text, params)).rows[0] || null; }

// ═══ DB INIT ═══
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL, display_name TEXT, created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS pools (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, join_code TEXT UNIQUE NOT NULL,
      commissioner_id TEXT NOT NULL, starting_balance INTEGER DEFAULT 1000,
      require_approval INTEGER DEFAULT 1, created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS pool_members (
      id TEXT PRIMARY KEY, pool_id TEXT NOT NULL, user_id TEXT NOT NULL,
      role TEXT DEFAULT 'member', status TEXT DEFAULT 'pending',
      balance INTEGER DEFAULT 1000, joined_at TIMESTAMPTZ DEFAULT NOW(), UNIQUE(pool_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS games (
      id TEXT PRIMARY KEY, week INTEGER, commence_time TEXT,
      home_team TEXT, away_team TEXT, spread_home REAL, spread_away REAL,
      total REAL, moneyline_home INTEGER, moneyline_away INTEGER,
      home_score INTEGER, away_score INTEGER, status TEXT DEFAULT 'upcoming',
      last_updated TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS bets (
      id TEXT PRIMARY KEY, member_id TEXT NOT NULL, pool_id TEXT NOT NULL,
      game_id TEXT NOT NULL, bet_type TEXT, pick TEXT, line REAL, odds INTEGER,
      wager INTEGER, result TEXT DEFAULT 'pending', payout INTEGER DEFAULT 0,
      parlay_group TEXT, created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS password_resets (
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token TEXT UNIQUE NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL, used INTEGER DEFAULT 0, created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY, pool_id TEXT NOT NULL, user_id TEXT NOT NULL,
      content TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS line_history (
      id TEXT PRIMARY KEY, game_id TEXT NOT NULL,
      spread_home REAL, spread_away REAL, total REAL,
      moneyline_home INTEGER, moneyline_away INTEGER,
      recorded_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  console.log("Database tables ready");
}

// ═══ AUTH ═══
function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: "No token" });
  try { req.user = jwt.verify(h.split(" ")[1], JWT_SECRET); next(); }
  catch { res.status(401).json({ error: "Invalid token" }); }
}
async function requireAdmin(req, res) {
  const a = await q1("SELECT * FROM pool_members WHERE pool_id=$1 AND user_id=$2 AND role='admin' AND status='active'", [req.params.poolId, req.user.id]);
  if (!a) { res.status(403).json({ error: "Admin required" }); return null; } return a;
}

app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, email, password, displayName } = req.body;
    if (!username || !email || !password) return res.status(400).json({ error: "All fields required" });
    if (password.length < 6) return res.status(400).json({ error: "Password min 6 chars" });
    const ex = await q1("SELECT id FROM users WHERE username=$1 OR email=$2", [username.toLowerCase(), email.toLowerCase()]);
    if (ex) return res.status(409).json({ error: "Username or email taken" });
    const id = uuid(), hash = bcrypt.hashSync(password, 10);
    await pool.query("INSERT INTO users (id,username,email,password_hash,display_name) VALUES ($1,$2,$3,$4,$5)", [id, username.toLowerCase(), email.toLowerCase(), hash, displayName || username]);
    const token = jwt.sign({ id, username: username.toLowerCase() }, JWT_SECRET, { expiresIn: "30d" });
    res.json({ token, user: { id, username: username.toLowerCase(), displayName: displayName || username } });
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Credentials required" });
    const user = await q1("SELECT * FROM users WHERE username=$1 OR email=$2", [username.toLowerCase(), username.toLowerCase()]);
    if (!user || !bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ error: "Invalid credentials" });
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: "30d" });
    res.json({ token, user: { id: user.id, username: user.username, displayName: user.display_name } });
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

app.get("/api/auth/me", auth, async (req, res) => {
  try {
    const user = await q1("SELECT id,username,display_name,email FROM users WHERE id=$1", [req.user.id]);
    if (!user) return res.status(404).json({ error: "Not found" });
    res.json(user);
  } catch (err) { res.status(500).json({ error: "Server error" }); }
});

// ═══ PASSWORD RESET ═══
app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email required" });
    const user = await q1("SELECT * FROM users WHERE email=$1", [email.toLowerCase()]);
    if (!user) return res.json({ success: true, message: "If that email exists, a reset link has been sent." });
    const token = Array.from({ length: 32 }, () => Math.random().toString(36).charAt(2)).join("");
    const id = uuid();
    await pool.query("UPDATE password_resets SET used=1 WHERE user_id=$1 AND used=0", [user.id]);
    await pool.query("INSERT INTO password_resets (id,user_id,token,expires_at) VALUES ($1,$2,$3,$4)", [id, user.id, token, new Date(Date.now() + 3600000).toISOString()]);
    const link = `${APP_URL}?reset=${token}`;
    if (resend) { try { await resend.emails.send({ from: "UFL Pool <noreply@resend.dev>", to: email.toLowerCase(), subject: "Reset Your UFL Pool Password", html: `<div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:40px 20px;"><h1 style="color:#3b82f6;">UFL POOL</h1><p>Hey ${user.display_name}, click below to reset:</p><div style="text-align:center;margin:30px 0;"><a href="${link}" style="background:#3b82f6;color:white;padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:700;">Reset Password</a></div><p style="color:#6b7280;font-size:13px;">Expires in 1 hour.</p></div>` }); } catch (e) { console.error(e); } }
    else { console.log("Reset link: " + link); }
    res.json({ success: true, message: "If that email exists, a reset link has been sent." });
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

app.get("/api/auth/verify-reset/:token", async (req, res) => {
  try {
    const r = await q1("SELECT * FROM password_resets WHERE token=$1 AND used=0 AND expires_at > NOW()", [req.params.token]);
    if (!r) return res.status(400).json({ error: "Invalid or expired" });
    res.json({ valid: true });
  } catch (err) { res.status(500).json({ error: "Server error" }); }
});

app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword || newPassword.length < 6) return res.status(400).json({ error: "Invalid input" });
    const r = await q1("SELECT * FROM password_resets WHERE token=$1 AND used=0 AND expires_at > NOW()", [token]);
    if (!r) return res.status(400).json({ error: "Invalid or expired" });
    await pool.query("UPDATE users SET password_hash=$1 WHERE id=$2", [bcrypt.hashSync(newPassword, 10), r.user_id]);
    await pool.query("UPDATE password_resets SET used=1 WHERE id=$1", [r.id]);
    const user = await q1("SELECT * FROM users WHERE id=$1", [r.user_id]);
    const jwt2 = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: "30d" });
    res.json({ success: true, token: jwt2, user: { id: user.id, username: user.username, displayName: user.display_name } });
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

// ═══ POOLS ═══
app.get("/api/my-pools", auth, async (req, res) => {
  try {
    const pools = await q(`SELECT p.*, pm.role, pm.status, pm.balance,
      (SELECT COUNT(*) FROM pool_members WHERE pool_id=p.id AND status='active') as member_count
      FROM pools p JOIN pool_members pm ON pm.pool_id=p.id WHERE pm.user_id=$1 ORDER BY p.created_at DESC`, [req.user.id]);
    res.json(pools);
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

app.post("/api/pools", auth, async (req, res) => {
  try {
    const { name, startingBalance, requireApproval } = req.body;
    if (!name) return res.status(400).json({ error: "Name required" });
    const id = uuid(), jc = Math.random().toString(36).substring(2, 8).toUpperCase(), bal = startingBalance || 1000;
    await pool.query("INSERT INTO pools (id,name,join_code,commissioner_id,starting_balance,require_approval) VALUES ($1,$2,$3,$4,$5,$6)", [id, name, jc, req.user.id, bal, requireApproval !== false ? 1 : 0]);
    const mid = uuid();
    await pool.query("INSERT INTO pool_members (id,pool_id,user_id,role,status,balance) VALUES ($1,$2,$3,$4,$5,$6)", [mid, id, req.user.id, "admin", "active", bal]);
    res.json({ id, joinCode: jc, name });
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

app.post("/api/pools/:code/join", auth, async (req, res) => {
  try {
    const p = await q1("SELECT * FROM pools WHERE join_code=$1", [req.params.code.toUpperCase()]);
    if (!p) return res.status(404).json({ error: "Pool not found" });
    const ex = await q1("SELECT * FROM pool_members WHERE pool_id=$1 AND user_id=$2", [p.id, req.user.id]);
    if (ex) { if (ex.status === "deactivated") return res.status(403).json({ error: "Removed from pool" }); return res.status(409).json({ error: "Already a member" }); }
    const id = uuid(), st = p.require_approval ? "pending" : "active";
    await pool.query("INSERT INTO pool_members (id,pool_id,user_id,role,status,balance) VALUES ($1,$2,$3,$4,$5,$6)", [id, p.id, req.user.id, "member", st, p.starting_balance]);
    res.json({ status: st, poolId: p.id, poolName: p.name });
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

// ═══ ADMIN ═══
app.get("/api/pools/:poolId/members", auth, async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    res.json(await q(`SELECT pm.*, u.username, u.display_name FROM pool_members pm JOIN users u ON pm.user_id=u.id
      WHERE pm.pool_id=$1 ORDER BY CASE pm.status WHEN 'pending' THEN 0 WHEN 'active' THEN 1 ELSE 2 END, pm.balance DESC`, [req.params.poolId]));
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

app.post("/api/pools/:poolId/members/:memberId/approve", auth, async (req, res) => {
  try { if (!(await requireAdmin(req, res))) return; await pool.query("UPDATE pool_members SET status='active' WHERE id=$1 AND pool_id=$2", [req.params.memberId, req.params.poolId]); res.json({ success: true }); }
  catch (err) { res.status(500).json({ error: "Server error" }); }
});

app.post("/api/pools/:poolId/members/:memberId/deactivate", auth, async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    const m = await q1("SELECT * FROM pool_members WHERE id=$1 AND pool_id=$2", [req.params.memberId, req.params.poolId]);
    if (!m) return res.status(404).json({ error: "Not found" });
    if (m.role === "admin") return res.status(400).json({ error: "Cannot deactivate admin" });
    await pool.query("UPDATE pool_members SET status='deactivated' WHERE id=$1", [req.params.memberId]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: "Server error" }); }
});

app.post("/api/pools/:poolId/members/:memberId/reactivate", auth, async (req, res) => {
  try { if (!(await requireAdmin(req, res))) return; await pool.query("UPDATE pool_members SET status='active' WHERE id=$1", [req.params.memberId]); res.json({ success: true }); }
  catch (err) { res.status(500).json({ error: "Server error" }); }
});

// Admin: adjust member balance
app.post("/api/pools/:poolId/members/:memberId/adjust-balance", auth, async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    const { amount, reason } = req.body;
    if (amount === undefined || amount === null) return res.status(400).json({ error: "Amount required" });
    const m = await q1("SELECT * FROM pool_members WHERE id=$1 AND pool_id=$2", [req.params.memberId, req.params.poolId]);
    if (!m) return res.status(404).json({ error: "Member not found" });
    const newBal = m.balance + parseInt(amount);
    if (newBal < 0) return res.status(400).json({ error: "Balance cannot go below 0" });
    await pool.query("UPDATE pool_members SET balance=$1 WHERE id=$2", [newBal, req.params.memberId]);
    // Log as a system message
    const user = await q1("SELECT display_name FROM users WHERE id=(SELECT user_id FROM pool_members WHERE id=$1)", [req.params.memberId]);
    const mid = uuid();
    const msg = amount > 0
      ? `[ADMIN] Adjusted ${user.display_name}'s balance: +${amount} pts${reason ? " — " + reason : ""}`
      : `[ADMIN] Adjusted ${user.display_name}'s balance: ${amount} pts${reason ? " — " + reason : ""}`;
    await pool.query("INSERT INTO messages (id,pool_id,user_id,content) VALUES ($1,$2,$3,$4)", [mid, req.params.poolId, req.user.id, msg]);
    res.json({ success: true, newBalance: newBal });
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

// ═══ MESSAGE BOARD ═══
app.get("/api/pools/:poolId/messages", auth, async (req, res) => {
  try {
    const member = await q1("SELECT * FROM pool_members WHERE pool_id=$1 AND user_id=$2 AND status='active'", [req.params.poolId, req.user.id]);
    if (!member) return res.status(403).json({ error: "Not in pool" });
    const limit = parseInt(req.query.limit) || 50;
    const before = req.query.before;
    let msgs;
    if (before) {
      msgs = await q(`SELECT m.*, u.display_name, u.username FROM messages m JOIN users u ON m.user_id=u.id
        WHERE m.pool_id=$1 AND m.created_at < $2 ORDER BY m.created_at DESC LIMIT $3`, [req.params.poolId, before, limit]);
    } else {
      msgs = await q(`SELECT m.*, u.display_name, u.username FROM messages m JOIN users u ON m.user_id=u.id
        WHERE m.pool_id=$1 ORDER BY m.created_at DESC LIMIT $2`, [req.params.poolId, limit]);
    }
    res.json(msgs.reverse());
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

app.post("/api/pools/:poolId/messages", auth, async (req, res) => {
  try {
    const member = await q1("SELECT * FROM pool_members WHERE pool_id=$1 AND user_id=$2 AND status='active'", [req.params.poolId, req.user.id]);
    if (!member) return res.status(403).json({ error: "Not in pool" });
    const { content } = req.body;
    if (!content || !content.trim()) return res.status(400).json({ error: "Message required" });
    if (content.length > 500) return res.status(400).json({ error: "Message too long (500 char max)" });
    const id = uuid();
    await pool.query("INSERT INTO messages (id,pool_id,user_id,content) VALUES ($1,$2,$3,$4)", [id, req.params.poolId, req.user.id, content.trim()]);
    const msg = await q1("SELECT m.*, u.display_name, u.username FROM messages m JOIN users u ON m.user_id=u.id WHERE m.id=$1", [id]);
    res.json(msg);
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

// ═══ GAMES & ODDS ═══
async function fetchOdds() {
  if (!ODDS_API_KEY) return 0;
  try {
    const url = `https://api.the-odds-api.com/v4/sports/${SPORT}/odds/?apiKey=${ODDS_API_KEY}&regions=us&markets=spreads,totals,h2h&oddsFormat=american`;
    const res = await fetch(url);
    if (!res.ok) { console.error("Odds API error: " + res.status); return 0; }
    const data = await res.json();
    console.log("Odds fetched: " + data.length + " games | Remaining: " + res.headers.get("x-requests-remaining"));

    for (const event of data) {
      const book = event.bookmakers?.[0];
      if (!book) continue;
      let sh=null,sa=null,tot=null,mlh=null,mla=null;
      for (const market of book.markets) {
        if (market.key==="spreads") { for (const o of market.outcomes) { if (o.name===event.home_team) sh=o.point; else sa=o.point; } }
        if (market.key==="totals") { const ov=market.outcomes.find(o=>o.name==="Over"); if(ov) tot=ov.point; }
        if (market.key==="h2h") { for (const o of market.outcomes) { if (o.name===event.home_team) mlh=o.price; else mla=o.price; } }
      }

      // Check if lines changed before recording history
      const existing = await q1("SELECT * FROM games WHERE id=$1", [event.id]);
      if (existing && (existing.spread_home !== sh || existing.total !== tot || existing.moneyline_home !== mlh)) {
        await pool.query("INSERT INTO line_history (id,game_id,spread_home,spread_away,total,moneyline_home,moneyline_away) VALUES ($1,$2,$3,$4,$5,$6,$7)",
          [uuid(), event.id, sh, sa, tot, mlh, mla]);
      } else if (!existing) {
        // First time seeing this game, record initial line
        await pool.query("INSERT INTO line_history (id,game_id,spread_home,spread_away,total,moneyline_home,moneyline_away) VALUES ($1,$2,$3,$4,$5,$6,$7)",
          [uuid(), event.id, sh, sa, tot, mlh, mla]);
      }

      await pool.query(`INSERT INTO games (id,commence_time,home_team,away_team,spread_home,spread_away,total,moneyline_home,moneyline_away,status,last_updated)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'upcoming',NOW())
        ON CONFLICT(id) DO UPDATE SET spread_home=$5,spread_away=$6,total=$7,moneyline_home=$8,moneyline_away=$9,last_updated=NOW(),commence_time=$2`,
        [event.id, event.commence_time, event.home_team, event.away_team, sh, sa, tot, mlh, mla]);
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
        const hs = event.scores.find(s => s.name === event.home_team);
        const as2 = event.scores.find(s => s.name === event.away_team);
        if (hs && as2) {
          const r = await pool.query("UPDATE games SET home_score=$1,away_score=$2,status='final' WHERE id=$3 AND status='upcoming' RETURNING id", [parseInt(hs.score), parseInt(as2.score), event.id]);
          if (r.rowCount > 0) graded++;
        }
      }
    }
    if (graded > 0) { console.log(graded + " games completed"); await gradeBets(); }
  } catch (err) { console.error("Score fetch failed:", err.message); }
}

async function gradeBets() {
  const pending = await q(`SELECT b.*, g.home_team, g.away_team, g.home_score, g.away_score
    FROM bets b JOIN games g ON b.game_id=g.id WHERE b.result='pending' AND g.status='final' AND b.parlay_group IS NULL`);
  for (const bet of pending) {
    const { home_score, away_score, home_team, away_team } = bet;
    const ts = home_score + away_score;
    let result = "loss", payout = 0;
    if (bet.bet_type === "spread") { const ps=bet.pick===home_team?home_score:away_score; const os=bet.pick===home_team?away_score:home_score; const m=ps-os+bet.line; result=m>0?"win":m===0?"push":"loss"; }
    else if (bet.bet_type === "over") { result=ts>bet.line?"win":ts===bet.line?"push":"loss"; }
    else if (bet.bet_type === "under") { result=ts<bet.line?"win":ts===bet.line?"push":"loss"; }
    else if (bet.bet_type === "moneyline") { if(home_score===away_score) result="push"; else result=bet.pick===(home_score>away_score?home_team:away_team)?"win":"loss"; }
    if (result === "win") { payout = (bet.bet_type==="moneyline"&&bet.odds) ? (bet.odds<0?bet.wager+Math.round(bet.wager*(100/Math.abs(bet.odds))):bet.wager+Math.round(bet.wager*(bet.odds/100))) : bet.wager+Math.round(bet.wager*(100/110)); }
    else if (result === "push") { payout = bet.wager; }
    await pool.query("UPDATE bets SET result=$1,payout=$2 WHERE id=$3", [result, payout, bet.id]);
    if (payout > 0) await pool.query("UPDATE pool_members SET balance=balance+$1 WHERE id=$2", [payout, bet.member_id]);
  }
  // Parlays
  const pgs = await q("SELECT DISTINCT parlay_group FROM bets WHERE parlay_group IS NOT NULL AND result='pending'");
  for (const { parlay_group } of pgs) {
    const legs = await q("SELECT b.*, g.home_team, g.away_team, g.home_score, g.away_score, g.status as gs FROM bets b JOIN games g ON b.game_id=g.id WHERE b.parlay_group=$1", [parlay_group]);
    if (legs.some(l => l.gs !== "final")) continue;
    let allWin=true, anyPush=false, mult=1;
    for (const leg of legs) {
      const { home_score, away_score, home_team, away_team } = leg;
      const ts = home_score + away_score;
      let lr = "loss";
      if (leg.bet_type==="spread") { const ps=leg.pick===home_team?home_score:away_score; const os=leg.pick===home_team?away_score:home_score; const m=ps-os+leg.line; lr=m>0?"win":m===0?"push":"loss"; }
      else if (leg.bet_type==="over") lr=ts>leg.line?"win":ts===leg.line?"push":"loss";
      else if (leg.bet_type==="under") lr=ts<leg.line?"win":ts===leg.line?"push":"loss";
      else if (leg.bet_type==="moneyline") { if(home_score===away_score) lr="push"; else lr=leg.pick===(home_score>away_score?home_team:away_team)?"win":"loss"; }
      if (lr==="loss") allWin=false; if (lr==="push") anyPush=true;
      if (lr==="win") { if(leg.bet_type==="moneyline"&&leg.odds){const o=leg.odds;mult*=o<0?1+100/Math.abs(o):1+o/100;}else{mult*=1.909;} }
      await pool.query("UPDATE bets SET result=$1 WHERE id=$2", [lr, leg.id]);
    }
    const f = legs[0]; let pp = 0;
    if (allWin || (anyPush && !legs.some(l => l.result === "loss"))) pp = Math.round(f.wager * mult);
    if (pp > 0) await pool.query("UPDATE pool_members SET balance=balance+$1 WHERE id=$2", [pp, f.member_id]);
  }
  console.log("Bet grading complete");
}

// ═══ BETTING ═══
app.get("/api/games", async (req, res) => { try { res.json(await q("SELECT * FROM games ORDER BY commence_time")); } catch(e) { res.status(500).json({error:"Server error"}); } });
app.get("/api/games/upcoming", async (req, res) => { try { res.json(await q("SELECT * FROM games WHERE status='upcoming' ORDER BY commence_time")); } catch(e) { res.status(500).json({error:"Server error"}); } });

// Full schedule — pull week info from ESPN
app.get("/api/schedule", async (req, res) => {
  try {
    // Try ESPN for proper week numbers
    let espnWeeks = [];
    try {
      // ESPN calendar gives us the week structure
      const calRes = await fetch("https://site.api.espn.com/apis/site/v2/sports/football/ufl/scoreboard");
      const calData = await calRes.json();
      const currentWeek = calData.week?.number;
      const totalWeeks = calData.leagues?.[0]?.calendar?.[0]?.entries?.length || 10;

      // Fetch each week from ESPN
      for (let w = 1; w <= totalWeeks; w++) {
        try {
          const wRes = await fetch(`https://site.api.espn.com/apis/site/v2/sports/football/ufl/scoreboard?week=${w}`);
          const wData = await wRes.json();
          if (wData.events && wData.events.length > 0) {
            const games = wData.events.map(ev => {
              const comp = ev.competitions?.[0];
              const home = comp?.competitors?.find(c => c.homeAway === "home");
              const away = comp?.competitors?.find(c => c.homeAway === "away");
              const isComplete = comp?.status?.type?.completed || false;
              return {
                espn_id: ev.id,
                name: ev.name,
                date: ev.date,
                home_team: home?.team?.displayName || home?.team?.name,
                away_team: away?.team?.displayName || away?.team?.name,
                home_abbr: home?.team?.abbreviation,
                away_abbr: away?.team?.abbreviation,
                home_score: isComplete ? parseInt(home?.score || 0) : null,
                away_score: isComplete ? parseInt(away?.score || 0) : null,
                home_record: home?.records?.[0]?.summary,
                away_record: away?.records?.[0]?.summary,
                status: isComplete ? "final" : comp?.status?.type?.name || "upcoming",
                status_detail: comp?.status?.type?.shortDetail || "",
                venue: comp?.venue?.fullName,
              };
            });
            espnWeeks.push({ week: w, games });
          }
        } catch (e) { /* skip week if ESPN fails */ }
      }
    } catch (e) {
      console.error("ESPN schedule fetch failed:", e.message);
    }

    // If ESPN worked, also merge in our odds data
    if (espnWeeks.length > 0) {
      const ourGames = await q("SELECT * FROM games ORDER BY commence_time");
      // Match by team names and date proximity
      for (const week of espnWeeks) {
        for (const game of week.games) {
          const match = ourGames.find(g => {
            const nameMatch = (g.home_team === game.home_team || g.away_team === game.away_team ||
              g.home_team?.includes(game.home_abbr) || g.away_team?.includes(game.away_abbr));
            const dateClose = Math.abs(new Date(g.commence_time) - new Date(game.date)) < 86400000 * 2;
            return nameMatch && dateClose;
          });
          if (match) {
            game.odds_game_id = match.id;
            game.spread_home = match.spread_home;
            game.spread_away = match.spread_away;
            game.total = match.total;
            game.moneyline_home = match.moneyline_home;
            game.moneyline_away = match.moneyline_away;
            // Update week number in our DB
            await pool.query("UPDATE games SET week=$1 WHERE id=$2", [week.week, match.id]);
          }
        }
      }
      return res.json(espnWeeks);
    }

    // Fallback: use our own games grouped by week from DB
    const games = await q("SELECT * FROM games ORDER BY commence_time ASC");
    const weeks = {};
    for (const game of games) {
      const w = game.week || 1;
      if (!weeks[w]) weeks[w] = { week: w, games: [] };
      weeks[w].games.push({
        ...game, home_abbr: game.home_team?.split(" ").pop()?.substring(0,3)?.toUpperCase(),
        away_abbr: game.away_team?.split(" ").pop()?.substring(0,3)?.toUpperCase(),
        date: game.commence_time, status_detail: game.status,
      });
    }
    res.json(Object.values(weeks).sort((a, b) => a.week - b.week));
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

// Line history for a game (with opening vs current comparison)
app.get("/api/games/:gameId/line-history", async (req, res) => {
  try {
    const history = await q("SELECT * FROM line_history WHERE game_id=$1 ORDER BY recorded_at ASC", [req.params.gameId]);
    const game = await q1("SELECT * FROM games WHERE id=$1", [req.params.gameId]);
    res.json({ history, current: game });
  } catch (err) { res.status(500).json({ error: "Server error" }); }
});

app.post("/api/bet", auth, async (req, res) => {
  try {
    const { pool_id, game_id, bet_type, pick, line, odds, wager, parlay_group } = req.body;
    const member = await q1("SELECT * FROM pool_members WHERE pool_id=$1 AND user_id=$2 AND status='active'", [pool_id, req.user.id]);
    if (!member) return res.status(403).json({ error: "Not active" });
    const game = await q1("SELECT * FROM games WHERE id=$1", [game_id]);
    if (!game) return res.status(404).json({ error: "Game not found" });
    if (game.status !== "upcoming") return res.status(400).json({ error: "Game already started" });
    // STRICT kickoff check
    if (new Date(game.commence_time) <= new Date()) return res.status(400).json({ error: "Betting is closed — game has kicked off" });
    if (!wager || wager <= 0) return res.status(400).json({ error: "Invalid wager" });
    if (wager > member.balance) return res.status(400).json({ error: "Insufficient balance" });
    await pool.query("UPDATE pool_members SET balance=balance-$1 WHERE id=$2", [wager, member.id]);
    const id = uuid();
    await pool.query("INSERT INTO bets (id,member_id,pool_id,game_id,bet_type,pick,line,odds,wager,parlay_group) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
      [id, member.id, pool_id, game_id, bet_type, pick, line, odds, wager, parlay_group || null]);
    res.json({ success: true, betId: id, newBalance: member.balance - wager });
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

// Activity — hide game AND picks until kickoff
app.get("/api/pools/:poolId/activity", auth, async (req, res) => {
  try {
    const member = await q1("SELECT * FROM pool_members WHERE pool_id=$1 AND user_id=$2 AND status='active'", [req.params.poolId, req.user.id]);
    if (!member) return res.status(403).json({ error: "Not in pool" });
    const bets = await q(`SELECT b.id, b.bet_type, b.pick, b.line, b.odds, b.wager, b.result, b.payout,
      b.parlay_group, b.created_at, b.member_id, b.game_id,
      g.home_team, g.away_team, g.commence_time, g.status as game_status, g.home_score, g.away_score,
      u.display_name, u.username
      FROM bets b JOIN games g ON b.game_id=g.id JOIN pool_members pm ON b.member_id=pm.id JOIN users u ON pm.user_id=u.id
      WHERE b.pool_id=$1 ORDER BY b.created_at DESC`, [req.params.poolId]);

    const now = new Date();
    const processed = bets.map(bet => {
      const gameStarted = new Date(bet.commence_time) <= now || bet.game_status !== "upcoming";
      const isOwn = bet.member_id === member.id;
      const revealed = gameStarted || isOwn;
      return {
        id: bet.id, display_name: bet.display_name, username: bet.username,
        wager: bet.wager, result: bet.result, payout: bet.payout,
        created_at: bet.created_at, parlay_group: bet.parlay_group,
        game_id: bet.game_id, game_status: bet.game_status,
        commence_time: bet.commence_time, is_own: isOwn, revealed,
        // HIDE everything until kickoff (game info + picks)
        home_team: revealed ? bet.home_team : null,
        away_team: revealed ? bet.away_team : null,
        home_score: revealed ? bet.home_score : null,
        away_score: revealed ? bet.away_score : null,
        bet_type: revealed ? bet.bet_type : null,
        pick: revealed ? bet.pick : null,
        line: revealed ? bet.line : null,
        odds: revealed ? bet.odds : null,
      };
    });
    res.json(processed);
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

app.get("/api/pools/:poolId/my-bets", auth, async (req, res) => {
  try {
    const member = await q1("SELECT * FROM pool_members WHERE pool_id=$1 AND user_id=$2", [req.params.poolId, req.user.id]);
    if (!member) return res.status(403).json({ error: "Not in pool" });
    res.json(await q("SELECT b.*, g.home_team, g.away_team, g.home_score, g.away_score, g.commence_time FROM bets b JOIN games g ON b.game_id=g.id WHERE b.member_id=$1 ORDER BY b.created_at DESC", [member.id]));
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

app.get("/api/pools/:poolId/leaderboard", async (req, res) => {
  try {
    res.json(await q(`SELECT pm.balance, pm.status, pm.role, u.display_name, u.username,
      (SELECT COUNT(*) FROM bets WHERE member_id=pm.id AND result='win') as wins,
      (SELECT COUNT(*) FROM bets WHERE member_id=pm.id AND result='loss') as losses,
      (SELECT COUNT(*) FROM bets WHERE member_id=pm.id AND result='push') as pushes,
      (SELECT COALESCE(SUM(wager),0) FROM bets WHERE member_id=pm.id AND result='pending') as pending_amount,
      (pm.balance + (SELECT COALESCE(SUM(wager),0) FROM bets WHERE member_id=pm.id AND result='pending')) as display_balance
      FROM pool_members pm JOIN users u ON pm.user_id=u.id
      WHERE pm.pool_id=$1 AND pm.status='active'
      ORDER BY (pm.balance + (SELECT COALESCE(SUM(wager),0) FROM bets WHERE member_id=pm.id AND result='pending')) DESC`, [req.params.poolId]));
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

// ═══ LIVE SCORES — games in progress with bets ═══
app.get("/api/pools/:poolId/live", auth, async (req, res) => {
  try {
    const member = await q1("SELECT * FROM pool_members WHERE pool_id=$1 AND user_id=$2 AND status='active'", [req.params.poolId, req.user.id]);
    if (!member) return res.status(403).json({ error: "Not in pool" });

    // Get all games that have started (commence_time <= now) but aren't final yet, plus recently completed
    const games = await q(`SELECT * FROM games WHERE
      (commence_time <= NOW()::text AND status='upcoming')
      OR status='final'
      ORDER BY commence_time DESC LIMIT 20`);

    // For each game, get bets from this pool
    const result = [];
    for (const game of games) {
      const gameBets = await q(`SELECT b.id, b.bet_type, b.pick, b.line, b.odds, b.wager, b.result, b.payout,
        b.member_id, u.display_name
        FROM bets b JOIN pool_members pm ON b.member_id=pm.id JOIN users u ON pm.user_id=u.id
        WHERE b.game_id=$1 AND b.pool_id=$2
        ORDER BY b.wager DESC`, [game.id, req.params.poolId]);
      result.push({ ...game, pool_bets: gameBets });
    }
    res.json(result);
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

// ═══ ESPN PROXY — rich team/game data ═══

// All teams with logos, colors, records
app.get("/api/espn/teams", async (req, res) => {
  try {
    const r = await fetch("https://site.api.espn.com/apis/site/v2/sports/football/ufl/teams");
    if (!r.ok) return res.status(502).json({ error: "ESPN unavailable" });
    const data = await r.json();
    // Flatten into useful format
    const teams = (data.sports?.[0]?.leagues?.[0]?.teams || []).map(t => {
      const team = t.team;
      return {
        id: team.id, name: team.displayName, abbr: team.abbreviation,
        shortName: team.shortDisplayName, nickname: team.name,
        color: team.color ? `#${team.color}` : "#666",
        altColor: team.alternateColor ? `#${team.alternateColor}` : "#333",
        logo: team.logos?.[0]?.href || null,
        record: team.record?.items?.[0]?.summary || null,
        location: team.location,
      };
    });
    res.json(teams);
  } catch (err) { res.status(502).json({ error: "ESPN unavailable" }); }
});

// Single team detail
app.get("/api/espn/teams/:teamId", async (req, res) => {
  try {
    const r = await fetch(`https://site.api.espn.com/apis/site/v2/sports/football/ufl/teams/${req.params.teamId}`);
    if (!r.ok) return res.status(502).json({ error: "ESPN unavailable" });
    res.json(await r.json());
  } catch (err) { res.status(502).json({ error: "ESPN unavailable" }); }
});

// Team roster
app.get("/api/espn/teams/:teamId/roster", async (req, res) => {
  try {
    const r = await fetch(`https://site.api.espn.com/apis/site/v2/sports/football/ufl/teams/${req.params.teamId}/roster`);
    if (!r.ok) return res.status(502).json({ error: "ESPN unavailable" });
    res.json(await r.json());
  } catch (err) { res.status(502).json({ error: "ESPN unavailable" }); }
});

// Team schedule
app.get("/api/espn/teams/:teamId/schedule", async (req, res) => {
  try {
    const r = await fetch(`https://site.api.espn.com/apis/site/v2/sports/football/ufl/teams/${req.params.teamId}/schedule`);
    if (!r.ok) return res.status(502).json({ error: "ESPN unavailable" });
    res.json(await r.json());
  } catch (err) { res.status(502).json({ error: "ESPN unavailable" }); }
});

// Standings
app.get("/api/espn/standings", async (req, res) => {
  try {
    const r = await fetch("https://site.api.espn.com/apis/v2/sports/football/ufl/standings");
    if (!r.ok) return res.status(502).json({ error: "ESPN unavailable" });
    res.json(await r.json());
  } catch (err) { res.status(502).json({ error: "ESPN unavailable" }); }
});

// News
app.get("/api/espn/news", async (req, res) => {
  try {
    const r = await fetch("https://site.api.espn.com/apis/site/v2/sports/football/ufl/news");
    if (!r.ok) return res.status(502).json({ error: "ESPN unavailable" });
    res.json(await r.json());
  } catch (err) { res.status(502).json({ error: "ESPN unavailable" }); }
});

// Scoreboard (live/current)
app.get("/api/espn/scoreboard", async (req, res) => {
  try {
    const week = req.query.week ? `?week=${req.query.week}` : "";
    const r = await fetch(`https://site.api.espn.com/apis/site/v2/sports/football/ufl/scoreboard${week}`);
    if (!r.ok) return res.status(502).json({ error: "ESPN unavailable" });
    res.json(await r.json());
  } catch (err) { res.status(502).json({ error: "ESPN unavailable" }); }
});

// Game summary (box score, stats, play-by-play)
app.get("/api/espn/summary/:eventId", async (req, res) => {
  try {
    const r = await fetch(`https://site.api.espn.com/apis/site/v2/sports/football/ufl/summary?event=${req.params.eventId}`);
    if (!r.ok) return res.status(502).json({ error: "ESPN unavailable" });
    res.json(await r.json());
  } catch (err) { res.status(502).json({ error: "ESPN unavailable" }); }
});

// ═══ ADMIN TRIGGERS ═══
app.post("/api/admin/refresh-odds", auth, async (req, res) => { const c = await fetchOdds(); res.json({ success: true, gamesUpdated: c }); });
app.post("/api/admin/refresh-scores", auth, async (req, res) => { await fetchScores(); res.json({ success: true }); });

// ═══ PLAYER PROFILE / STATS ═══
app.get("/api/pools/:poolId/profile", auth, async (req, res) => {
  try {
    const member = await q1("SELECT * FROM pool_members WHERE pool_id=$1 AND user_id=$2", [req.params.poolId, req.user.id]);
    if (!member) return res.status(403).json({ error: "Not in pool" });
    const user = await q1("SELECT username, display_name FROM users WHERE id=$1", [req.user.id]);

    const stats = await q1(`SELECT
      COUNT(*) as total_bets,
      COUNT(*) FILTER (WHERE result='win') as wins,
      COUNT(*) FILTER (WHERE result='loss') as losses,
      COUNT(*) FILTER (WHERE result='push') as pushes,
      COUNT(*) FILTER (WHERE result='pending') as pending,
      COALESCE(SUM(wager),0) as total_wagered,
      COALESCE(SUM(payout),0) as total_payout,
      COALESCE(SUM(wager) FILTER (WHERE result='pending'),0) as pending_amount,
      COALESCE(SUM(CASE WHEN result='win' THEN payout - wager WHEN result='loss' THEN -wager ELSE 0 END),0) as net_profit,
      COALESCE(AVG(wager),0) as avg_wager
    FROM bets WHERE member_id=$1 AND parlay_group IS NULL`, [member.id]);

    // Bet type breakdown
    const byType = await q(`SELECT bet_type,
      COUNT(*) as total, COUNT(*) FILTER (WHERE result='win') as wins,
      COUNT(*) FILTER (WHERE result='loss') as losses
    FROM bets WHERE member_id=$1 AND parlay_group IS NULL GROUP BY bet_type`, [member.id]);

    // Parlay stats
    const parlayStats = await q1(`SELECT
      COUNT(DISTINCT parlay_group) as total_parlays,
      COUNT(DISTINCT parlay_group) FILTER (WHERE result='win') as parlay_wins
    FROM bets WHERE member_id=$1 AND parlay_group IS NOT NULL`, [member.id]);

    // Recent bets
    const recent = await q(`SELECT b.*, g.home_team, g.away_team, g.home_score, g.away_score
      FROM bets b JOIN games g ON b.game_id=g.id
      WHERE b.member_id=$1 ORDER BY b.created_at DESC LIMIT 10`, [member.id]);

    // Streak
    const graded = await q(`SELECT result FROM bets WHERE member_id=$1 AND result IN ('win','loss') AND parlay_group IS NULL ORDER BY created_at DESC LIMIT 20`, [member.id]);
    let streak = 0, streakType = "";
    if (graded.length > 0) {
      streakType = graded[0].result;
      for (const b of graded) { if (b.result === streakType) streak++; else break; }
    }

    const winRate = stats.total_bets > 0 ? ((parseInt(stats.wins) / (parseInt(stats.wins) + parseInt(stats.losses))) * 100) : 0;
    const roi = parseInt(stats.total_wagered) > 0 ? ((parseInt(stats.net_profit) / parseInt(stats.total_wagered)) * 100) : 0;

    res.json({
      username: user.username, display_name: user.display_name,
      balance: member.balance, role: member.role,
      stats: { ...stats, win_rate: Math.round(winRate * 10) / 10, roi: Math.round(roi * 10) / 10 },
      byType, parlayStats, recent,
      streak: { count: streak, type: streakType },
    });
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

// ═══ WEEKLY RECAP ═══
app.get("/api/pools/:poolId/recap/:week", auth, async (req, res) => {
  try {
    const member = await q1("SELECT * FROM pool_members WHERE pool_id=$1 AND user_id=$2 AND status='active'", [req.params.poolId, req.user.id]);
    if (!member) return res.status(403).json({ error: "Not in pool" });
    const week = parseInt(req.params.week);

    // Get games for this week
    const games = await q("SELECT * FROM games WHERE week=$1 ORDER BY commence_time", [week]);

    // Get all bets for this week in this pool
    const weekBets = await q(`SELECT b.*, g.home_team, g.away_team, g.home_score, g.away_score, g.week,
      u.display_name, pm.balance
      FROM bets b JOIN games g ON b.game_id=g.id JOIN pool_members pm ON b.member_id=pm.id JOIN users u ON pm.user_id=u.id
      WHERE b.pool_id=$1 AND g.week=$2 ORDER BY b.wager DESC`, [req.params.poolId, week]);

    // Player summaries for the week
    const playerSummaries = await q(`SELECT u.display_name, pm.balance,
      COUNT(*) FILTER (WHERE b.result='win') as wins,
      COUNT(*) FILTER (WHERE b.result='loss') as losses,
      COALESCE(SUM(CASE WHEN b.result='win' THEN b.payout - b.wager WHEN b.result='loss' THEN -b.wager ELSE 0 END),0) as week_profit
      FROM bets b JOIN games g ON b.game_id=g.id JOIN pool_members pm ON b.member_id=pm.id JOIN users u ON pm.user_id=u.id
      WHERE b.pool_id=$1 AND g.week=$2 AND b.result != 'pending'
      GROUP BY u.display_name, pm.balance ORDER BY week_profit DESC`, [req.params.poolId, week]);

    // Biggest win/loss
    const bigWin = await q1(`SELECT b.wager, b.payout, b.bet_type, b.pick, b.line, u.display_name
      FROM bets b JOIN pool_members pm ON b.member_id=pm.id JOIN users u ON pm.user_id=u.id JOIN games g ON b.game_id=g.id
      WHERE b.pool_id=$1 AND g.week=$2 AND b.result='win' ORDER BY (b.payout - b.wager) DESC LIMIT 1`, [req.params.poolId, week]);

    const bigLoss = await q1(`SELECT b.wager, b.bet_type, b.pick, b.line, u.display_name
      FROM bets b JOIN pool_members pm ON b.member_id=pm.id JOIN users u ON pm.user_id=u.id JOIN games g ON b.game_id=g.id
      WHERE b.pool_id=$1 AND g.week=$2 AND b.result='loss' ORDER BY b.wager DESC LIMIT 1`, [req.params.poolId, week]);

    res.json({ week, games, bets: weekBets, playerSummaries, bigWin, bigLoss });
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

// ═══ CSV EXPORTS ═══
app.get("/api/pools/:poolId/export/standings", auth, async (req, res) => {
  try {
    const lb = await q(`SELECT u.display_name, u.username, pm.balance, pm.role,
      (SELECT COUNT(*) FROM bets WHERE member_id=pm.id AND result='win') as wins,
      (SELECT COUNT(*) FROM bets WHERE member_id=pm.id AND result='loss') as losses,
      (SELECT COUNT(*) FROM bets WHERE member_id=pm.id AND result='push') as pushes,
      (SELECT COALESCE(SUM(wager),0) FROM bets WHERE member_id=pm.id AND result='pending') as pending,
      (pm.balance + (SELECT COALESCE(SUM(wager),0) FROM bets WHERE member_id=pm.id AND result='pending')) as display_balance
      FROM pool_members pm JOIN users u ON pm.user_id=u.id
      WHERE pm.pool_id=$1 AND pm.status='active'
      ORDER BY display_balance DESC`, [req.params.poolId]);
    let csv = "Rank,Name,Username,Balance,Display Balance,Wins,Losses,Pushes,Pending,Role\n";
    lb.forEach((p, i) => {
      csv += `${i + 1},"${p.display_name}",${p.username},${p.balance},${p.display_balance},${p.wins},${p.losses},${p.pushes},${p.pending},${p.role}\n`;
    });
    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", "attachment; filename=standings.csv");
    res.send(csv);
  } catch (err) { res.status(500).json({ error: "Server error" }); }
});

app.get("/api/pools/:poolId/export/bets", auth, async (req, res) => {
  try {
    const member = await q1("SELECT * FROM pool_members WHERE pool_id=$1 AND user_id=$2", [req.params.poolId, req.user.id]);
    if (!member) return res.status(403).json({ error: "Not in pool" });
    const bets = await q(`SELECT b.*, g.home_team, g.away_team, g.home_score, g.away_score, g.week, g.commence_time
      FROM bets b JOIN games g ON b.game_id=g.id WHERE b.member_id=$1 ORDER BY b.created_at DESC`, [member.id]);
    let csv = "Date,Week,Game,Type,Pick,Line,Odds,Wager,Result,Payout,Profit\n";
    for (const b of bets) {
      const profit = b.result === "win" ? b.payout - b.wager : b.result === "loss" ? -b.wager : 0;
      csv += `"${new Date(b.created_at).toLocaleDateString()}",${b.week||""},"${b.away_team} @ ${b.home_team}",${b.bet_type},"${b.pick}",${b.line||""},${b.odds||""},${b.wager},${b.result},${b.payout},${profit}\n`;
    }
    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", "attachment; filename=my-bets.csv");
    res.send(csv);
  } catch (err) { res.status(500).json({ error: "Server error" }); }
});

// ═══ HEALTH ═══
app.get("/", (req, res) => { res.json({ status: "ok", app: "UFL Fantasy Sportsbook Pool", oddsApiConfigured: !!ODDS_API_KEY }); });

// ═══ CRON ═══
cron.schedule("0 */4 * * *", () => { console.log("Cron: odds"); fetchOdds(); });
cron.schedule("*/15 * * * 0,1,5,6", () => { console.log("Cron: scores"); fetchScores(); });
cron.schedule("0 */2 * * 2,3,4", () => { console.log("Cron: safety scores"); fetchScores(); });

// ═══ START ═══
app.listen(PORT, async () => {
  console.log("UFL Pool running on port " + PORT);
  await initDB();
  if (ODDS_API_KEY) { console.log("Fetching odds..."); const c = await fetchOdds(); console.log("Loaded " + c + " games"); }
});
