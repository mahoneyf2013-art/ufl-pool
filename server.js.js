const express = require("express");
const cors = require("cors");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cron = require("node-cron");

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME_IN_PRODUCTION";
const ODDS_API_KEY = process.env.ODDS_API_KEY;
const SPORT = "americanfootball_ufl";
const PORT = process.env.PORT || 3001;
const APP_URL = process.env.APP_URL || "http://localhost:5173";

// Resend (optional — only if RESEND_API_KEY is set)
let resend = null;
try {
  const { Resend } = require("resend");
  if (process.env.RESEND_API_KEY) {
    resend = new Resend(process.env.RESEND_API_KEY);
    console.log("📧 Resend configured");
  }
} catch (e) {
  console.log("📧 Resend not installed — password reset emails disabled");
}

function uuid() {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    return (c === "x" ? r : (r & 0x3) | 0x8).toString(16);
  });
}

const db = new Database("ufl_pool.db");
db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    display_name TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS pools (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    join_code TEXT UNIQUE NOT NULL,
    commissioner_id TEXT NOT NULL,
    starting_balance INTEGER DEFAULT 1000,
    require_approval INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (commissioner_id) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS pool_members (
    id TEXT PRIMARY KEY,
    pool_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role TEXT DEFAULT 'member',
    status TEXT DEFAULT 'pending',
    balance INTEGER DEFAULT 1000,
    joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (pool_id) REFERENCES pools(id),
    FOREIGN KEY (user_id) REFERENCES users(id),
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
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
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
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (member_id) REFERENCES pool_members(id),
    FOREIGN KEY (game_id) REFERENCES games(id)
  );
  CREATE TABLE IF NOT EXISTS password_resets (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token TEXT UNIQUE NOT NULL,
    expires_at DATETIME NOT NULL,
    used INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

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

function requireAdmin(req, res) {
  const admin = db.prepare("SELECT * FROM pool_members WHERE pool_id=? AND user_id=? AND role='admin' AND status='active'").get(req.params.poolId, req.user.id);
  if (!admin) { res.status(403).json({ error: "Admin access required" }); return null; }
  return admin;
}

// ═══ AUTH ═══

app.post("/api/auth/register", (req, res) => {
  const { username, email, password, displayName } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: "Username, email, and password required" });
  if (password.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters" });
  const existing = db.prepare("SELECT id FROM users WHERE username=? OR email=?").get(username.toLowerCase(), email.toLowerCase());
  if (existing) return res.status(409).json({ error: "Username or email already taken" });
  const id = uuid();
  const hash = bcrypt.hashSync(password, 10);
  db.prepare("INSERT INTO users (id, username, email, password_hash, display_name) VALUES (?,?,?,?,?)").run(id, username.toLowerCase(), email.toLowerCase(), hash, displayName || username);
  const token = jwt.sign({ id, username: username.toLowerCase() }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, user: { id, username: username.toLowerCase(), displayName: displayName || username } });
});

app.post("/api/auth/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Username and password required" });
  const user = db.prepare("SELECT * FROM users WHERE username=? OR email=?").get(username.toLowerCase(), username.toLowerCase());
  if (!user || !bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ error: "Invalid credentials" });
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, user: { id: user.id, username: user.username, displayName: user.display_name } });
});

app.get("/api/auth/me", auth, (req, res) => {
  const user = db.prepare("SELECT id, username, display_name, email FROM users WHERE id=?").get(req.user.id);
  if (!user) return res.status(404).json({ error: "User not found" });
  res.json(user);
});

// ═══ PASSWORD RESET ═══

app.post("/api/auth/forgot-password", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email required" });
  const user = db.prepare("SELECT * FROM users WHERE email=?").get(email.toLowerCase());
  if (!user) return res.json({ success: true, message: "If that email exists, a reset link has been sent." });

  const token = Array.from({ length: 32 }, () => Math.random().toString(36).charAt(2)).join("");
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
  const id = uuid();

  db.prepare("UPDATE password_resets SET used=1 WHERE user_id=? AND used=0").run(user.id);
  db.prepare("INSERT INTO password_resets (id, user_id, token, expires_at) VALUES (?,?,?,?)").run(id, user.id, token, expiresAt);

  const resetLink = `${APP_URL}?reset=${token}`;

  if (resend) {
    try {
      await resend.emails.send({
        from: "UFL Pool <noreply@resend.dev>",
        to: email.toLowerCase(),
        subject: "Reset Your UFL Pool Password",
        html: `
          <div style="font-family: -apple-system, sans-serif; max-width: 480px; margin: 0 auto; padding: 40px 20px;">
            <div style="text-align: center; margin-bottom: 30px;">
              <h1 style="color: #3b82f6; font-size: 28px; margin: 0;">UFL POOL</h1>
              <p style="color: #6b7280; font-size: 14px;">Password Reset Request</p>
            </div>
            <p style="color: #333; font-size: 15px; line-height: 1.6;">Hey ${user.display_name},</p>
            <p style="color: #333; font-size: 15px; line-height: 1.6;">Someone requested a password reset for your UFL Pool account. Click the button below to set a new password:</p>
            <div style="text-align: center; margin: 30px 0;">
              <a href="${resetLink}" style="background: #3b82f6; color: white; padding: 14px 32px; border-radius: 8px; text-decoration: none; font-weight: 700; font-size: 15px; display: inline-block;">Reset Password</a>
            </div>
            <p style="color: #6b7280; font-size: 13px; line-height: 1.6;">This link expires in 1 hour. If you didn't request this, you can safely ignore this email.</p>
          </div>
        `,
      });
      console.log("Email sent to " + email);
    } catch (err) {
      console.error("Email send failed:", err.message);
    }
  } else {
    console.log("Reset link (no email configured): " + resetLink);
  }

  res.json({ success: true, message: "If that email exists, a reset link has been sent." });
});

app.get("/api/auth/verify-reset/:token", (req, res) => {
  const reset = db.prepare("SELECT * FROM password_resets WHERE token=? AND used=0 AND expires_at > datetime('now')").get(req.params.token);
  if (!reset) return res.status(400).json({ error: "Invalid or expired reset link" });
  res.json({ valid: true });
});

app.post("/api/auth/reset-password", (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) return res.status(400).json({ error: "Token and new password required" });
  if (newPassword.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters" });
  const reset = db.prepare("SELECT * FROM password_resets WHERE token=? AND used=0 AND expires_at > datetime('now')").get(token);
  if (!reset) return res.status(400).json({ error: "Invalid or expired reset link" });
  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare("UPDATE users SET password_hash=? WHERE id=?").run(hash, reset.user_id);
  db.prepare("UPDATE password_resets SET used=1 WHERE id=?").run(reset.id);
  const user = db.prepare("SELECT * FROM users WHERE id=?").get(reset.user_id);
  const jwtToken = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ success: true, token: jwtToken, user: { id: user.id, username: user.username, displayName: user.display_name } });
});

// ═══ POOLS ═══

app.get("/api/my-pools", auth, (req, res) => {
  const pools = db.prepare(`
    SELECT p.*, pm.role, pm.status, pm.balance,
      (SELECT COUNT(*) FROM pool_members WHERE pool_id=p.id AND status='active') as member_count
    FROM pools p JOIN pool_members pm ON pm.pool_id = p.id
    WHERE pm.user_id = ? ORDER BY p.created_at DESC
  `).all(req.user.id);
  res.json(pools);
});

app.post("/api/pools", auth, (req, res) => {
  const { name, startingBalance, requireApproval } = req.body;
  if (!name) return res.status(400).json({ error: "Pool name required" });
  const id = uuid();
  const joinCode = Math.random().toString(36).substring(2, 8).toUpperCase();
  const bal = startingBalance || 1000;
  db.prepare("INSERT INTO pools (id, name, join_code, commissioner_id, starting_balance, require_approval) VALUES (?,?,?,?,?,?)").run(id, name, joinCode, req.user.id, bal, requireApproval !== false ? 1 : 0);
  const memberId = uuid();
  db.prepare("INSERT INTO pool_members (id, pool_id, user_id, role, status, balance) VALUES (?,?,?,?,?,?)").run(memberId, id, req.user.id, "admin", "active", bal);
  res.json({ id, joinCode, name });
});

app.post("/api/pools/:code/join", auth, (req, res) => {
  const pool = db.prepare("SELECT * FROM pools WHERE join_code=?").get(req.params.code.toUpperCase());
  if (!pool) return res.status(404).json({ error: "Pool not found" });
  const existing = db.prepare("SELECT * FROM pool_members WHERE pool_id=? AND user_id=?").get(pool.id, req.user.id);
  if (existing) {
    if (existing.status === "deactivated") return res.status(403).json({ error: "You have been removed from this pool" });
    return res.status(409).json({ error: "Already a member of this pool" });
  }
  const id = uuid();
  const status = pool.require_approval ? "pending" : "active";
  db.prepare("INSERT INTO pool_members (id, pool_id, user_id, role, status, balance) VALUES (?,?,?,?,?,?)").run(id, pool.id, req.user.id, "member", status, pool.starting_balance);
  res.json({ status, poolId: pool.id, poolName: pool.name });
});

// ═══ ADMIN ═══

app.get("/api/pools/:poolId/members", auth, (req, res) => {
  if (!requireAdmin(req, res)) return;
  const members = db.prepare(`
    SELECT pm.*, u.username, u.display_name
    FROM pool_members pm JOIN users u ON pm.user_id = u.id
    WHERE pm.pool_id = ?
    ORDER BY CASE pm.status WHEN 'pending' THEN 0 WHEN 'active' THEN 1 ELSE 2 END, pm.balance DESC
  `).all(req.params.poolId);
  res.json(members);
});

app.post("/api/pools/:poolId/members/:memberId/approve", auth, (req, res) => {
  if (!requireAdmin(req, res)) return;
  const member = db.prepare("SELECT * FROM pool_members WHERE id=? AND pool_id=?").get(req.params.memberId, req.params.poolId);
  if (!member) return res.status(404).json({ error: "Member not found" });
  db.prepare("UPDATE pool_members SET status='active' WHERE id=?").run(req.params.memberId);
  res.json({ success: true });
});

app.post("/api/pools/:poolId/members/:memberId/deactivate", auth, (req, res) => {
  if (!requireAdmin(req, res)) return;
  const member = db.prepare("SELECT * FROM pool_members WHERE id=? AND pool_id=?").get(req.params.memberId, req.params.poolId);
  if (!member) return res.status(404).json({ error: "Member not found" });
  if (member.role === "admin") return res.status(400).json({ error: "Cannot deactivate an admin" });
  db.prepare("UPDATE pool_members SET status='deactivated' WHERE id=?").run(req.params.memberId);
  res.json({ success: true });
});

app.post("/api/pools/:poolId/members/:memberId/reactivate", auth, (req, res) => {
  if (!requireAdmin(req, res)) return;
  db.prepare("UPDATE pool_members SET status='active' WHERE id=?").run(req.params.memberId);
  res.json({ success: true });
});

// ═══ GAMES & ODDS ═══

async function fetchOdds() {
  if (!ODDS_API_KEY) { console.log("No ODDS_API_KEY set"); return 0; }
  try {
    const url = `https://api.the-odds-api.com/v4/sports/${SPORT}/odds/?apiKey=${ODDS_API_KEY}&regions=us&markets=spreads,totals,h2h&oddsFormat=american`;
    const res = await fetch(url);
    if (!res.ok) { console.error("Odds API error: " + res.status); return 0; }
    const data = await res.json();
    const remaining = res.headers.get("x-requests-remaining");
    console.log("Odds fetched: " + data.length + " games | Remaining: " + remaining);

    const upsert = db.prepare(`
      INSERT INTO games (id, commence_time, home_team, away_team, spread_home, spread_away, total, moneyline_home, moneyline_away, status, last_updated)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'upcoming', CURRENT_TIMESTAMP)
      ON CONFLICT(id) DO UPDATE SET
        spread_home=excluded.spread_home, spread_away=excluded.spread_away,
        total=excluded.total, moneyline_home=excluded.moneyline_home,
        moneyline_away=excluded.moneyline_away, last_updated=CURRENT_TIMESTAMP,
        commence_time=excluded.commence_time
    `);

    const insertMany = db.transaction((events) => {
      for (const event of events) {
        const book = event.bookmakers?.[0];
        if (!book) continue;
        let sh = null, sa = null, tot = null, mlh = null, mla = null;
        for (const market of book.markets) {
          if (market.key === "spreads") { for (const o of market.outcomes) { if (o.name === event.home_team) sh = o.point; else sa = o.point; } }
          if (market.key === "totals") { const ov = market.outcomes.find((o) => o.name === "Over"); if (ov) tot = ov.point; }
          if (market.key === "h2h") { for (const o of market.outcomes) { if (o.name === event.home_team) mlh = o.price; else mla = o.price; } }
        }
        upsert.run(event.id, event.commence_time, event.home_team, event.away_team, sh, sa, tot, mlh, mla);
      }
    });
    insertMany(data);
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
        const as = event.scores.find((s) => s.name === event.away_team);
        if (hs && as) {
          db.prepare("UPDATE games SET home_score=?, away_score=?, status='final' WHERE id=? AND status='upcoming'").run(parseInt(hs.score), parseInt(as.score), event.id);
          graded++;
        }
      }
    }
    if (graded > 0) { console.log(graded + " games completed — grading bets..."); gradeBets(); }
  } catch (err) { console.error("Score fetch failed:", err.message); }
}

function gradeBets() {
  const pending = db.prepare(`
    SELECT b.*, g.home_team, g.away_team, g.home_score, g.away_score
    FROM bets b JOIN games g ON b.game_id = g.id
    WHERE b.result = 'pending' AND g.status = 'final' AND b.parlay_group IS NULL
  `).all();

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
      } else {
        payout = bet.wager + Math.round(bet.wager * (100 / 110));
      }
    } else if (result === "push") { payout = bet.wager; }

    db.prepare("UPDATE bets SET result=?, payout=? WHERE id=?").run(result, payout, bet.id);
    if (payout > 0) db.prepare("UPDATE pool_members SET balance = balance + ? WHERE id=?").run(payout, bet.member_id);
  }

  const parlayGroups = db.prepare("SELECT DISTINCT parlay_group FROM bets WHERE parlay_group IS NOT NULL AND result = 'pending'").all();
  for (const { parlay_group } of parlayGroups) {
    const legs = db.prepare("SELECT b.*, g.home_team, g.away_team, g.home_score, g.away_score, g.status as game_status FROM bets b JOIN games g ON b.game_id = g.id WHERE b.parlay_group = ?").all(parlay_group);
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
      db.prepare("UPDATE bets SET result=? WHERE id=?").run(lr, leg.id);
    }
    const first = legs[0];
    let pp = 0;
    if (allWin || (anyPush && !legs.some((l) => l.result === "loss"))) { pp = Math.round(first.wager * multiplier); }
    if (pp > 0) db.prepare("UPDATE pool_members SET balance = balance + ? WHERE id=?").run(pp, first.member_id);
  }
  console.log("Bet grading complete");
}

// ═══ BETTING ROUTES ═══

app.get("/api/games", (req, res) => {
  res.json(db.prepare("SELECT * FROM games ORDER BY commence_time").all());
});

app.get("/api/games/upcoming", (req, res) => {
  res.json(db.prepare("SELECT * FROM games WHERE status='upcoming' ORDER BY commence_time").all());
});

app.post("/api/bet", auth, (req, res) => {
  const { pool_id, game_id, bet_type, pick, line, odds, wager, parlay_group } = req.body;
  const member = db.prepare("SELECT * FROM pool_members WHERE pool_id=? AND user_id=? AND status='active'").get(pool_id, req.user.id);
  if (!member) return res.status(403).json({ error: "Not an active member" });
  const game = db.prepare("SELECT * FROM games WHERE id=?").get(game_id);
  if (!game) return res.status(404).json({ error: "Game not found" });
  if (game.status !== "upcoming") return res.status(400).json({ error: "Game already started" });
  if (new Date(game.commence_time) <= new Date()) return res.status(400).json({ error: "Game has already kicked off" });
  if (!wager || wager <= 0) return res.status(400).json({ error: "Invalid wager" });
  if (wager > member.balance) return res.status(400).json({ error: "Insufficient balance" });
  db.prepare("UPDATE pool_members SET balance = balance - ? WHERE id=?").run(wager, member.id);
  const id = uuid();
  db.prepare("INSERT INTO bets (id, member_id, pool_id, game_id, bet_type, pick, line, odds, wager, parlay_group) VALUES (?,?,?,?,?,?,?,?,?,?)").run(id, member.id, pool_id, game_id, bet_type, pick, line, odds, wager, parlay_group || null);
  res.json({ success: true, betId: id, newBalance: member.balance - wager });
});

// Pool activity feed — pending bets with hidden details until game starts
app.get("/api/pools/:poolId/activity", auth, (req, res) => {
  const member = db.prepare("SELECT * FROM pool_members WHERE pool_id=? AND user_id=? AND status='active'").get(req.params.poolId, req.user.id);
  if (!member) return res.status(403).json({ error: "Not in pool" });

  const bets = db.prepare(`
    SELECT b.id, b.bet_type, b.pick, b.line, b.odds, b.wager, b.result, b.payout,
           b.parlay_group, b.created_at, b.member_id, b.game_id,
           g.home_team, g.away_team, g.commence_time, g.status as game_status,
           g.home_score, g.away_score,
           u.display_name, u.username
    FROM bets b
    JOIN games g ON b.game_id = g.id
    JOIN pool_members pm ON b.member_id = pm.id
    JOIN users u ON pm.user_id = u.id
    WHERE b.pool_id = ?
    ORDER BY b.created_at DESC
  `).all(req.params.poolId);

  const now = new Date();
  const processed = bets.map(bet => {
    const gameStarted = new Date(bet.commence_time) <= now || bet.game_status !== "upcoming";
    const isOwn = bet.member_id === member.id;
    return {
      id: bet.id,
      display_name: bet.display_name,
      username: bet.username,
      wager: bet.wager,
      result: bet.result,
      payout: bet.payout,
      created_at: bet.created_at,
      parlay_group: bet.parlay_group,
      game_id: bet.game_id,
      game_status: bet.game_status,
      commence_time: bet.commence_time,
      home_team: bet.home_team,
      away_team: bet.away_team,
      home_score: bet.home_score,
      away_score: bet.away_score,
      revealed: gameStarted || isOwn,
      bet_type: (gameStarted || isOwn) ? bet.bet_type : null,
      pick: (gameStarted || isOwn) ? bet.pick : null,
      line: (gameStarted || isOwn) ? bet.line : null,
      odds: (gameStarted || isOwn) ? bet.odds : null,
      is_own: isOwn,
    };
  });

  res.json(processed);
});

app.get("/api/pools/:poolId/my-bets", auth, (req, res) => {
  const member = db.prepare("SELECT * FROM pool_members WHERE pool_id=? AND user_id=?").get(req.params.poolId, req.user.id);
  if (!member) return res.status(403).json({ error: "Not in pool" });
  const bets = db.prepare("SELECT b.*, g.home_team, g.away_team, g.home_score, g.away_score, g.commence_time FROM bets b JOIN games g ON b.game_id = g.id WHERE b.member_id = ? ORDER BY b.created_at DESC").all(member.id);
  res.json(bets);
});

app.get("/api/pools/:poolId/leaderboard", (req, res) => {
  const lb = db.prepare(`
    SELECT pm.balance, pm.status, pm.role, u.display_name, u.username,
      (SELECT COUNT(*) FROM bets WHERE member_id=pm.id AND result='win') as wins,
      (SELECT COUNT(*) FROM bets WHERE member_id=pm.id AND result='loss') as losses,
      (SELECT COUNT(*) FROM bets WHERE member_id=pm.id AND result='push') as pushes,
      (SELECT COALESCE(SUM(wager), 0) FROM bets WHERE member_id=pm.id AND result='pending') as pending_amount,
      (pm.balance + (SELECT COALESCE(SUM(wager), 0) FROM bets WHERE member_id=pm.id AND result='pending')) as display_balance
    FROM pool_members pm JOIN users u ON pm.user_id = u.id
    WHERE pm.pool_id = ? AND pm.status = 'active'
    ORDER BY (pm.balance + (SELECT COALESCE(SUM(wager), 0) FROM bets WHERE member_id=pm.id AND result='pending')) DESC
  `).all(req.params.poolId);
  res.json(lb);
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

app.get("/api/health", (req, res) => {
  const gc = db.prepare("SELECT COUNT(*) as count FROM games").get().count;
  const uc = db.prepare("SELECT COUNT(*) as count FROM users").get().count;
  res.json({ status: "ok", games: gc, users: uc });
});

// ═══ CRON ═══

cron.schedule("0 */3 * * *", () => { console.log("Cron: Fetching odds..."); fetchOdds(); });
cron.schedule("*/20 * * * 6,0", () => { console.log("Cron: Checking scores..."); fetchScores(); });

// ═══ START ═══

app.listen(PORT, async () => {
  console.log("UFL Pool server running on port " + PORT);
  console.log("Odds API: " + (ODDS_API_KEY ? "Configured" : "Not set"));
  console.log("Resend: " + (resend ? "Configured" : "Not configured"));
  if (ODDS_API_KEY) {
    console.log("Fetching initial odds...");
    const count = await fetchOdds();
    console.log("Loaded " + count + " games");
  }
});
