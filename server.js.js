// ═══════════════════════════════════════════════════════════════
// UFL FANTASY SPORTSBOOK POOL — Backend Server
// Deploy to Railway in ~10 minutes (instructions below)
// ═══════════════════════════════════════════════════════════════

const express = require("express");
const cors = require("cors");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cron = require("node-cron");

const app = express();
app.use(cors());
app.use(express.json());

// ── Config ──
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME_IN_PRODUCTION";
const ODDS_API_KEY = process.env.ODDS_API_KEY;
const SPORT = "americanfootball_ufl";
const PORT = process.env.PORT || 3001;

// ── UUID helper ──
function uuid() {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    return (c === "x" ? r : (r & 0x3) | 0x8).toString(16);
  });
}

// ═══════════════════════════════════════════
// DATABASE SETUP
// ═══════════════════════════════════════════

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
```

**After your existing login route**, paste in all three routes from the **Password Reset — Backend Routes** artifact (the `forgot-password`, `verify-reset`, and `reset-password` routes).

**Step 4: Push to Railway**

If you deployed via GitHub, just commit and push:
```
git add .
git commit -m "add password reset"
git push
`);

// ═══════════════════════════════════════════
// AUTH MIDDLEWARE
// ═══════════════════════════════════════════

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

// Helper: check if user is admin of a pool
function requireAdmin(req, res) {
  const admin = db
    .prepare(
      "SELECT * FROM pool_members WHERE pool_id=? AND user_id=? AND role='admin' AND status='active'"
    )
    .get(req.params.poolId, req.user.id);
  if (!admin) {
    res.status(403).json({ error: "Admin access required" });
    return null;
  }
  return admin;
}

// ═══════════════════════════════════════════
// AUTH ROUTES
// ═══════════════════════════════════════════

// Register
app.post("/api/auth/register", (req, res) => {
  const { username, email, password, displayName } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ error: "Username, email, and password required" });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters" });
  }

  const existing = db
    .prepare("SELECT id FROM users WHERE username=? OR email=?")
    .get(username.toLowerCase(), email.toLowerCase());
  if (existing) {
    return res.status(409).json({ error: "Username or email already taken" });
  }

  const id = uuid();
  const hash = bcrypt.hashSync(password, 10);
  db.prepare(
    "INSERT INTO users (id, username, email, password_hash, display_name) VALUES (?,?,?,?,?)"
  ).run(id, username.toLowerCase(), email.toLowerCase(), hash, displayName || username);

  const token = jwt.sign({ id, username: username.toLowerCase() }, JWT_SECRET, {
    expiresIn: "30d",
  });
  res.json({
    token,
    user: { id, username: username.toLowerCase(), displayName: displayName || username },
  });
});

// Login
app.post("/api/auth/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }

  const user = db
    .prepare("SELECT * FROM users WHERE username=? OR email=?")
    .get(username.toLowerCase(), username.toLowerCase());
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, {
    expiresIn: "30d",
  });
  res.json({
    token,
    user: { id: user.id, username: user.username, displayName: user.display_name },
  });
});

// Get current user info
app.get("/api/auth/me", auth, (req, res) => {
  const user = db.prepare("SELECT id, username, display_name, email FROM users WHERE id=?").get(req.user.id);
  if (!user) return res.status(404).json({ error: "User not found" });
  res.json(user);
});

// ═══════════════════════════════════════════
// POOL ROUTES
// ═══════════════════════════════════════════

// List my pools
app.get("/api/my-pools", auth, (req, res) => {
  const pools = db
    .prepare(
      `SELECT p.*, pm.role, pm.status, pm.balance,
        (SELECT COUNT(*) FROM pool_members WHERE pool_id=p.id AND status='active') as member_count
      FROM pools p
      JOIN pool_members pm ON pm.pool_id = p.id
      WHERE pm.user_id = ?
      ORDER BY p.created_at DESC`
    )
    .all(req.user.id);
  res.json(pools);
});

// Create pool
app.post("/api/pools", auth, (req, res) => {
  const { name, startingBalance, requireApproval } = req.body;
  if (!name) return res.status(400).json({ error: "Pool name required" });

  const id = uuid();
  const joinCode = Math.random().toString(36).substring(2, 8).toUpperCase();
  const bal = startingBalance || 1000;

  db.prepare(
    "INSERT INTO pools (id, name, join_code, commissioner_id, starting_balance, require_approval) VALUES (?,?,?,?,?,?)"
  ).run(id, name, joinCode, req.user.id, bal, requireApproval !== false ? 1 : 0);

  // Creator auto-joins as admin, active
  const memberId = uuid();
  db.prepare(
    "INSERT INTO pool_members (id, pool_id, user_id, role, status, balance) VALUES (?,?,?,?,?,?)"
  ).run(memberId, id, req.user.id, "admin", "active", bal);

  res.json({ id, joinCode, name });
});

// Join pool by code
app.post("/api/pools/:code/join", auth, (req, res) => {
  const pool = db
    .prepare("SELECT * FROM pools WHERE join_code=?")
    .get(req.params.code.toUpperCase());
  if (!pool) return res.status(404).json({ error: "Pool not found" });

  const existing = db
    .prepare("SELECT * FROM pool_members WHERE pool_id=? AND user_id=?")
    .get(pool.id, req.user.id);
  if (existing) {
    if (existing.status === "deactivated") {
      return res.status(403).json({ error: "You have been removed from this pool" });
    }
    return res.status(409).json({ error: "Already a member of this pool" });
  }

  const id = uuid();
  const status = pool.require_approval ? "pending" : "active";
  db.prepare(
    "INSERT INTO pool_members (id, pool_id, user_id, role, status, balance) VALUES (?,?,?,?,?,?)"
  ).run(id, pool.id, req.user.id, "member", status, pool.starting_balance);

  res.json({ status, poolId: pool.id, poolName: pool.name });
});

// ═══════════════════════════════════════════
// ADMIN ROUTES
// ═══════════════════════════════════════════

// List all members (admin only)
app.get("/api/pools/:poolId/members", auth, (req, res) => {
  if (!requireAdmin(req, res)) return;
  const members = db
    .prepare(
      `SELECT pm.*, u.username, u.display_name
      FROM pool_members pm JOIN users u ON pm.user_id = u.id
      WHERE pm.pool_id = ?
      ORDER BY
        CASE pm.status WHEN 'pending' THEN 0 WHEN 'active' THEN 1 ELSE 2 END,
        pm.balance DESC`
    )
    .all(req.params.poolId);
  res.json(members);
});

// Approve member
app.post("/api/pools/:poolId/members/:memberId/approve", auth, (req, res) => {
  if (!requireAdmin(req, res)) return;
  const member = db
    .prepare("SELECT * FROM pool_members WHERE id=? AND pool_id=?")
    .get(req.params.memberId, req.params.poolId);
  if (!member) return res.status(404).json({ error: "Member not found" });
  if (member.status !== "pending") return res.status(400).json({ error: "Member is not pending" });

  db.prepare("UPDATE pool_members SET status='active' WHERE id=?").run(req.params.memberId);
  res.json({ success: true, message: "Member approved" });
});

// Deactivate member
app.post("/api/pools/:poolId/members/:memberId/deactivate", auth, (req, res) => {
  if (!requireAdmin(req, res)) return;
  const member = db
    .prepare("SELECT * FROM pool_members WHERE id=? AND pool_id=?")
    .get(req.params.memberId, req.params.poolId);
  if (!member) return res.status(404).json({ error: "Member not found" });
  if (member.role === "admin") return res.status(400).json({ error: "Cannot deactivate an admin" });

  db.prepare("UPDATE pool_members SET status='deactivated' WHERE id=?").run(req.params.memberId);
  res.json({ success: true, message: "Member deactivated" });
});

// Reactivate member
app.post("/api/pools/:poolId/members/:memberId/reactivate", auth, (req, res) => {
  if (!requireAdmin(req, res)) return;
  db.prepare("UPDATE pool_members SET status='active' WHERE id=?").run(req.params.memberId);
  res.json({ success: true, message: "Member reactivated" });
});

// ═══════════════════════════════════════════
// GAMES & ODDS (The Odds API)
// ═══════════════════════════════════════════

async function fetchOdds() {
  if (!ODDS_API_KEY) {
    console.log("⚠️  No ODDS_API_KEY set — skipping odds fetch");
    return 0;
  }

  try {
    const url = `https://api.the-odds-api.com/v4/sports/${SPORT}/odds/?apiKey=${ODDS_API_KEY}&regions=us&markets=spreads,totals,h2h&oddsFormat=american`;
    const res = await fetch(url);

    if (!res.ok) {
      console.error(`Odds API error: ${res.status} ${res.statusText}`);
      return 0;
    }

    const data = await res.json();
    const remaining = res.headers.get("x-requests-remaining");
    const used = res.headers.get("x-requests-used");
    console.log(`✅ Odds fetched: ${data.length} games | API usage: ${used} used, ${remaining} remaining`);

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
        // Use first available bookmaker
        const book = event.bookmakers?.[0];
        if (!book) continue;

        let spreadHome = null, spreadAway = null, total = null, mlHome = null, mlAway = null;

        for (const market of book.markets) {
          if (market.key === "spreads") {
            for (const o of market.outcomes) {
              if (o.name === event.home_team) spreadHome = o.point;
              else spreadAway = o.point;
            }
          }
          if (market.key === "totals") {
            const over = market.outcomes.find((o) => o.name === "Over");
            if (over) total = over.point;
          }
          if (market.key === "h2h") {
            for (const o of market.outcomes) {
              if (o.name === event.home_team) mlHome = o.price;
              else mlAway = o.price;
            }
          }
        }

        upsert.run(
          event.id, event.commence_time, event.home_team, event.away_team,
          spreadHome, spreadAway, total, mlHome, mlAway
        );
      }
    });

    insertMany(data);
    return data.length;
  } catch (err) {
    console.error("❌ Odds fetch failed:", err.message);
    return 0;
  }
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
        const homeScore = event.scores.find((s) => s.name === event.home_team);
        const awayScore = event.scores.find((s) => s.name === event.away_team);
        if (homeScore && awayScore) {
          db.prepare("UPDATE games SET home_score=?, away_score=?, status='final' WHERE id=? AND status='upcoming'")
            .run(parseInt(homeScore.score), parseInt(awayScore.score), event.id);
          graded++;
        }
      }
    }

    if (graded > 0) {
      console.log(`🏈 ${graded} games completed — grading bets...`);
      gradeBets();
    }
  } catch (err) {
    console.error("❌ Score fetch failed:", err.message);
  }
}

// ═══════════════════════════════════════════
// BET GRADING
// ═══════════════════════════════════════════

function gradeBets() {
  const pending = db.prepare(`
    SELECT b.*, g.home_team, g.away_team, g.home_score, g.away_score
    FROM bets b
    JOIN games g ON b.game_id = g.id
    WHERE b.result = 'pending' AND g.status = 'final' AND b.parlay_group IS NULL
  `).all();

  for (const bet of pending) {
    const { home_score, away_score, home_team, away_team } = bet;
    const totalScore = home_score + away_score;
    let result = "loss";
    let payout = 0;

    if (bet.bet_type === "spread") {
      const pickScore = bet.pick === home_team ? home_score : away_score;
      const oppScore = bet.pick === home_team ? away_score : home_score;
      const margin = pickScore - oppScore + bet.line;
      result = margin > 0 ? "win" : margin === 0 ? "push" : "loss";
    } else if (bet.bet_type === "over") {
      result = totalScore > bet.line ? "win" : totalScore === bet.line ? "push" : "loss";
    } else if (bet.bet_type === "under") {
      result = totalScore < bet.line ? "win" : totalScore === bet.line ? "push" : "loss";
    } else if (bet.bet_type === "moneyline") {
      if (home_score === away_score) {
        result = "push";
      } else {
        const winner = home_score > away_score ? home_team : away_team;
        result = bet.pick === winner ? "win" : "loss";
      }
    }

    // Calculate payout
    if (result === "win") {
      if (bet.bet_type === "moneyline" && bet.odds) {
        const odds = bet.odds;
        payout = odds < 0
          ? bet.wager + Math.round(bet.wager * (100 / Math.abs(odds)))
          : bet.wager + Math.round(bet.wager * (odds / 100));
      } else {
        // Standard -110 payout for spreads and totals
        payout = bet.wager + Math.round(bet.wager * (100 / 110));
      }
    } else if (result === "push") {
      payout = bet.wager;
    }

    // Update bet and player balance
    db.prepare("UPDATE bets SET result=?, payout=? WHERE id=?").run(result, payout, bet.id);
    if (payout > 0) {
      db.prepare("UPDATE pool_members SET balance = balance + ? WHERE id=?").run(payout, bet.member_id);
    }
  }

  // ── Grade parlays ──
  const parlayGroups = db.prepare(`
    SELECT DISTINCT parlay_group FROM bets
    WHERE parlay_group IS NOT NULL AND result = 'pending'
  `).all();

  for (const { parlay_group } of parlayGroups) {
    const legs = db.prepare(`
      SELECT b.*, g.home_team, g.away_team, g.home_score, g.away_score, g.status as game_status
      FROM bets b JOIN games g ON b.game_id = g.id
      WHERE b.parlay_group = ?
    `).all(parlay_group);

    // Only grade if ALL games in parlay are final
    if (legs.some((l) => l.game_status !== "final")) continue;

    let allWin = true;
    let anyPush = false;
    let totalMultiplier = 1;

    for (const leg of legs) {
      const { home_score, away_score, home_team, away_team } = leg;
      const totalScore = home_score + away_score;
      let legResult = "loss";

      if (leg.bet_type === "spread") {
        const pickScore = leg.pick === home_team ? home_score : away_score;
        const oppScore = leg.pick === home_team ? away_score : home_score;
        const margin = pickScore - oppScore + leg.line;
        legResult = margin > 0 ? "win" : margin === 0 ? "push" : "loss";
      } else if (leg.bet_type === "over") {
        legResult = totalScore > leg.line ? "win" : totalScore === leg.line ? "push" : "loss";
      } else if (leg.bet_type === "under") {
        legResult = totalScore < leg.line ? "win" : totalScore === leg.line ? "push" : "loss";
      } else if (leg.bet_type === "moneyline") {
        if (home_score === away_score) legResult = "push";
        else legResult = leg.pick === (home_score > away_score ? home_team : away_team) ? "win" : "loss";
      }

      if (legResult === "loss") allWin = false;
      if (legResult === "push") anyPush = true;

      // Build multiplier for winning/push legs
      if (legResult === "win") {
        if (leg.bet_type === "moneyline" && leg.odds) {
          const o = leg.odds;
          totalMultiplier *= o < 0 ? 1 + 100 / Math.abs(o) : 1 + o / 100;
        } else {
          totalMultiplier *= 1.909; // -110 odds
        }
      }
      // Push legs are removed from parlay (multiplier stays same)

      db.prepare("UPDATE bets SET result=? WHERE id=?").run(legResult, leg.id);
    }

    // Payout: all must win (pushes reduce parlay but don't kill it)
    const firstLeg = legs[0];
    let parlayPayout = 0;
    if (allWin) {
      parlayPayout = Math.round(firstLeg.wager * totalMultiplier);
    } else if (anyPush && !legs.some((l) => l.result === "loss")) {
      parlayPayout = Math.round(firstLeg.wager * totalMultiplier);
    }
    // else loss — no payout

    if (parlayPayout > 0) {
      db.prepare("UPDATE pool_members SET balance = balance + ? WHERE id=?").run(parlayPayout, firstLeg.member_id);
    }
  }

  console.log("✅ Bet grading complete");
}

// ═══════════════════════════════════════════
// BETTING ROUTES
// ═══════════════════════════════════════════

// Get all games
app.get("/api/games", (req, res) => {
  const games = db.prepare("SELECT * FROM games ORDER BY commence_time").all();
  res.json(games);
});

// Get upcoming games only
app.get("/api/games/upcoming", (req, res) => {
  const games = db.prepare("SELECT * FROM games WHERE status='upcoming' ORDER BY commence_time").all();
  res.json(games);
});

// Place a bet
app.post("/api/bet", auth, (req, res) => {
  const { pool_id, game_id, bet_type, pick, line, odds, wager, parlay_group } = req.body;

  const member = db
    .prepare("SELECT * FROM pool_members WHERE pool_id=? AND user_id=? AND status='active'")
    .get(pool_id, req.user.id);
  if (!member) return res.status(403).json({ error: "Not an active member of this pool" });

  const game = db.prepare("SELECT * FROM games WHERE id=?").get(game_id);
  if (!game) return res.status(404).json({ error: "Game not found" });
  if (game.status !== "upcoming") return res.status(400).json({ error: "Game already started" });

  // Check game hasn't started by time
  if (new Date(game.commence_time) <= new Date()) {
    return res.status(400).json({ error: "Game has already kicked off" });
  }

  if (!wager || wager <= 0) return res.status(400).json({ error: "Invalid wager amount" });
  if (wager > member.balance) return res.status(400).json({ error: "Insufficient balance" });

  // Deduct wager
  db.prepare("UPDATE pool_members SET balance = balance - ? WHERE id=?").run(wager, member.id);

  // Insert bet
  const id = uuid();
  db.prepare(
    "INSERT INTO bets (id, member_id, pool_id, game_id, bet_type, pick, line, odds, wager, parlay_group) VALUES (?,?,?,?,?,?,?,?,?,?)"
  ).run(id, member.id, pool_id, game_id, bet_type, pick, line, odds, wager, parlay_group || null);

  res.json({ success: true, betId: id, newBalance: member.balance - wager });
});

// Get my bets in a pool
app.get("/api/pools/:poolId/my-bets", auth, (req, res) => {
  const member = db
    .prepare("SELECT * FROM pool_members WHERE pool_id=? AND user_id=?")
    .get(req.params.poolId, req.user.id);
  if (!member) return res.status(403).json({ error: "Not in this pool" });

  const bets = db
    .prepare(
      `SELECT b.*, g.home_team, g.away_team, g.home_score, g.away_score, g.commence_time
      FROM bets b JOIN games g ON b.game_id = g.id
      WHERE b.member_id = ?
      ORDER BY b.created_at DESC`
    )
    .all(member.id);
  res.json(bets);
});

// Leaderboard
app.get("/api/pools/:poolId/leaderboard", (req, res) => {
  const lb = db
    .prepare(
      `SELECT pm.balance, pm.status, pm.role, u.display_name, u.username,
        (SELECT COUNT(*) FROM bets WHERE member_id=pm.id AND result='win') as wins,
        (SELECT COUNT(*) FROM bets WHERE member_id=pm.id AND result='loss') as losses,
        (SELECT COUNT(*) FROM bets WHERE member_id=pm.id AND result='push') as pushes
      FROM pool_members pm
      JOIN users u ON pm.user_id = u.id
      WHERE pm.pool_id = ? AND pm.status = 'active'
      ORDER BY pm.balance DESC`
    )
    .all(req.params.poolId);
  res.json(lb);
});

// ═══════════════════════════════════════════
// ADMIN: Manual triggers (useful for testing)
// ═══════════════════════════════════════════

app.post("/api/admin/refresh-odds", auth, async (req, res) => {
  const count = await fetchOdds();
  res.json({ success: true, gamesUpdated: count });
});

app.post("/api/admin/refresh-scores", auth, async (req, res) => {
  await fetchScores();
  res.json({ success: true, message: "Scores refreshed and bets graded" });
});

// ═══════════════════════════════════════════
// HEALTH CHECK (Railway uses this)
// ═══════════════════════════════════════════

app.get("/", (req, res) => {
  res.json({
    status: "ok",
    app: "UFL Fantasy Sportsbook Pool",
    oddsApiConfigured: !!ODDS_API_KEY,
    timestamp: new Date().toISOString(),
  });
});

app.get("/api/health", (req, res) => {
  const gameCount = db.prepare("SELECT COUNT(*) as count FROM games").get().count;
  const userCount = db.prepare("SELECT COUNT(*) as count FROM users").get().count;
  res.json({ status: "ok", games: gameCount, users: userCount });
});

// ═══════════════════════════════════════════
// CRON JOBS — Auto-fetch odds & scores
// ═══════════════════════════════════════════

// Fetch odds every 3 hours (uses ~8 requests/day = ~240/month)
cron.schedule("0 */3 * * *", () => {
  console.log("⏰ Cron: Fetching odds...");
  fetchOdds();
});

// Fetch scores every 20 min on Sat & Sun (UFL game days)
// Uses ~6 requests/game day = ~48/month for 8 weekends
cron.schedule("*/20 * * * 6,0", () => {
  console.log("⏰ Cron: Checking scores...");
  fetchScores();
});

// ═══════════════════════════════════════════
// START SERVER
// ═══════════════════════════════════════════

app.listen(PORT, async () => {
  console.log(`\n🏈 UFL Pool server running on port ${PORT}`);
  console.log(`   Odds API: ${ODDS_API_KEY ? "✅ Configured" : "⚠️  Not set (add ODDS_API_KEY)"}`);
  console.log(`   JWT Secret: ${JWT_SECRET === "CHANGE_ME_IN_PRODUCTION" ? "⚠️  Using default (change in production!)" : "✅ Custom"}`);

  // Fetch odds on startup
  if (ODDS_API_KEY) {
    console.log("\n📡 Fetching initial odds...");
    const count = await fetchOdds();
    console.log(`   Loaded ${count} games\n`);
  }
});
