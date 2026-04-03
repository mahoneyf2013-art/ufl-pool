import React, {
  useState,
  useEffect,
  useCallback,
  useRef,
  createContext,
  useContext,
  useMemo,
} from "react";

// ─── Constants ───────────────────────────────────────────────────────────────
const API_URL = "https://ufl-pool-production.up.railway.app";

const UFL_TEAMS = {
  DC: { name: "DC Defenders", abbr: "DC", color: "#E31937", espnId: "dc-defenders" },
  AR: { name: "Arlington Renegades", abbr: "AR", color: "#2E8B57", espnId: "arlington-renegades" },
  HOU: { name: "Houston Roughnecks", abbr: "HOU", color: "#002244", espnId: "houston-roughnecks" },
  MEM: { name: "Memphis Showboats", abbr: "MEM", color: "#FFB81C", espnId: "memphis-showboats" },
  MCH: { name: "Michigan Panthers", abbr: "MCH", color: "#003366", espnId: "michigan-panthers" },
  BIR: { name: "Birmingham Stallions", abbr: "BIR", color: "#862633", espnId: "birmingham-stallions" },
  STL: { name: "St. Louis Battlehawks", abbr: "STL", color: "#003DA5", espnId: "stl-battlehawks" },
  SA: { name: "San Antonio Brahmas", abbr: "SA", color: "#6C2D3A", espnId: "san-antonio-brahmas" },
};

const ESPN_LOGO_URL = (teamEspnId) =>
  `https://a.espncdn.com/combiner/i?img=/i/teamlogos/leagues/500/ufl.png&h=80&w=80`;

const TEAM_LOGO = (abbr) => {
  const t = UFL_TEAMS[abbr];
  if (!t) return "";
  return `https://a.espncdn.com/combiner/i?img=/i/teamlogos/leagues/500/ufl.png&h=40&w=40`;
};

// ─── Contexts ────────────────────────────────────────────────────────────────
const AuthContext = createContext(null);
const useAuth = () => useContext(AuthContext);

// ─── Utility Helpers ─────────────────────────────────────────────────────────
const api = async (path, opts = {}) => {
  const token = localStorage.getItem("token");
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(`${API_URL}${path}`, { ...opts, headers });
  if (res.status === 401) {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    window.location.reload();
    throw new Error("Unauthorized");
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || err.message || res.statusText);
  }
  if (res.status === 204) return null;
  return res.json();
};

const formatMoney = (n) =>
  "$" + Number(n || 0).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });

const formatOdds = (odds) => {
  if (!odds && odds !== 0) return "—";
  return odds > 0 ? `+${odds}` : `${odds}`;
};

const calcPayout = (wager, odds) => {
  if (!odds || !wager) return 0;
  if (odds > 0) return wager * (odds / 100);
  return wager * (100 / Math.abs(odds));
};

const timeAgo = (date) => {
  const s = Math.floor((Date.now() - new Date(date).getTime()) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
};

const isLockedForBetting = (kickoff) => {
  if (!kickoff) return true;
  return new Date(kickoff).getTime() - Date.now() < 5 * 60 * 1000;
};

const downloadCSV = (rows, filename) => {
  if (!rows.length) return;
  const keys = Object.keys(rows[0]);
  const csv = [keys.join(","), ...rows.map((r) => keys.map((k) => `"${r[k] ?? ""}"`).join(","))].join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
};

// ─── Error Boundary ──────────────────────────────────────────────────────────
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }
  componentDidCatch(err, info) {
    console.error("ErrorBoundary caught:", err, info);
  }
  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: 40, textAlign: "center" }}>
          <h2 style={{ color: "#e74c3c" }}>Something went wrong</h2>
          <p style={{ color: "#999" }}>{this.state.error?.message}</p>
          <button
            onClick={() => { this.setState({ hasError: false }); window.location.reload(); }}
            style={btnPrimary}
          >
            Reload App
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

// ─── Spinner ─────────────────────────────────────────────────────────────────
const Spinner = ({ size = 32, text }) => (
  <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 8, padding: 32 }}>
    <div
      style={{
        width: size, height: size, border: "3px solid #333", borderTopColor: "#00bfff",
        borderRadius: "50%", animation: "spin 0.8s linear infinite",
      }}
    />
    {text && <span style={{ color: "#aaa", fontSize: 13 }}>{text}</span>}
    <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
  </div>
);

// ─── Modal ───────────────────────────────────────────────────────────────────
const Modal = ({ open, onClose, title, children, width = 480 }) => {
  if (!open) return null;
  return (
    <div
      onClick={onClose}
      style={{
        position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)", zIndex: 9999,
        display: "flex", alignItems: "center", justifyContent: "center", padding: 16,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          background: "#1a1a2e", borderRadius: 12, maxWidth: width, width: "100%",
          maxHeight: "90vh", overflowY: "auto", padding: 24, position: "relative",
          border: "1px solid #333",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
          <h3 style={{ margin: 0, color: "#fff" }}>{title}</h3>
          <button onClick={onClose} style={{ background: "none", border: "none", color: "#999", fontSize: 22, cursor: "pointer" }}>✕</button>
        </div>
        {children}
      </div>
    </div>
  );
};

// ─── Common Styles ───────────────────────────────────────────────────────────
const btnPrimary = {
  background: "linear-gradient(135deg, #00bfff, #0080ff)", color: "#fff", border: "none",
  borderRadius: 8, padding: "10px 20px", cursor: "pointer", fontWeight: 600, fontSize: 14,
};
const btnDanger = { ...btnPrimary, background: "linear-gradient(135deg, #ff4444, #cc0000)" };
const btnSecondary = {
  background: "transparent", color: "#aaa", border: "1px solid #444",
  borderRadius: 8, padding: "10px 20px", cursor: "pointer", fontWeight: 500, fontSize: 14,
};
const inputStyle = {
  width: "100%", padding: "10px 14px", background: "#0d0d1a", border: "1px solid #333",
  borderRadius: 8, color: "#fff", fontSize: 14, boxSizing: "border-box",
};
const cardStyle = {
  background: "#16213e", borderRadius: 10, padding: 16, marginBottom: 12,
  border: "1px solid #1a1a3e",
};

// ─── TeamLogo ────────────────────────────────────────────────────────────────
const TeamLogo = ({ abbr, size = 36 }) => {
  const t = UFL_TEAMS[abbr];
  return (
    <div
      style={{
        width: size, height: size, borderRadius: "50%", display: "flex",
        alignItems: "center", justifyContent: "center", fontWeight: 800,
        fontSize: size * 0.38, color: "#fff", background: t?.color || "#555",
        flexShrink: 0, border: "2px solid rgba(255,255,255,0.15)",
      }}
    >
      {abbr}
    </div>
  );
};

// ═══════════════════════════════════════════════════════════════════════════════
// AUTH PAGES
// ═══════════════════════════════════════════════════════════════════════════════
const LoginPage = ({ onSwitch, onLogin }) => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const data = await api("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
      localStorage.setItem("token", data.token);
      localStorage.setItem("user", JSON.stringify(data.user));
      onLogin(data.user, data.token);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", background: "#0a0a1a", padding: 16 }}>
      <div style={{ maxWidth: 400, width: "100%", background: "#12122a", borderRadius: 16, padding: 32, border: "1px solid #222" }}>
        <h1 style={{ textAlign: "center", color: "#00bfff", margin: "0 0 8px" }}>🏈 UFL Pool</h1>
        <p style={{ textAlign: "center", color: "#777", marginBottom: 24 }}>Sign in to your account</p>
        {error && <div style={{ background: "#2a0a0a", color: "#ff6b6b", padding: 10, borderRadius: 8, marginBottom: 16, fontSize: 13 }}>{error}</div>}
        <form onSubmit={submit}>
          <label style={{ color: "#aaa", fontSize: 12, display: "block", marginBottom: 4 }}>Username</label>
          <input value={username} onChange={(e) => setUsername(e.target.value)} style={{ ...inputStyle, marginBottom: 14 }} required />
          <label style={{ color: "#aaa", fontSize: 12, display: "block", marginBottom: 4 }}>Password</label>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} style={{ ...inputStyle, marginBottom: 20 }} required />
          <button type="submit" disabled={loading} style={{ ...btnPrimary, width: "100%", padding: 12 }}>
            {loading ? "Signing in…" : "Sign In"}
          </button>
        </form>
        <div style={{ display: "flex", justifyContent: "space-between", marginTop: 16 }}>
          <button onClick={() => onSwitch("register")} style={{ background: "none", border: "none", color: "#00bfff", cursor: "pointer", fontSize: 13 }}>Create account</button>
          <button onClick={() => onSwitch("forgot")} style={{ background: "none", border: "none", color: "#666", cursor: "pointer", fontSize: 13 }}>Forgot password?</button>
        </div>
      </div>
    </div>
  );
};

const RegisterPage = ({ onSwitch }) => {
  const [form, setForm] = useState({ username: "", email: "", password: "", confirmPassword: "" });
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);
  const set = (k) => (e) => setForm((p) => ({ ...p, [k]: e.target.value }));

  const submit = async (e) => {
    e.preventDefault();
    setError("");
    if (form.password !== form.confirmPassword) return setError("Passwords do not match");
    if (form.password.length < 6) return setError("Password must be at least 6 characters");
    setLoading(true);
    try {
      await api("/api/auth/register", { method: "POST", body: JSON.stringify(form) });
      setSuccess("Account created! Check your email for verification, then sign in.");
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", background: "#0a0a1a", padding: 16 }}>
      <div style={{ maxWidth: 400, width: "100%", background: "#12122a", borderRadius: 16, padding: 32, border: "1px solid #222" }}>
        <h2 style={{ textAlign: "center", color: "#fff", margin: "0 0 24px" }}>Create Account</h2>
        {error && <div style={{ background: "#2a0a0a", color: "#ff6b6b", padding: 10, borderRadius: 8, marginBottom: 16, fontSize: 13 }}>{error}</div>}
        {success ? (
          <div>
            <div style={{ background: "#0a2a0a", color: "#6bff6b", padding: 12, borderRadius: 8, marginBottom: 16, fontSize: 13 }}>{success}</div>
            <button onClick={() => onSwitch("login")} style={{ ...btnPrimary, width: "100%" }}>Back to Login</button>
          </div>
        ) : (
          <form onSubmit={submit}>
            <label style={{ color: "#aaa", fontSize: 12, display: "block", marginBottom: 4 }}>Username</label>
            <input value={form.username} onChange={set("username")} style={{ ...inputStyle, marginBottom: 14 }} required />
            <label style={{ color: "#aaa", fontSize: 12, display: "block", marginBottom: 4 }}>Email</label>
            <input type="email" value={form.email} onChange={set("email")} style={{ ...inputStyle, marginBottom: 14 }} required />
            <label style={{ color: "#aaa", fontSize: 12, display: "block", marginBottom: 4 }}>Password</label>
            <input type="password" value={form.password} onChange={set("password")} style={{ ...inputStyle, marginBottom: 14 }} required />
            <label style={{ color: "#aaa", fontSize: 12, display: "block", marginBottom: 4 }}>Confirm Password</label>
            <input type="password" value={form.confirmPassword} onChange={set("confirmPassword")} style={{ ...inputStyle, marginBottom: 20 }} required />
            <button type="submit" disabled={loading} style={{ ...btnPrimary, width: "100%", padding: 12 }}>
              {loading ? "Creating…" : "Register"}
            </button>
          </form>
        )}
        <button onClick={() => onSwitch("login")} style={{ background: "none", border: "none", color: "#00bfff", cursor: "pointer", fontSize: 13, marginTop: 16, display: "block", textAlign: "center", width: "100%" }}>
          ← Back to Login
        </button>
      </div>
    </div>
  );
};

const ForgotPasswordPage = ({ onSwitch }) => {
  const [email, setEmail] = useState("");
  const [token, setToken] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [step, setStep] = useState(1);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);

  const sendReset = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await api("/api/auth/forgot-password", { method: "POST", body: JSON.stringify({ email }) });
      setSuccess("Reset email sent! Check your inbox.");
      setStep(2);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const resetPw = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await api("/api/auth/reset-password", { method: "POST", body: JSON.stringify({ token, newPassword }) });
      setSuccess("Password reset! You can now log in.");
      setStep(3);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", background: "#0a0a1a", padding: 16 }}>
      <div style={{ maxWidth: 400, width: "100%", background: "#12122a", borderRadius: 16, padding: 32, border: "1px solid #222" }}>
        <h2 style={{ textAlign: "center", color: "#fff", margin: "0 0 24px" }}>Reset Password</h2>
        {error && <div style={{ background: "#2a0a0a", color: "#ff6b6b", padding: 10, borderRadius: 8, marginBottom: 16, fontSize: 13 }}>{error}</div>}
        {step === 1 && (
          <form onSubmit={sendReset}>
            <label style={{ color: "#aaa", fontSize: 12, display: "block", marginBottom: 4 }}>Email</label>
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} style={{ ...inputStyle, marginBottom: 20 }} required />
            <button type="submit" disabled={loading} style={{ ...btnPrimary, width: "100%", padding: 12 }}>{loading ? "Sending…" : "Send Reset Link"}</button>
          </form>
        )}
        {step === 2 && (
          <form onSubmit={resetPw}>
            <div style={{ background: "#0a2a0a", color: "#6bff6b", padding: 10, borderRadius: 8, marginBottom: 16, fontSize: 13 }}>{success}</div>
            <label style={{ color: "#aaa", fontSize: 12, display: "block", marginBottom: 4 }}>Reset Token (from email)</label>
            <input value={token} onChange={(e) => setToken(e.target.value)} style={{ ...inputStyle, marginBottom: 14 }} required />
            <label style={{ color: "#aaa", fontSize: 12, display: "block", marginBottom: 4 }}>New Password</label>
            <input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} style={{ ...inputStyle, marginBottom: 20 }} required />
            <button type="submit" disabled={loading} style={{ ...btnPrimary, width: "100%", padding: 12 }}>{loading ? "Resetting…" : "Reset Password"}</button>
          </form>
        )}
        {step === 3 && (
          <div>
            <div style={{ background: "#0a2a0a", color: "#6bff6b", padding: 12, borderRadius: 8, marginBottom: 16, fontSize: 13 }}>{success}</div>
            <button onClick={() => onSwitch("login")} style={{ ...btnPrimary, width: "100%" }}>Go to Login</button>
          </div>
        )}
        <button onClick={() => onSwitch("login")} style={{ background: "none", border: "none", color: "#00bfff", cursor: "pointer", fontSize: 13, marginTop: 16, display: "block", textAlign: "center", width: "100%" }}>
          ← Back to Login
        </button>
      </div>
    </div>
  );
};

// ═══════════════════════════════════════════════════════════════════════════════
// SIDEBAR NAVIGATION
// ═══════════════════════════════════════════════════════════════════════════════
const NAV_SECTIONS = [
  { label: "Bet", items: [{ key: "board", icon: "📋", label: "Board" }, { key: "parlay", icon: "🎯", label: "Parlay" }] },
  { label: "Games", items: [{ key: "live", icon: "🔴", label: "Live Scores" }, { key: "schedule", icon: "📅", label: "Schedule" }, { key: "recap", icon: "📊", label: "Weekly Recap" }] },
  { label: "Pool", items: [{ key: "activity", icon: "📜", label: "Activity" }, { key: "chat", icon: "💬", label: "Chat" }, { key: "standings", icon: "🏆", label: "Standings" }] },
  { label: "Me", items: [{ key: "profile", icon: "👤", label: "Profile" }, { key: "mybets", icon: "🎰", label: "My Bets" }] },
  { label: "", items: [{ key: "news", icon: "📰", label: "News" }] },
];

const Sidebar = ({ open, onClose, current, onNav, user }) => {
  const isAdmin = user?.role === "admin";
  return (
    <>
      {open && <div onClick={onClose} style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)", zIndex: 999 }} />}
      <div
        style={{
          position: "fixed", top: 0, left: open ? 0 : -280, width: 270, height: "100vh",
          background: "#0d0d1a", borderRight: "1px solid #222", zIndex: 1000,
          transition: "left 0.25s ease", overflowY: "auto", display: "flex", flexDirection: "column",
        }}
      >
        <div style={{ padding: "20px 16px 12px", borderBottom: "1px solid #1a1a2e" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: 24 }}>🏈</span>
            <div>
              <div style={{ color: "#fff", fontWeight: 700 }}>{user?.username}</div>
              <div style={{ color: "#00bfff", fontSize: 12 }}>{formatMoney(user?.balance)}</div>
            </div>
          </div>
        </div>
        <div style={{ flex: 1, padding: "8px 0" }}>
          {NAV_SECTIONS.map((sec, si) => (
            <div key={si}>
              {sec.label && <div style={{ padding: "12px 16px 4px", color: "#555", fontSize: 11, fontWeight: 600, textTransform: "uppercase", letterSpacing: 1 }}>{sec.label}</div>}
              {sec.items.map((item) => (
                <button
                  key={item.key}
                  onClick={() => { onNav(item.key); onClose(); }}
                  style={{
                    display: "flex", alignItems: "center", gap: 10, width: "100%",
                    padding: "10px 16px", background: current === item.key ? "rgba(0,191,255,0.1)" : "transparent",
                    border: "none", color: current === item.key ? "#00bfff" : "#ccc",
                    cursor: "pointer", fontSize: 14, textAlign: "left",
                    borderLeft: current === item.key ? "3px solid #00bfff" : "3px solid transparent",
                  }}
                >
                  <span>{item.icon}</span> {item.label}
                </button>
              ))}
            </div>
          ))}
          {isAdmin && (
            <div>
              <div style={{ padding: "12px 16px 4px", color: "#555", fontSize: 11, fontWeight: 600, textTransform: "uppercase", letterSpacing: 1 }}>Admin</div>
              <button
                onClick={() => { onNav("admin"); onClose(); }}
                style={{
                  display: "flex", alignItems: "center", gap: 10, width: "100%",
                  padding: "10px 16px", background: current === "admin" ? "rgba(0,191,255,0.1)" : "transparent",
                  border: "none", color: current === "admin" ? "#00bfff" : "#ccc",
                  cursor: "pointer", fontSize: 14, textAlign: "left",
                  borderLeft: current === "admin" ? "3px solid #00bfff" : "3px solid transparent",
                }}
              >
                <span>⚙️</span> Admin Panel
              </button>
            </div>
          )}
        </div>
        <div style={{ padding: 16, borderTop: "1px solid #1a1a2e" }}>
          <button
            onClick={() => {
              if (window.confirm("Leave the pool and log out?")) {
                localStorage.removeItem("token");
                localStorage.removeItem("user");
                window.location.reload();
              }
            }}
            style={{ ...btnDanger, width: "100%", padding: 10, fontSize: 13 }}
          >
            🚪 Leave Pool / Logout
          </button>
        </div>
      </div>
    </>
  );
};

// ═══════════════════════════════════════════════════════════════════════════════
// BOARD PAGE
// ═══════════════════════════════════════════════════════════════════════════════
const BoardPage = () => {
  const { user, refreshUser } = useAuth();
  const [games, setGames] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState({});
  const [betModal, setBetModal] = useState(null);
  const [wager, setWager] = useState("");
  const [placing, setPlacing] = useState(false);
  const [error, setError] = useState("");
  const [confirmModal, setConfirmModal] = useState(null);

  const fetchGames = useCallback(async () => {
    try {
      const data = await api("/api/games/board");
      setGames(data || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchGames(); }, [fetchGames]);

  const toggleExpand = (id) => setExpanded((p) => ({ ...p, [id]: !p[id] }));

  const openBet = (game, betType, team, odds) => {
    const locked = isLockedForBetting(game.kickoff);
    if (locked) return alert("This game is locked for betting (within 5 min of kickoff).");
    setBetModal({ game, betType, team, odds });
    setWager("");
    setError("");
  };

  const placeBet = async () => {
    const w = parseFloat(wager);
    if (!w || w <= 0) return setError("Enter a valid wager");
    if (w > (user?.balance || 0)) return setError("Insufficient balance");
    // Check 25% threshold for confirmation
    if (w > (user?.balance || 0) * 0.25 && !confirmModal) {
      setConfirmModal(true);
      return;
    }
    setPlacing(true);
    setError("");
    try {
      await api("/api/bets", {
        method: "POST",
        body: JSON.stringify({
          game_id: betModal.game.id,
          bet_type: betModal.betType,
          team: betModal.team,
          odds: betModal.odds,
          amount: w,
        }),
      });
      setBetModal(null);
      setConfirmModal(null);
      refreshUser();
      fetchGames();
    } catch (err) {
      setError(err.message);
    } finally {
      setPlacing(false);
    }
  };

  if (loading) return <Spinner text="Loading board…" />;

  return (
    <div>
      <h2 style={{ color: "#fff", margin: "0 0 16px" }}>📋 Betting Board</h2>
      {games.length === 0 && <p style={{ color: "#888" }}>No games available for betting.</p>}
      {games.map((g) => {
        const locked = isLockedForBetting(g.kickoff);
        return (
          <div key={g.id} style={{ ...cardStyle, opacity: locked ? 0.6 : 1 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <span style={{ color: "#888", fontSize: 12 }}>
                {new Date(g.kickoff).toLocaleDateString("en-US", { weekday: "short", month: "short", day: "numeric" })}{" "}
                {new Date(g.kickoff).toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit" })}
              </span>
              {locked && <span style={{ color: "#ff6b6b", fontSize: 11, fontWeight: 600 }}>🔒 LOCKED</span>}
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
              <TeamLogo abbr={g.away_team} />
              <div style={{ flex: 1 }}>
                <div style={{ color: "#fff", fontWeight: 600 }}>{UFL_TEAMS[g.away_team]?.name || g.away_team}</div>
                <div style={{ color: "#888", fontSize: 12 }}>@ {UFL_TEAMS[g.home_team]?.name || g.home_team}</div>
              </div>
              <TeamLogo abbr={g.home_team} />
            </div>
            {/* Spread */}
            <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
              <button
                onClick={() => openBet(g, "spread", g.away_team, g.away_spread_odds)}
                disabled={locked}
                style={{ flex: 1, padding: "8px 4px", background: "#1a1a3e", border: "1px solid #333", borderRadius: 6, color: "#fff", cursor: locked ? "default" : "pointer", fontSize: 13 }}
              >
                {g.away_team} {g.away_spread > 0 ? "+" : ""}{g.away_spread}<br />
                <span style={{ color: "#00bfff", fontSize: 12 }}>{formatOdds(g.away_spread_odds)}</span>
              </button>
              <button
                onClick={() => openBet(g, "spread", g.home_team, g.home_spread_odds)}
                disabled={locked}
                style={{ flex: 1, padding: "8px 4px", background: "#1a1a3e", border: "1px solid #333", borderRadius: 6, color: "#fff", cursor: locked ? "default" : "pointer", fontSize: 13 }}
              >
                {g.home_team} {g.home_spread > 0 ? "+" : ""}{g.home_spread}<br />
                <span style={{ color: "#00bfff", fontSize: 12 }}>{formatOdds(g.home_spread_odds)}</span>
              </button>
            </div>
            {/* Moneyline */}
            <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
              <button
                onClick={() => openBet(g, "moneyline", g.away_team, g.away_ml)}
                disabled={locked}
                style={{ flex: 1, padding: "8px 4px", background: "#1a1a3e", border: "1px solid #333", borderRadius: 6, color: "#fff", cursor: locked ? "default" : "pointer", fontSize: 13 }}
              >
                {g.away_team} ML<br />
                <span style={{ color: "#ffd700", fontSize: 12 }}>{formatOdds(g.away_ml)}</span>
              </button>
              <button
                onClick={() => openBet(g, "moneyline", g.home_team, g.home_ml)}
                disabled={locked}
                style={{ flex: 1, padding: "8px 4px", background: "#1a1a3e", border: "1px solid #333", borderRadius: 6, color: "#fff", cursor: locked ? "default" : "pointer", fontSize: 13 }}
              >
                {g.home_team} ML<br />
                <span style={{ color: "#ffd700", fontSize: 12 }}>{formatOdds(g.home_ml)}</span>
              </button>
            </div>
            {/* Over/Under */}
            {g.total && (
              <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
                <button
                  onClick={() => openBet(g, "over", "over", g.over_odds)}
                  disabled={locked}
                  style={{ flex: 1, padding: "8px 4px", background: "#1a1a3e", border: "1px solid #333", borderRadius: 6, color: "#fff", cursor: locked ? "default" : "pointer", fontSize: 13 }}
                >
                  O {g.total}<br />
                  <span style={{ color: "#4ecdc4", fontSize: 12 }}>{formatOdds(g.over_odds)}</span>
                </button>
                <button
                  onClick={() => openBet(g, "under", "under", g.under_odds)}
                  disabled={locked}
                  style={{ flex: 1, padding: "8px 4px", background: "#1a1a3e", border: "1px solid #333", borderRadius: 6, color: "#fff", cursor: locked ? "default" : "pointer", fontSize: 13 }}
                >
                  U {g.total}<br />
                  <span style={{ color: "#4ecdc4", fontSize: 12 }}>{formatOdds(g.under_odds)}</span>
                </button>
              </div>
            )}
            {/* Line History Toggle */}
            <button
              onClick={() => toggleExpand(g.id)}
              style={{ background: "none", border: "none", color: "#00bfff", cursor: "pointer", fontSize: 12 }}
            >
              {expanded[g.id] ? "▲ Hide" : "▼ Show"} Line History
            </button>
            {expanded[g.id] && (
              <div style={{ marginTop: 8, padding: 8, background: "#0d0d1a", borderRadius: 6, fontSize: 12, color: "#aaa" }}>
                {g.line_history && g.line_history.length > 0 ? (
                  g.line_history.map((lh, i) => (
                    <div key={i} style={{ display: "flex", justifyContent: "space-between", padding: "4px 0", borderBottom: "1px solid #1a1a2e" }}>
                      <span>{new Date(lh.timestamp).toLocaleString()}</span>
                      <span>Spread: {lh.home_spread > 0 ? "+" : ""}{lh.home_spread} | O/U: {lh.total} | ML: {formatOdds(lh.home_ml)}/{formatOdds(lh.away_ml)}</span>
                    </div>
                  ))
                ) : (
                  <span>No line movement data yet.</span>
                )}
              </div>
            )}
          </div>
        );
      })}

      {/* Bet Placement Modal */}
      <Modal open={!!betModal} onClose={() => { setBetModal(null); setConfirmModal(null); }} title="Place Bet">
        {betModal && (
          <div>
            <div style={{ ...cardStyle, background: "#0d0d1a" }}>
              <div style={{ color: "#fff", fontSize: 15, fontWeight: 600 }}>
                {betModal.betType === "spread" && `${betModal.team} Spread`}
                {betModal.betType === "moneyline" && `${betModal.team} Moneyline`}
                {betModal.betType === "over" && `Over ${betModal.game.total}`}
                {betModal.betType === "under" && `Under ${betModal.game.total}`}
              </div>
              <div style={{ color: "#00bfff", fontSize: 13, marginTop: 4 }}>
                {UFL_TEAMS[betModal.game.away_team]?.name} @ {UFL_TEAMS[betModal.game.home_team]?.name}
              </div>
              <div style={{ color: "#ffd700", fontSize: 14, marginTop: 4 }}>Odds: {formatOdds(betModal.odds)}</div>
            </div>
            <div style={{ marginBottom: 12 }}>
              <label style={{ color: "#aaa", fontSize: 12, display: "block", marginBottom: 4 }}>Wager Amount</label>
              <input
                type="number"
                value={wager}
                onChange={(e) => { setWager(e.target.value); setConfirmModal(null); }}
                placeholder="0.00"
                style={inputStyle}
              />
              <div style={{ color: "#888", fontSize: 12, marginTop: 4 }}>Balance: {formatMoney(user?.balance)}</div>
            </div>
            {parseFloat(wager) > 0 && (
              <div style={{ background: "#0a2a0a", padding: 10, borderRadius: 8, marginBottom: 12, fontSize: 13 }}>
                <div style={{ color: "#6bff6b" }}>
                  Potential Payout: {formatMoney(calcPayout(parseFloat(wager), betModal.odds))}
                </div>
                <div style={{ color: "#4ecdc4" }}>
                  Total Return: {formatMoney(parseFloat(wager) + calcPayout(parseFloat(wager), betModal.odds))}
                </div>
              </div>
            )}
            {confirmModal && (
              <div style={{ background: "#2a2a0a", padding: 10, borderRadius: 8, marginBottom: 12, border: "1px solid #ffd700" }}>
                <div style={{ color: "#ffd700", fontSize: 13, fontWeight: 600 }}>⚠️ Large Wager Confirmation</div>
                <div style={{ color: "#ccc", fontSize: 12, marginTop: 4 }}>
                  This wager is more than 25% of your balance. Are you sure?
                </div>
              </div>
            )}
            {error && <div style={{ color: "#ff6b6b", fontSize: 13, marginBottom: 12 }}>{error}</div>}
            <div style={{ display: "flex", gap: 8 }}>
              <button onClick={() => { setBetModal(null); setConfirmModal(null); }} style={btnSecondary}>Cancel</button>
              <button onClick={placeBet} disabled={placing} style={{ ...btnPrimary, flex: 1 }}>
                {placing ? "Placing…" : confirmModal ? "Confirm Bet" : "Place Bet"}
              </button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
};

// ═══════════════════════════════════════════════════════════════════════════════
// PARLAY PAGE
// ═══════════════════════════════════════════════════════════════════════════════
const ParlayPage = () => {
  const { user, refreshUser } = useAuth();
  const [games, setGames] = useState([]);
  const [legs, setLegs] = useState([]);
  const [wager, setWager] = useState("");
  const [loading, setLoading] = useState(true);
  const [placing, setPlacing] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    api("/api/games/board").then((d) => { setGames(d || []); setLoading(false); }).catch(() => setLoading(false));
  }, []);

  const hasConflict = (newLeg) => {
    return legs.some((l) => {
      if (l.game_id !== newLeg.game_id) return false;
      // spread + moneyline on same team same game is a conflict
      const types = [l.bet_type, newLeg.bet_type].sort();
      if (types[0] === "moneyline" && types[1] === "spread" && l.team === newLeg.team) return true;
      // same exact bet
      if (l.bet_type === newLeg.bet_type && l.team === newLeg.team) return true;
      return false;
    });
  };

  const addLeg = (game, betType, team, odds) => {
    if (isLockedForBetting(game.kickoff)) return alert("Game is locked.");
    const leg = { game_id: game.id, bet_type: betType, team, odds, game };
    if (hasConflict(leg)) return alert("Conflict: Cannot combine spread + ML on the same team in the same game.");
    // Remove any same-game/same-type duplicate
    setLegs((prev) => [...prev.filter((l) => !(l.game_id === game.id && l.bet_type === betType)), leg]);
  };

  const removeLeg = (idx) => setLegs((p) => p.filter((_, i) => i !== idx));

  const totalOdds = useMemo(() => {
    if (legs.length < 2) return 0;
    let mult = 1;
    legs.forEach((l) => {
      const dec = l.odds > 0 ? l.odds / 100 + 1 : 100 / Math.abs(l.odds) + 1;
      mult *= dec;
    });
    return Math.round((mult - 1) * 100);
  }, [legs]);

  const parlayPayout = useMemo(() => {
    const w = parseFloat(wager) || 0;
    return calcPayout(w, totalOdds);
  }, [wager, totalOdds]);

  const placeParlay = async () => {
    if (legs.length < 2) return setError("Parlays require at least 2 legs.");
    const w = parseFloat(wager);
    if (!w || w <= 0) return setError("Enter a valid wager.");
    if (w > (user?.balance || 0)) return setError("Insufficient balance.");
    setPlacing(true);
    setError("");
    try {
      await api("/api/bets/parlay", {
        method: "POST",
        body: JSON.stringify({
          legs: legs.map((l) => ({ game_id: l.game_id, bet_type: l.bet_type, team: l.team, odds: l.odds })),
          amount: w,
        }),
      });
      setLegs([]);
      setWager("");
      refreshUser();
    } catch (err) {
      setError(err.message);
    } finally {
      setPlacing(false);
    }
  };

  if (loading) return <Spinner text="Loading games…" />;

  return (
    <div>
      <h2 style={{ color: "#fff", margin: "0 0 16px" }}>🎯 Parlay Builder</h2>
      {/* Parlay Slip */}
      {legs.length > 0 && (
        <div style={{ ...cardStyle, background: "#1a1a3e", marginBottom: 20, border: "1px solid #00bfff33" }}>
          <h4 style={{ color: "#00bfff", margin: "0 0 12px" }}>Parlay Slip ({legs.length} legs)</h4>
          {legs.map((l, i) => (
            <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "6px 0", borderBottom: "1px solid #1a1a2e" }}>
              <div>
                <span style={{ color: "#fff", fontSize: 13 }}>{l.team} {l.bet_type}</span>
                <span style={{ color: "#888", fontSize: 11, marginLeft: 6 }}>{formatOdds(l.odds)}</span>
              </div>
              <button onClick={() => removeLeg(i)} style={{ background: "none", border: "none", color: "#ff6b6b", cursor: "pointer", fontSize: 16 }}>×</button>
            </div>
          ))}
          {legs.length >= 2 && (
            <div style={{ marginTop: 12 }}>
              <div style={{ color: "#ffd700", fontSize: 14, fontWeight: 600, marginBottom: 8 }}>Parlay Odds: {formatOdds(totalOdds)}</div>
              <input
                type="number" value={wager} onChange={(e) => setWager(e.target.value)}
                placeholder="Wager amount" style={{ ...inputStyle, marginBottom: 8 }}
              />
              {parseFloat(wager) > 0 && (
                <div style={{ color: "#6bff6b", fontSize: 13, marginBottom: 8 }}>
                  Potential Payout: {formatMoney(parlayPayout)} | Total Return: {formatMoney(parseFloat(wager) + parlayPayout)}
                </div>
              )}
              {error && <div style={{ color: "#ff6b6b", fontSize: 13, marginBottom: 8 }}>{error}</div>}
              <button onClick={placeParlay} disabled={placing} style={{ ...btnPrimary, width: "100%" }}>
                {placing ? "Placing…" : "Place Parlay"}
              </button>
            </div>
          )}
        </div>
      )}
      {/* Game List */}
      {games.map((g) => {
        const locked = isLockedForBetting(g.kickoff);
        return (
          <div key={g.id} style={{ ...cardStyle, opacity: locked ? 0.5 : 1 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
              <TeamLogo abbr={g.away_team} size={28} />
              <span style={{ color: "#fff", fontSize: 14 }}>{g.away_team} @ {g.home_team}</span>
              <TeamLogo abbr={g.home_team} size={28} />
              {locked && <span style={{ color: "#ff6b6b", fontSize: 11, marginLeft: "auto" }}>🔒</span>}
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {[
                { type: "spread", team: g.away_team, odds: g.away_spread_odds, label: `${g.away_team} ${g.away_spread > 0 ? "+" : ""}${g.away_spread}` },
                { type: "spread", team: g.home_team, odds: g.home_spread_odds, label: `${g.home_team} ${g.home_spread > 0 ? "+" : ""}${g.home_spread}` },
                { type: "moneyline", team: g.away_team, odds: g.away_ml, label: `${g.away_team} ML` },
                { type: "moneyline", team: g.home_team, odds: g.home_ml, label: `${g.home_team} ML` },
                { type: "over", team: "over", odds: g.over_odds, label: `O ${g.total}` },
                { type: "under", team: "under", odds: g.under_odds, label: `U ${g.total}` },
              ].map((b, i) => {
                const selected = legs.some((l) => l.game_id === g.id && l.bet_type === b.type && l.team === b.team);
                return (
                  <button
                    key={i}
                    onClick={() => addLeg(g, b.type, b.team, b.odds)}
                    disabled={locked}
                    style={{
                      padding: "6px 10px", borderRadius: 6, fontSize: 12, cursor: locked ? "default" : "pointer",
                      background: selected ? "#00bfff33" : "#0d0d1a", border: selected ? "1px solid #00bfff" : "1px solid #333",
                      color: selected ? "#00bfff" : "#ccc",
                    }}
                  >
                    {b.label} <span style={{ color: "#ffd700" }}>{formatOdds(b.odds)}</span>
                  </button>
                );
              })}
            </div>
          </div>
        );
      })}
    </div>
  );
};

// ═══════════════════════════════════════════════════════════════════════════════
// LIVE SCORES
// ═══════════════════════════════════════════════════════════════════════════════
const LiveScoresPage = () => {
  const [games, setGames] = useState([]);
  const [loading, setLoading] = useState(true);
  const [poolBets, setPoolBets] = useState({});

  const fetchLive = useCallback(async () => {
    try {
      const [g, b] = await Promise.all([
        api("/api/games/live"),
        api("/api/games/live/pool-bets").catch(() => ({})),
      ]);
      setGames(g || []);
      setPoolBets(b || {});
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchLive();
    const iv = setInterval(fetchLive, 30000);
    return () => clearInterval(iv);
  }, [fetchLive]);

  if (loading) return <Spinner text="Loading live scores…" />;

  return (
    <div>
      <h2 style={{ color: "#fff", margin: "0 0 4px" }}>🔴 Live Scores</h2>
      <p style={{ color: "#666", fontSize: 12, margin: "0 0 16px" }}>Auto-refreshes every 30 seconds</p>
      {games.length === 0 && <p style={{ color: "#888" }}>No live games right now.</p>}
      {games.map((g) => (
        <div key={g.id} style={cardStyle}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
            <span style={{ color: g.status === "live" ? "#ff4444" : "#888", fontSize: 12, fontWeight: 600 }}>
              {g.status === "live" ? `🔴 ${g.quarter || ""} ${g.clock || ""}` : g.status}
            </span>
            <span style={{ color: "#666", fontSize: 11 }}>{g.network}</span>
          </div>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <TeamLogo abbr={g.away_team} size={32} />
              <div>
                <div style={{ color: "#fff", fontWeight: 600 }}>{g.away_team}</div>
                <div style={{ color: "#888", fontSize: 12 }}>{g.away_record}</div>
              </div>
            </div>
            <div style={{ textAlign: "center" }}>
              <div style={{ color: "#fff", fontSize: 24, fontWeight: 700 }}>
                {g.away_score ?? "-"} — {g.home_score ?? "-"}
              </div>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <div style={{ textAlign: "right" }}>
                <div style={{ color: "#fff", fontWeight: 600 }}>{g.home_team}</div>
                <div style={{ color: "#888", fontSize: 12 }}>{g.home_record}</div>
              </div>
              <TeamLogo abbr={g.home_team} size={32} />
            </div>
          </div>
          {/* Pool Bets on this game */}
          {poolBets[g.id] && poolBets[g.id].length > 0 && (
            <div style={{ marginTop: 10, padding: 8, background: "#0d0d1a", borderRadius: 6 }}>
              <div style={{ color: "#00bfff", fontSize: 11, fontWeight: 600, marginBottom: 4 }}>POOL BETS</div>
              {poolBets[g.id].map((bet, i) => (
                <div key={i} style={{ display: "flex", justifyContent: "space-between", color: "#aaa", fontSize: 12, padding: "2px 0" }}>
                  <span>{bet.username}: {bet.team} {bet.bet_type}</span>
                  <span>{formatMoney(bet.amount)}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  );
};

// ═══════════════════════════════════════════════════════════════════════════════
// SCHEDULE
// ═══════════════════════════════════════════════════════════════════════════════
const SchedulePage = () => {
  const [weeks, setWeeks] = useState([]);
  const [selectedWeek, setSelectedWeek] = useState(null);
  const [games, setGames] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState({});

  useEffect(() => {
    api("/api/games/schedule/weeks").then((d) => {
      setWeeks(d || []);
      if (d && d.length > 0) setSelectedWeek(d.find((w) => w.is_current)?.week || d[0].week);
    }).catch(() => {}).finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (selectedWeek == null) return;
    setLoading(true);
    api(`/api/games/schedule?week=${selectedWeek}`).then((d) => setGames(d || [])).catch(() => {}).finally(() => setLoading(false));
  }, [selectedWeek]);

  const toggleExpand = (id) => setExpanded((p) => ({ ...p, [id]: !p[id] }));

  return (
    <div>
      <h2 style={{ color: "#fff", margin: "0 0 16px" }}>📅 Schedule</h2>
      <div style={{ display: "flex", gap: 6, overflowX: "auto", marginBottom: 16, paddingBottom: 4 }}>
        {weeks.map((w) => (
          <button
            key={w.week}
            onClick={() => setSelectedWeek(w.week)}
            style={{
              padding: "6px 14px", borderRadius: 20, fontSize: 12, whiteSpace: "nowrap",
              background: selectedWeek === w.week ? "#00bfff" : "#1a1a3e",
              color: selectedWeek === w.week ? "#000" : "#aaa",
              border: "none", cursor: "pointer", fontWeight: selectedWeek === w.week ? 700 : 400,
            }}
          >
            Week {w.week}
          </button>
        ))}
      </div>
      {loading ? <Spinner text="Loading schedule…" /> : (
        games.map((g) => (
          <div key={g.id} style={cardStyle}>
            <div style={{ display: "flex", justifyContent: "space-between", color: "#888", fontSize: 12, marginBottom: 8 }}>
              <span>{new Date(g.kickoff).toLocaleDateString("en-US", { weekday: "long", month: "long", day: "numeric" })}</span>
              <span>{g.network}</span>
            </div>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <TeamLogo abbr={g.away_team} size={30} />
                <div>
                  <div style={{ color: "#fff", fontWeight: 600, fontSize: 14 }}>{UFL_TEAMS[g.away_team]?.name || g.away_team}</div>
                  <div style={{ color: "#888", fontSize: 11 }}>{g.away_record || ""}</div>
                </div>
              </div>
              <div style={{ textAlign: "center" }}>
                {g.status === "final" ? (
                  <div style={{ color: "#fff", fontSize: 20, fontWeight: 700 }}>{g.away_score} - {g.home_score}</div>
                ) : (
                  <div style={{ color: "#00bfff", fontSize: 13 }}>
                    {new Date(g.kickoff).toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit" })}
                  </div>
                )}
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <div style={{ textAlign: "right" }}>
                  <div style={{ color: "#fff", fontWeight: 600, fontSize: 14 }}>{UFL_TEAMS[g.home_team]?.name || g.home_team}</div>
                  <div style={{ color: "#888", fontSize: 11 }}>{g.home_record || ""}</div>
                </div>
                <TeamLogo abbr={g.home_team} size={30} />
              </div>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span style={{ color: "#666", fontSize: 11 }}>{g.venue}</span>
              <button onClick={() => toggleExpand(g.id)} style={{ background: "none", border: "none", color: "#00bfff", cursor: "pointer", fontSize: 12 }}>
                {expanded[g.id] ? "▲ Less" : "▼ Details"}
              </button>
            </div>
            {expanded[g.id] && (
              <div style={{ marginTop: 10, padding: 10, background: "#0d0d1a", borderRadius: 6, fontSize: 12, color: "#aaa" }}>
                {g.line_history && g.line_history.length > 0 && (
                  <div style={{ marginBottom: 10 }}>
                    <div style={{ color: "#00bfff", fontWeight: 600, marginBottom: 4 }}>Line History</div>
                    {g.line_history.map((lh, i) => (
                      <div key={i} style={{ display: "flex", justifyContent: "space-between", padding: "2px 0" }}>
                        <span>{new Date(lh.timestamp).toLocaleString()}</span>
                        <span>Spread: {lh.home_spread} | O/U: {lh.total}</span>
                      </div>
                    ))}
                  </div>
                )}
                {g.summary && (
                  <div>
                    <div style={{ color: "#ffd700", fontWeight: 600, marginBottom: 4 }}>Game Summary</div>
                    <div style={{ whiteSpace: "pre-wrap" }}>{g.summary}</div>
                  </div>
                )}
                {g.scoring_plays && g.scoring_plays.length > 0 && (
                  <div style={{ marginTop: 8 }}>
                    <div style={{ color: "#4ecdc4", fontWeight: 600, marginBottom: 4 }}>Scoring Plays</div>
                    {g.scoring_plays.map((sp, i) => (
                      <div key={i} style={{ padding: "3px 0", borderBottom: "1px solid #1a1a2e" }}>
                        {sp.quarter && <span style={{ color: "#888" }}>Q{sp.quarter} </span>}
                        <span>{sp.description}</span>
                        <span style={{ color: "#ffd700", marginLeft: 6 }}>{sp.away_score}-{sp.home_score}</span>
                      </div>
                    ))}
                  </div>
                )}
                {g.team_stats && (
                  <div style={{ marginTop: 8 }}>
                    <div style={{ color: "#ff69b4", fontWeight: 600, marginBottom: 4 }}>Team Stats</div>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr auto 1fr", gap: 4 }}>
                      {Object.entries(g.team_stats).map(([stat, vals]) => (
                        <React.Fragment key={stat}>
                          <span style={{ textAlign: "right" }}>{vals.away}</span>
                          <span style={{ textAlign: "center", color: "#666" }}>{stat}</span>
                          <span>{vals.home}</span>
                        </React.Fragment>
                      ))}
                    </div>
                  </div>
                )}
                {g.key_players && g.key_players.length > 0 && (
                  <div style={{ marginTop: 8 }}>
                    <div style={{ color: "#00bfff", fontWeight: 600, marginBottom: 4 }}>Key Players</div>
                    {g.key_players.map((p, i) => (
                      <div key={i} style={{ padding: "2px 0" }}>{p.name} ({p.team}) — {p.stats}</div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        ))
      )}
    </div>
  );
};

// ═══════════════════════════════════════════════════════════════════════════════
// WEEKLY RECAP
// ═══════════════════════════════════════════════════════════════════════════════
const WeeklyRecapPage = () => {
  const [recap, setRecap] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api("/api/pool/recap").then(setRecap).catch(() => {}).finally(() => setLoading(false));
  }, []);

  if (loading) return <Spinner text="Loading recap…" />;
  if (!recap) return <p style={{ color: "#888" }}>No recap available yet.</p>;

  return (
    <div>
      <h2 style={{ color: "#fff", margin: "0 0 16px" }}>📊 Weekly Recap — Week {recap.week}</h2>
      {/* Performance Rankings */}
      {recap.rankings && recap.rankings.length > 0 && (
        <div style={{ ...cardStyle, marginBottom: 16 }}>
          <h4 style={{ color: "#00bfff", margin: "0 0 10px" }}>Performance Rankings</h4>
          {recap.rankings.map((r, i) => (
            <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "6px 0", borderBottom: "1px solid #1a1a2e" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ color: i < 3 ? "#ffd700" : "#888", fontWeight: 700, width: 24 }}>#{i + 1}</span>
                <span style={{ color: "#fff" }}>{r.username}</span>
              </div>
              <span style={{ color: r.profit >= 0 ? "#6bff6b" : "#ff6b6b", fontWeight: 600 }}>{formatMoney(r.profit)}</span>
            </div>
          ))}
        </div>
      )}
      {/* Biggest Wins */}
      {recap.biggest_wins && recap.biggest_wins.length > 0 && (
        <div style={{ ...cardStyle, marginBottom: 16 }}>
          <h4 style={{ color: "#6bff6b", margin: "0 0 10px" }}>💰 Biggest Wins</h4>
          {recap.biggest_wins.map((b, i) => (
            <div key={i} style={{ padding: "6px 0", borderBottom: "1px solid #1a1a2e", color: "#ccc", fontSize: 13 }}>
              <span style={{ fontWeight: 600 }}>{b.username}</span> won {formatMoney(b.payout)} on {b.description}
            </div>
          ))}
        </div>
      )}
      {/* Biggest Losses */}
      {recap.biggest_losses && recap.biggest_losses.length > 0 && (
        <div style={cardStyle}>
          <h4 style={{ color: "#ff6b6b", margin: "0 0 10px" }}>📉 Biggest Losses</h4>
          {recap.biggest_losses.map((b, i) => (
            <div key={i} style={{ padding: "6px 0", borderBottom: "1px solid #1a1a2e", color: "#ccc", fontSize: 13 }}>
              <span style={{ fontWeight: 600 }}>{b.username}</span> lost {formatMoney(b.amount)} on {b.description}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

// ═══════════════════════════════════════════════════════════════════════════════
// ACTIVITY
// ═══════════════════════════════════════════════════════════════════════════════
const ActivityPage = () => {
  const [activity, setActivity] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api("/api/pool/activity").then((d) => setActivity(d || [])).catch(() => {}).finally(() => setLoading(false));
  }, []);

  if (loading) return <Spinner text="Loading activity…" />;

  return (
    <div>
      <h2 style={{ color: "#fff", margin: "0 0 4px" }}>📜 Pool Activity</h2>
      <p style={{ color: "#666", fontSize: 12, margin: "0 0 16px" }}>Picks are hidden until kickoff</p>
      {activity.length === 0 && <p style={{ color: "#888" }}>No activity yet.</p>}
      {activity.map((a, i) => {
        const hidden = a.hidden && !a.revealed;
        return (
          <div key={i} style={{ ...cardStyle, display: "flex", gap: 10 }}>
            <div style={{ width: 36, height: 36, borderRadius: "50%", background: "#1a1a3e", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 16, flexShrink: 0 }}>
              {a.type === "bet" ? "🎲" : a.type === "parlay" ? "🎯" : a.type === "win" ? "💰" : a.type === "loss" ? "📉" : "📌"}
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ color: "#fff", fontSize: 13 }}>
                <span style={{ fontWeight: 600 }}>{a.username}</span>{" "}
                {hidden ? (
                  <span style={{ color: "#888", fontStyle: "italic" }}>placed a hidden bet</span>
                ) : (
                  <span style={{ color: "#ccc" }}>{a.description}</span>
                )}
              </div>
              {/* Parlay legs */}
              {a.type === "parlay" && !hidden && a.legs && (
                <div style={{ marginTop: 4 }}>
                  {a.legs.map((leg, li) => (
                    <div key={li} style={{ fontSize: 12, color: leg.revealed ? (leg.result === "win" ? "#6bff6b" : leg.result === "loss" ? "#ff6b6b" : "#aaa") : "#888", padding: "1px 0" }}>
                      {leg.revealed ? `${leg.team} ${leg.bet_type} ${formatOdds(leg.odds)} — ${leg.result || "pending"}` : `Leg ${li + 1}: Hidden until kickoff`}
                    </div>
                  ))}
                </div>
              )}
              <div style={{ color: "#666", fontSize: 11, marginTop: 2 }}>{timeAgo(a.created_at)}</div>
            </div>
            {!hidden && a.amount && (
              <div style={{ color: a.type === "win" ? "#6bff6b" : a.type === "loss" ? "#ff6b6b" : "#ffd700", fontWeight: 600, fontSize: 13, flexShrink: 0 }}>
                {formatMoney(a.amount)}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};

// ═══════════════════════════════════════════════════════════════════════════════
// CHAT
// ═══════════════════════════════════════════════════════════════════════════════
const ChatPage = () => {
  const { user } = useAuth();
  const [messages, setMessages] = useState([]);
  const [text, setText] = useState("");
  const [loading, setLoading] = useState(true);
  const [sending, setSending] = useState(false);
  const bottomRef = useRef(null);

  const fetchMessages = useCallback(async () => {
    try {
      const d = await api("/api/chat");
      setMessages(d || []);
    } catch (err) { console.error(err); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => {
    fetchMessages();
    const iv = setInterval(fetchMessages, 10000);
    return () => clearInterval(iv);
  }, [fetchMessages]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const send = async () => {
    if (!text.trim()) return;
    setSending(true);
    try {
      await api("/api/chat", { method: "POST", body: JSON.stringify({ message: text.trim() }) });
      setText("");
      fetchMessages();
    } catch (err) { console.error(err); }
    finally { setSending(false); }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "calc(100vh - 120px)" }}>
      <h2 style={{ color: "#fff", margin: "0 0 12px", flexShrink: 0 }}>💬 Pool Chat</h2>
      <div style={{ flex: 1, overflowY: "auto", marginBottom: 12 }}>
        {loading ? <Spinner text="Loading messages…" /> : messages.length === 0 ? (
          <p style={{ color: "#888", textAlign: "center" }}>No messages yet. Start the conversation!</p>
        ) : (
          messages.map((m, i) => {
            const isSystem = m.is_system;
            const isMe = m.user_id === user?.id;
            return (
              <div
                key={m.id || i}
                style={{
                  marginBottom: 8, display: "flex", justifyContent: isSystem ? "center" : isMe ? "flex-end" : "flex-start",
                }}
              >
                {isSystem ? (
                  <div style={{ background: "#1a1a3e", color: "#ffd700", fontSize: 12, padding: "4px 12px", borderRadius: 12, fontStyle: "italic" }}>
                    ⚡ {m.message}
                  </div>
                ) : (
                  <div style={{ maxWidth: "75%", background: isMe ? "#00406b" : "#1a1a3e", borderRadius: 12, padding: "8px 12px" }}>
                    {!isMe && <div style={{ color: "#00bfff", fontSize: 11, fontWeight: 600, marginBottom: 2 }}>{m.username}</div>}
                    <div style={{ color: "#fff", fontSize: 14 }}>{m.message}</div>
                    <div style={{ color: "#666", fontSize: 10, marginTop: 2, textAlign: "right" }}>{timeAgo(m.created_at)}</div>
                  </div>
                )}
              </div>
            );
          })
        )}
        <div ref={bottomRef} />
      </div>
      <div style={{ display: "flex", gap: 8, flexShrink: 0 }}>
        <input
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && send()}
          placeholder="Type a message…"
          style={{ ...inputStyle, flex: 1 }}
        />
        <button onClick={send} disabled={sending || !text.trim()} style={{ ...btnPrimary, padding: "10px 16px" }}>
          {sending ? "…" : "Send"}
        </button>
      </div>
    </div>
  );
};

// ═══════════════════════════════════════════════════════════════════════════════
// STANDINGS
// ═══════════════════════════════════════════════════════════════════════════════
const StandingsPage = () => {
  const [standings, setStandings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [profileModal, setProfileModal] = useState(null);
  const [profileData, setProfileData] = useState(null);
  const [profileLoading, setProfileLoading] = useState(false);

  useEffect(() => {
    api("/api/pool/standings").then((d) => setStandings(d || [])).catch(() => {}).finally(() => setLoading(false));
  }, []);

  const openProfile = async (userId) => {
    setProfileModal(userId);
    setProfileLoading(true);
    try {
      const data = await api(`/api/users/${userId}/profile`);
      setProfileData(data);
    } catch (err) {
      console.error(err);
    } finally {
      setProfileLoading(false);
    }
  };

  const exportCSV = () => {
    downloadCSV(
      standings.map((s, i) => ({
        Rank: i + 1, Username: s.username, Balance: s.balance, AtRisk: s.at_risk || 0,
        Wins: s.wins, Losses: s.losses, WinRate: s.win_rate, ROI: s.roi,
      })),
      "ufl_pool_standings.csv"
    );
  };

  if (loading) return <Spinner text="Loading standings…" />;

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <h2 style={{ color: "#fff", margin: 0 }}>🏆 Standings</h2>
        <button onClick={exportCSV} style={{ ...btnSecondary, padding: "6px 12px", fontSize: 12 }}>📥 CSV</button>
      </div>
      {standings.map((s, i) => (
        <div
          key={s.user_id || i}
          onClick={() => openProfile(s.user_id)}
          style={{ ...cardStyle, cursor: "pointer", display: "flex", alignItems: "center", gap: 12, transition: "background 0.15s" }}
          onMouseOver={(e) => (e.currentTarget.style.background = "#1a2a4e")}
          onMouseOut={(e) => (e.currentTarget.style.background = "#16213e")}
        >
          <span style={{ color: i < 3 ? "#ffd700" : "#888", fontWeight: 700, fontSize: 18, width: 32, textAlign: "center" }}>
            {i === 0 ? "🥇" : i === 1 ? "🥈" : i === 2 ? "🥉" : `#${i + 1}`}
          </span>
          <div style={{ flex: 1 }}>
            <div style={{ color: "#fff", fontWeight: 600, fontSize: 14 }}>{s.username}</div>
            <div style={{ color: "#888", fontSize: 12 }}>
              {s.wins}W-{s.losses}L | WR: {s.win_rate ? `${(s.win_rate * 100).toFixed(1)}%` : "—"}
            </div>
          </div>
          <div style={{ textAlign: "right" }}>
            <div style={{ color: "#00bfff", fontWeight: 700, fontSize: 15 }}>{formatMoney(s.balance)}</div>
            {s.at_risk > 0 && <div style={{ color: "#ffd700", fontSize: 11 }}>At risk: {formatMoney(s.at_risk)}</div>}
          </div>
        </div>
      ))}

      {/* Profile Modal */}
      <Modal open={!!profileModal} onClose={() => { setProfileModal(null); setProfileData(null); }} title="Player Profile" width={520}>
        {profileLoading ? <Spinner text="Loading profile…" /> : profileData ? (
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
              <div style={{ width: 50, height: 50, borderRadius: "50%", background: "#1a1a3e", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 22 }}>
                {profileData.username?.[0]?.toUpperCase() || "?"}
              </div>
              <div>
                <div style={{ color: "#fff", fontWeight: 700, fontSize: 18 }}>{profileData.username}</div>
                <div style={{ color: "#00bfff", fontSize: 14 }}>Balance: {formatMoney(profileData.balance)}</div>
              </div>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 16 }}>
              {[
                { label: "Win Rate", val: profileData.win_rate ? `${(profileData.win_rate * 100).toFixed(1)}%` : "—" },
                { label: "ROI", val: profileData.roi ? `${(profileData.roi * 100).toFixed(1)}%` : "—" },
                { label: "P&L", val: formatMoney(profileData.pnl), color: (profileData.pnl || 0) >= 0 ? "#6bff6b" : "#ff6b6b" },
                { label: "Streak", val: profileData.streak || "—" },
                { label: "Record", val: `${profileData.wins || 0}W-${profileData.losses || 0}L` },
                { label: "Total Bets", val: profileData.total_bets || 0 },
              ].map((item, idx) => (
                <div key={idx} style={{ background: "#0d0d1a", padding: 10, borderRadius: 8, textAlign: "center" }}>
                  <div style={{ color: "#888", fontSize: 11 }}>{item.label}</div>
                  <div style={{ color: item.color || "#fff", fontWeight: 700, fontSize: 15 }}>{item.val}</div>
                </div>
              ))}
            </div>
            {/* Bet type breakdown */}
            {profileData.bet_breakdown && (
              <div style={{ marginBottom: 16 }}>
                <h4 style={{ color: "#aaa", margin: "0 0 8px", fontSize: 13 }}>Bet Type Breakdown</h4>
                {Object.entries(profileData.bet_breakdown).map(([type, data]) => (
                  <div key={type} style={{ display: "flex", justifyContent: "space-between", padding: "4px 0", borderBottom: "1px solid #1a1a2e", fontSize: 13, color: "#ccc" }}>
                    <span style={{ textTransform: "capitalize" }}>{type}</span>
                    <span>{data.wins}W-{data.losses}L ({data.count} total)</span>
                  </div>
                ))}
              </div>
            )}
            {/* Recent graded bets */}
            {profileData.recent_bets && profileData.recent_bets.length > 0 && (
              <div>
                <h4 style={{ color: "#aaa", margin: "0 0 8px", fontSize: 13 }}>Recent Graded Bets</h4>
                {profileData.recent_bets.map((b, i) => (
                  <div key={i} style={{ display: "flex", justifyContent: "space-between", padding: "6px 0", borderBottom: "1px solid #1a1a2e", fontSize: 13 }}>
                    <div>
                      <span style={{ color: "#fff" }}>{b.team} {b.bet_type}</span>
                      <span style={{ color: "#888", marginLeft: 6 }}>{formatOdds(b.odds)}</span>
                    </div>
                    <span style={{ color: b.result === "win" ? "#6bff6b" : b.result === "loss" ? "#ff6b6b" : "#ffd700", fontWeight: 600 }}>
                      {b.result === "win" ? `+${formatMoney(b.payout)}` : b.result === "loss" ? `-${formatMoney(b.amount)}` : "Pending"}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        ) : (
          <p style={{ color: "#888" }}>Could not load profile data.</p>
        )}
      </Modal>
    </div>
  );
};

// ═══════════════════════════════════════════════════════════════════════════════
// NEWS
// ═══════════════════════════════════════════════════════════════════════════════
const NewsPage = () => {
  const [articles, setArticles] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api("/api/news").then((d) => setArticles(d || [])).catch(() => {}).finally(() => setLoading(false));
  }, []);

  if (loading) return <Spinner text="Loading news…" />;

  return (
    <div>
      <h2 style={{ color: "#fff", margin: "0 0 16px" }}>📰 UFL News</h2>
      {articles.length === 0 && <p style={{ color: "#888" }}>No news articles available.</p>}
      {articles.map((a, i) => (
        <a
          key={i}
          href={a.url}
          target="_blank"
          rel="noopener noreferrer"
          style={{ textDecoration: "none", display: "block", marginBottom: 12 }}
        >
          <div style={{ ...cardStyle, display: "flex", gap: 12, cursor: "pointer" }}
            onMouseOver={(e) => (e.currentTarget.style.background = "#1a2a4e")}
            onMouseOut={(e) => (e.currentTarget.style.background = "#16213e")}
          >
            {a.image && (
              <img
                src={a.image}
                alt=""
                style={{ width: 80, height: 60, objectFit: "cover", borderRadius: 6, flexShrink: 0 }}
                onError={(e) => (e.target.style.display = "none")}
              />
            )}
            <div>
              <div style={{ color: "#fff", fontWeight: 600, fontSize: 14, marginBottom: 4 }}>{a.title}</div>
              <div style={{ color: "#888", fontSize: 12, lineHeight: 1.4 }}>{a.description}</div>
              <div style={{ color: "#666", fontSize: 11, marginTop: 4 }}>{a.source} • {timeAgo(a.published_at)}</div>
            </div>
          </div>
        </a>
      ))}
    </div>
  );
};

// ═══════════════════════════════════════════════════════════════════════════════
// PROFILE
// ═══════════════════════════════════════════════════════════════════════════════
const ProfilePage = () => {
  const { user } = useAuth();
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api("/api/users/me/profile").then(setProfile).catch(() => {}).finally(() => setLoading(false));
  }, []);

  if (loading) return <Spinner text="Loading profile…" />;
  const p = profile || {};

  return (
    <div>
      <h2 style={{ color: "#fff", margin: "0 0 16px" }}>👤 My Profile</h2>
      <div style={{ ...cardStyle, display: "flex", alignItems: "center", gap: 14, marginBottom: 20 }}>
        <div style={{ width: 60, height: 60, borderRadius: "50%", background: "linear-gradient(135deg, #00bfff, #0080ff)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 26, color: "#fff", fontWeight: 700 }}>
          {user?.username?.[0]?.toUpperCase() || "?"}
        </div>
        <div>
          <div style={{ color: "#fff", fontWeight: 700, fontSize: 20 }}>{user?.username}</div>
          <div style={{ color: "#888", fontSize: 13 }}>{user?.email}</div>
          <div style={{ color: "#00bfff", fontSize: 15, fontWeight: 600, marginTop: 2 }}>{formatMoney(p.balance || user?.balance)}</div>
        </div>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10, marginBottom: 20 }}>
        {[
          { label: "Win Rate", val: p.win_rate ? `${(p.win_rate * 100).toFixed(1)}%` : "—" },
          { label: "ROI", val: p.roi ? `${(p.roi * 100).toFixed(1)}%` : "—" },
          { label: "P&L", val: formatMoney(p.pnl), color: (p.pnl || 0) >= 0 ? "#6bff6b" : "#ff6b6b" },
          { label: "Record", val: `${p.wins || 0}W-${p.losses || 0}L` },
          { label: "Streak", val: p.streak || "—" },
          { label: "Total Bets", val: p.total_bets || 0 },
        ].map((item, idx) => (
          <div key={idx} style={{ background: "#0d0d1a", padding: 12, borderRadius: 10, textAlign: "center" }}>
            <div style={{ color: "#888", fontSize: 11, marginBottom: 2 }}>{item.label}</div>
            <div style={{ color: item.color || "#fff", fontWeight: 700, fontSize: 16 }}>{item.val}</div>
          </div>
        ))}
      </div>
      {/* Bet Type Breakdown */}
      {p.bet_breakdown && (
        <div style={cardStyle}>
          <h4 style={{ color: "#aaa", margin: "0 0 10px", fontSize: 13, textTransform: "uppercase" }}>Bet Type Breakdown</h4>
          {Object.entries(p.bet_breakdown).map(([type, data]) => {
            const total = (data.wins || 0) + (data.losses || 0);
            const wr = total > 0 ? ((data.wins / total) * 100).toFixed(1) : 0;
            return (
              <div key={type} style={{ marginBottom: 8 }}>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13, color: "#ccc", marginBottom: 2 }}>
                  <span style={{ textTransform: "capitalize" }}>{type}</span>
                  <span>{data.wins}W-{data.losses}L ({wr}%)</span>
                </div>
                <div style={{ height: 6, background: "#0d0d1a", borderRadius: 3, overflow: "hidden" }}>
                  <div style={{ width: `${wr}%`, height: "100%", background: "linear-gradient(90deg, #00bfff, #0080ff)", borderRadius: 3 }} />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

// ═══════════════════════════════════════════════════════════════════════════════
// MY BETS
// ═══════════════════════════════════════════════════════════════════════════════
const MyBetsPage = () => {
  const [bets, setBets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState("pending");

  useEffect(() => {
    api("/api/bets/mine").then((d) => setBets(d || [])).catch(() => {}).finally(() => setLoading(false));
  }, []);

  const filtered = useMemo(() => {
    if (tab === "pending") return bets.filter((b) => b.status === "pending");
    if (tab === "graded") return bets.filter((b) => b.status === "win" || b.status === "loss" || b.status === "push");
    return bets;
  }, [bets, tab]);

  const exportCSV = () => {
    downloadCSV(
      filtered.map((b) => ({
        Date: b.created_at, Type: b.bet_type, Team: b.team, Odds: b.odds,
        Amount: b.amount, Payout: b.payout || "", Status: b.status,
      })),
      "my_bets.csv"
    );
  };

  if (loading) return <Spinner text="Loading bets…" />;

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <h2 style={{ color: "#fff", margin: 0 }}>🎰 My Bets</h2>
        <button onClick={exportCSV} style={{ ...btnSecondary, padding: "6px 12px", fontSize: 12 }}>📥 CSV</button>
      </div>
      <div style={{ display: "flex", gap: 6, marginBottom: 16 }}>
        {["pending", "graded", "all"].map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            style={{
              padding: "6px 16px", borderRadius: 20, fontSize: 13, border: "none", cursor: "pointer",
              background: tab === t ? "#00bfff" : "#1a1a3e", color: tab === t ? "#000" : "#aaa",
              fontWeight: tab === t ? 700 : 400, textTransform: "capitalize",
            }}
          >
            {t}
          </button>
        ))}
      </div>
      {filtered.length === 0 && <p style={{ color: "#888" }}>No bets found.</p>}
      {filtered.map((b, i) => (
        <div key={b.id || i} style={cardStyle}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ color: "#fff", fontWeight: 600, fontSize: 14 }}>
                {b.is_parlay ? "🎯 Parlay" : `${b.team} ${b.bet_type}`}
              </div>
              <div style={{ color: "#888", fontSize: 12, marginTop: 2 }}>
                {b.game_description || ""} • {formatOdds(b.odds)}
              </div>
              {b.is_parlay && b.legs && (
                <div style={{ marginTop: 6 }}>
                  {b.legs.map((leg, li) => (
                    <div key={li} style={{ fontSize: 12, color: leg.status === "win" ? "#6bff6b" : leg.status === "loss" ? "#ff6b6b" : "#aaa", padding: "1px 0" }}>
                      {leg.team} {leg.bet_type} {formatOdds(leg.odds)} — {leg.status || "pending"}
                    </div>
                  ))}
                </div>
              )}
              <div style={{ color: "#666", fontSize: 11, marginTop: 4 }}>{new Date(b.created_at).toLocaleString()}</div>
            </div>
            <div style={{ textAlign: "right" }}>
              <div style={{ color: "#fff", fontWeight: 600 }}>{formatMoney(b.amount)}</div>
              <div style={{ fontSize: 12, marginTop: 2, color: b.status === "win" ? "#6bff6b" : b.status === "loss" ? "#ff6b6b" : b.status === "push" ? "#ffd700" : "#00bfff" }}>
                {b.status === "win" && `Won ${formatMoney(b.payout)}`}
                {b.status === "loss" && "Lost"}
                {b.status === "push" && "Push"}
                {b.status === "pending" && `To win ${formatMoney(calcPayout(b.amount, b.odds))}`}
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
};

// ═══════════════════════════════════════════════════════════════════════════════
// ADMIN
// ═══════════════════════════════════════════════════════════════════════════════
const AdminPage = () => {
  const [members, setMembers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [adjModal, setAdjModal] = useState(null);
  const [adjAmount, setAdjAmount] = useState("");
  const [adjReason, setAdjReason] = useState("");
  const [adjLoading, setAdjLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");

  const fetchMembers = useCallback(async () => {
    try {
      const d = await api("/api/admin/members");
      setMembers(d || []);
    } catch (err) { console.error(err); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchMembers(); }, [fetchMembers]);

  const updateMember = async (userId, action) => {
    try {
      await api(`/api/admin/members/${userId}/${action}`, { method: "POST" });
      fetchMembers();
    } catch (err) {
      alert(err.message);
    }
  };

  const adjustBalance = async () => {
    const amt = parseFloat(adjAmount);
    if (isNaN(amt)) return setError("Invalid amount");
    if (!adjReason.trim()) return setError("Reason is required");
    setAdjLoading(true);
    setError("");
    try {
      await api(`/api/admin/members/${adjModal.id}/balance`, {
        method: "POST",
        body: JSON.stringify({ amount: amt, reason: adjReason.trim() }),
      });
      setAdjModal(null);
      setAdjAmount("");
      setAdjReason("");
      fetchMembers();
    } catch (err) {
      setError(err.message);
    } finally {
      setAdjLoading(false);
    }
  };

  const refreshScores = async () => {
    setRefreshing(true);
    try {
      await api("/api/admin/refresh-scores", { method: "POST" });
      alert("Scores refreshed!");
    } catch (err) {
      alert(err.message);
    } finally {
      setRefreshing(false);
    }
  };

  const refreshOdds = async () => {
    setRefreshing(true);
    try {
      await api("/api/admin/refresh-odds", { method: "POST" });
      alert("Odds refreshed!");
    } catch (err) {
      alert(err.message);
    } finally {
      setRefreshing(false);
    }
  };

  if (loading) return <Spinner text="Loading admin…" />;

  return (
    <div>
      <h2 style={{ color: "#fff", margin: "0 0 16px" }}>⚙️ Admin Panel</h2>
      {/* Manual Refresh */}
      <div style={{ ...cardStyle, display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 20 }}>
        <button onClick={refreshScores} disabled={refreshing} style={btnPrimary}>
          {refreshing ? "Refreshing…" : "🔄 Refresh Scores"}
        </button>
        <button onClick={refreshOdds} disabled={refreshing} style={btnPrimary}>
          {refreshing ? "Refreshing…" : "📊 Refresh Odds"}
        </button>
      </div>
      {/* Members */}
      <h3 style={{ color: "#aaa", fontSize: 14, margin: "0 0 12px" }}>Members ({members.length})</h3>
      {members.map((m) => (
        <div key={m.id} style={{ ...cardStyle, display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{ flex: 1 }}>
            <div style={{ color: "#fff", fontWeight: 600 }}>{m.username}</div>
            <div style={{ color: "#888", fontSize: 12 }}>{m.email}</div>
            <div style={{ color: "#00bfff", fontSize: 12 }}>{formatMoney(m.balance)} • {m.status || "active"}</div>
          </div>
          <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
            {m.status === "pending" && (
              <>
                <button onClick={() => updateMember(m.id, "approve")} style={{ ...btnPrimary, padding: "4px 10px", fontSize: 11 }}>Approve</button>
                <button onClick={() => updateMember(m.id, "deny")} style={{ ...btnDanger, padding: "4px 10px", fontSize: 11 }}>Deny</button>
              </>
            )}
            {m.status === "active" && (
              <button onClick={() => updateMember(m.id, "deactivate")} style={{ ...btnSecondary, padding: "4px 10px", fontSize: 11 }}>Deactivate</button>
            )}
            {m.status === "deactivated" && (
              <button onClick={() => updateMember(m.id, "approve")} style={{ ...btnPrimary, padding: "4px 10px", fontSize: 11 }}>Reactivate</button>
            )}
            <button onClick={() => { setAdjModal(m); setAdjAmount(""); setAdjReason(""); setError(""); }} style={{ ...btnSecondary, padding: "4px 10px", fontSize: 11 }}>💰 Adjust</button>
          </div>
        </div>
      ))}

      {/* Balance Adjustment Modal */}
      <Modal open={!!adjModal} onClose={() => setAdjModal(null)} title={`Adjust Balance — ${adjModal?.username}`}>
        <div>
          <div style={{ color: "#888", fontSize: 13, marginBottom: 12 }}>Current balance: {formatMoney(adjModal?.balance)}</div>
          <label style={{ color: "#aaa", fontSize: 12, display: "block", marginBottom: 4 }}>Amount (positive to add, negative to subtract)</label>
          <input type="number" value={adjAmount} onChange={(e) => setAdjAmount(e.target.value)} style={{ ...inputStyle, marginBottom: 12 }} placeholder="e.g. 100 or -50" />
          <label style={{ color: "#aaa", fontSize: 12, display: "block", marginBottom: 4 }}>Reason (logged to chat)</label>
          <input value={adjReason} onChange={(e) => setAdjReason(e.target.value)} style={{ ...inputStyle, marginBottom: 12 }} placeholder="Weekly bonus, penalty, etc." />
          {error && <div style={{ color: "#ff6b6b", fontSize: 13, marginBottom: 12 }}>{error}</div>}
          <div style={{ display: "flex", gap: 8 }}>
            <button onClick={() => setAdjModal(null)} style={btnSecondary}>Cancel</button>
            <button onClick={adjustBalance} disabled={adjLoading} style={{ ...btnPrimary, flex: 1 }}>
              {adjLoading ? "Adjusting…" : "Confirm Adjustment"}
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
};

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN APP
// ═══════════════════════════════════════════════════════════════════════════════
const MainApp = () => {
  const { user } = useAuth();
  const [page, setPage] = useState("board");
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const renderPage = () => {
    switch (page) {
      case "board": return <BoardPage />;
      case "parlay": return <ParlayPage />;
      case "live": return <LiveScoresPage />;
      case "schedule": return <SchedulePage />;
      case "recap": return <WeeklyRecapPage />;
      case "activity": return <ActivityPage />;
      case "chat": return <ChatPage />;
      case "standings": return <StandingsPage />;
      case "profile": return <ProfilePage />;
      case "mybets": return <MyBetsPage />;
      case "news": return <NewsPage />;
      case "admin": return user?.role === "admin" ? <AdminPage /> : <p style={{ color: "#888" }}>Access denied.</p>;
      default: return <BoardPage />;
    }
  };

  return (
    <div style={{ minHeight: "100vh", background: "#0a0a1a" }}>
      <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} current={page} onNav={setPage} user={user} />
      {/* Top Bar */}
      <div style={{
        position: "sticky", top: 0, zIndex: 100, background: "#0d0d1a", borderBottom: "1px solid #1a1a2e",
        display: "flex", alignItems: "center", padding: "10px 16px", gap: 12,
      }}>
        <button onClick={() => setSidebarOpen(true)} style={{ background: "none", border: "none", color: "#fff", fontSize: 22, cursor: "pointer", padding: 0 }}>
          ☰
        </button>
        <span style={{ color: "#00bfff", fontWeight: 700, fontSize: 16 }}>🏈 UFL Pool</span>
        <div style={{ marginLeft: "auto", color: "#00bfff", fontSize: 13, fontWeight: 600 }}>{formatMoney(user?.balance)}</div>
      </div>
      {/* Page Content */}
      <div style={{ padding: "16px 16px 80px", maxWidth: 640, margin: "0 auto" }}>
        <ErrorBoundary>{renderPage()}</ErrorBoundary>
      </div>
    </div>
  );
};

// ═══════════════════════════════════════════════════════════════════════════════
// APP ROOT
// ═══════════════════════════════════════════════════════════════════════════════
const App = () => {
  const [authPage, setAuthPage] = useState("login");
  const [user, setUser] = useState(() => {
    try { return JSON.parse(localStorage.getItem("user")); } catch { return null; }
  });
  const [token, setToken] = useState(() => localStorage.getItem("token"));

  const refreshUser = useCallback(async () => {
    try {
      const data = await api("/api/users/me");
      setUser(data);
      localStorage.setItem("user", JSON.stringify(data));
    } catch (err) {
      console.error("Failed to refresh user:", err);
    }
  }, []);

  const handleLogin = (u, t) => {
    setUser(u);
    setToken(t);
  };

  const authValue = useMemo(() => ({ user, token, refreshUser }), [user, token, refreshUser]);

  if (!token || !user) {
    switch (authPage) {
      case "register": return <RegisterPage onSwitch={setAuthPage} />;
      case "forgot": return <ForgotPasswordPage onSwitch={setAuthPage} />;
      default: return <LoginPage onSwitch={setAuthPage} onLogin={handleLogin} />;
    }
  }

  return (
    <ErrorBoundary>
      <AuthContext.Provider value={authValue}>
        <MainApp />
      </AuthContext.Provider>
    </ErrorBoundary>
  );
};

export default App;
