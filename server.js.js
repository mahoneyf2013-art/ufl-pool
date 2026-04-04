const express=require("express"),cors=require("cors"),{Pool}=require("pg"),bcrypt=require("bcryptjs"),jwt=require("jsonwebtoken"),cron=require("node-cron");
const app=express();app.use(cors());app.use(express.json());
const JWT_SECRET=process.env.JWT_SECRET||"CHANGE_ME",ODDS_API_KEY=process.env.ODDS_API_KEY,SPORT="americanfootball_ufl",PORT=process.env.PORT||3001,APP_URL=process.env.APP_URL||"http://localhost:5173";
let resend=null;try{const{Resend}=require("resend");if(process.env.RESEND_API_KEY){resend=new Resend(process.env.RESEND_API_KEY);}}catch(e){}
function uuid(){return"xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g,c=>{const r=Math.random()*16|0;return(c==="x"?r:(r&0x3|0x8)).toString(16)});}
const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.DATABASE_URL?.includes("railway")?{rejectUnauthorized:false}:false});
async function q(t,p){return(await pool.query(t,p)).rows;}
async function q1(t,p){return(await pool.query(t,p)).rows[0]||null;}

async function initDB(){await pool.query(`
  CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,username TEXT UNIQUE NOT NULL,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,display_name TEXT,created_at TIMESTAMPTZ DEFAULT NOW());
  CREATE TABLE IF NOT EXISTS pools(id TEXT PRIMARY KEY,name TEXT NOT NULL,join_code TEXT UNIQUE NOT NULL,commissioner_id TEXT NOT NULL,starting_balance INTEGER DEFAULT 1000,require_approval INTEGER DEFAULT 1,created_at TIMESTAMPTZ DEFAULT NOW());
  CREATE TABLE IF NOT EXISTS pool_members(id TEXT PRIMARY KEY,pool_id TEXT NOT NULL,user_id TEXT NOT NULL,role TEXT DEFAULT 'member',status TEXT DEFAULT 'pending',balance INTEGER DEFAULT 1000,joined_at TIMESTAMPTZ DEFAULT NOW(),UNIQUE(pool_id,user_id));
  CREATE TABLE IF NOT EXISTS games(id TEXT PRIMARY KEY,week INTEGER,commence_time TEXT,home_team TEXT,away_team TEXT,spread_home REAL,spread_away REAL,total REAL,moneyline_home INTEGER,moneyline_away INTEGER,home_score INTEGER,away_score INTEGER,status TEXT DEFAULT 'upcoming',last_updated TIMESTAMPTZ DEFAULT NOW());
  CREATE TABLE IF NOT EXISTS bets(id TEXT PRIMARY KEY,member_id TEXT NOT NULL,pool_id TEXT NOT NULL,game_id TEXT NOT NULL,bet_type TEXT,pick TEXT,line REAL,odds INTEGER,wager INTEGER,result TEXT DEFAULT 'pending',payout INTEGER DEFAULT 0,parlay_group TEXT,created_at TIMESTAMPTZ DEFAULT NOW());
  CREATE TABLE IF NOT EXISTS password_resets(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,token TEXT UNIQUE NOT NULL,expires_at TIMESTAMPTZ NOT NULL,used INTEGER DEFAULT 0,created_at TIMESTAMPTZ DEFAULT NOW());
  CREATE TABLE IF NOT EXISTS messages(id TEXT PRIMARY KEY,pool_id TEXT NOT NULL,user_id TEXT NOT NULL,content TEXT NOT NULL,created_at TIMESTAMPTZ DEFAULT NOW());
  CREATE TABLE IF NOT EXISTS line_history(id TEXT PRIMARY KEY,game_id TEXT NOT NULL,spread_home REAL,spread_away REAL,total REAL,moneyline_home INTEGER,moneyline_away INTEGER,recorded_at TIMESTAMPTZ DEFAULT NOW());
`);console.log("DB ready");}

// AUTH
function auth(rq,rs,nx){const h=rq.headers.authorization;if(!h)return rs.status(401).json({error:"No token"});try{rq.user=jwt.verify(h.split(" ")[1],JWT_SECRET);nx();}catch{rs.status(401).json({error:"Invalid token"});}}
async function requireAdmin(rq,rs){const a=await q1("SELECT * FROM pool_members WHERE pool_id=$1 AND user_id=$2 AND role='admin' AND status='active'",[rq.params.poolId,rq.user.id]);if(!a){rs.status(403).json({error:"Admin required"});return null;}return a;}

app.post("/api/auth/register",async(rq,rs)=>{try{const{username,email,password,displayName}=rq.body;if(!username||!email||!password)return rs.status(400).json({error:"All fields required"});if(password.length<6)return rs.status(400).json({error:"Password min 6"});const ex=await q1("SELECT id FROM users WHERE username=$1 OR email=$2",[username.toLowerCase(),email.toLowerCase()]);if(ex)return rs.status(409).json({error:"Taken"});const id=uuid(),hash=bcrypt.hashSync(password,10);await pool.query("INSERT INTO users(id,username,email,password_hash,display_name)VALUES($1,$2,$3,$4,$5)",[id,username.toLowerCase(),email.toLowerCase(),hash,displayName||username]);const token=jwt.sign({id,username:username.toLowerCase()},JWT_SECRET,{expiresIn:"30d"});rs.json({token,user:{id,username:username.toLowerCase(),displayName:displayName||username}});}catch(e){console.error(e);rs.status(500).json({error:"Server error"});}});
app.post("/api/auth/login",async(rq,rs)=>{try{const{username,password}=rq.body;if(!username||!password)return rs.status(400).json({error:"Required"});const user=await q1("SELECT * FROM users WHERE username=$1 OR email=$2",[username.toLowerCase(),username.toLowerCase()]);if(!user||!bcrypt.compareSync(password,user.password_hash))return rs.status(401).json({error:"Invalid credentials"});const token=jwt.sign({id:user.id,username:user.username},JWT_SECRET,{expiresIn:"30d"});rs.json({token,user:{id:user.id,username:user.username,displayName:user.display_name}});}catch(e){console.error(e);rs.status(500).json({error:"Server error"});}});
app.get("/api/auth/me",auth,async(rq,rs)=>{try{const u=await q1("SELECT id,username,display_name,email FROM users WHERE id=$1",[rq.user.id]);if(!u)return rs.status(404).json({error:"Not found"});rs.json(u);}catch(e){rs.status(500).json({error:"Server error"});}});

// PASSWORD RESET
app.post("/api/auth/forgot-password",async(rq,rs)=>{try{const{email}=rq.body;if(!email)return rs.status(400).json({error:"Email required"});const user=await q1("SELECT * FROM users WHERE email=$1",[email.toLowerCase()]);if(!user)return rs.json({success:true,message:"If that email exists, a reset link has been sent."});const token=Array.from({length:32},()=>Math.random().toString(36).charAt(2)).join(""),id=uuid();await pool.query("UPDATE password_resets SET used=1 WHERE user_id=$1 AND used=0",[user.id]);await pool.query("INSERT INTO password_resets(id,user_id,token,expires_at)VALUES($1,$2,$3,$4)",[id,user.id,token,new Date(Date.now()+3600000).toISOString()]);const link=`${APP_URL}?reset=${token}`;if(resend){try{await resend.emails.send({from:"UFL Pool <noreply@resend.dev>",to:email.toLowerCase(),subject:"Reset Your UFL Pool Password",html:`<div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:40px 20px;"><h1 style="color:#3b82f6;">UFL POOL</h1><p>Hey ${user.display_name}, click below to reset:</p><div style="text-align:center;margin:30px 0;"><a href="${link}" style="background:#3b82f6;color:white;padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:700;">Reset Password</a></div><p style="color:#6b7280;font-size:13px;">Expires in 1 hour.</p></div>`});}catch(e){console.error(e);}}else{console.log("Reset link: "+link);}rs.json({success:true,message:"If that email exists, a reset link has been sent."});}catch(e){console.error(e);rs.status(500).json({error:"Server error"});}});
app.get("/api/auth/verify-reset/:token",async(rq,rs)=>{try{const r=await q1("SELECT * FROM password_resets WHERE token=$1 AND used=0 AND expires_at>NOW()",[rq.params.token]);if(!r)return rs.status(400).json({error:"Invalid"});rs.json({valid:true});}catch(e){rs.status(500).json({error:"Server error"});}});
app.post("/api/auth/reset-password",async(rq,rs)=>{try{const{token,newPassword}=rq.body;if(!token||!newPassword||newPassword.length<6)return rs.status(400).json({error:"Invalid"});const r=await q1("SELECT * FROM password_resets WHERE token=$1 AND used=0 AND expires_at>NOW()",[token]);if(!r)return rs.status(400).json({error:"Expired"});await pool.query("UPDATE users SET password_hash=$1 WHERE id=$2",[bcrypt.hashSync(newPassword,10),r.user_id]);await pool.query("UPDATE password_resets SET used=1 WHERE id=$1",[r.id]);const user=await q1("SELECT * FROM users WHERE id=$1",[r.user_id]);const t=jwt.sign({id:user.id,username:user.username},JWT_SECRET,{expiresIn:"30d"});rs.json({success:true,token:t,user:{id:user.id,username:user.username,displayName:user.display_name}});}catch(e){console.error(e);rs.status(500).json({error:"Server error"});}});

// POOLS
app.get("/api/my-pools",auth,async(rq,rs)=>{try{rs.json(await q(`SELECT p.*,pm.role,pm.status,pm.balance,(SELECT COUNT(*)FROM pool_members WHERE pool_id=p.id AND status='active')as member_count FROM pools p JOIN pool_members pm ON pm.pool_id=p.id WHERE pm.user_id=$1 ORDER BY p.created_at DESC`,[rq.user.id]));}catch(e){console.error(e);rs.status(500).json({error:"Server error"});}});
app.post("/api/pools",auth,async(rq,rs)=>{try{const{name,startingBalance,requireApproval}=rq.body;if(!name)return rs.status(400).json({error:"Name required"});const id=uuid(),jc=Math.random().toString(36).substring(2,8).toUpperCase(),bal=startingBalance||1000;await pool.query("INSERT INTO pools(id,name,join_code,commissioner_id,starting_balance,require_approval)VALUES($1,$2,$3,$4,$5,$6)",[id,name,jc,rq.user.id,bal,requireApproval!==false?1:0]);const mid=uuid();await pool.query("INSERT INTO pool_members(id,pool_id,user_id,role,status,balance)VALUES($1,$2,$3,$4,$5,$6)",[mid,id,rq.user.id,"admin","active",bal]);rs.json({id,joinCode:jc,name});}catch(e){console.error(e);rs.status(500).json({error:"Server error"});}});
app.post("/api/pools/:code/join",auth,async(rq,rs)=>{try{const p=await q1("SELECT * FROM pools WHERE join_code=$1",[rq.params.code.toUpperCase()]);if(!p)return rs.status(404).json({error:"Not found"});const ex=await q1("SELECT * FROM pool_members WHERE pool_id=$1 AND user_id=$2",[p.id,rq.user.id]);if(ex){if(ex.status==="deactivated")return rs.status(403).json({error:"Removed"});return rs.status(409).json({error:"Already member"});}const id=uuid(),st=p.require_approval?"pending":"active";await pool.query("INSERT INTO pool_members(id,pool_id,user_id,role,status,balance)VALUES($1,$2,$3,$4,$5,$6)",[id,p.id,rq.user.id,"member",st,p.starting_balance]);rs.json({status:st,poolId:p.id,poolName:p.name});}catch(e){console.error(e);rs.status(500).json({error:"Server error"});}});

// ADMIN
app.get("/api/pools/:poolId/members",auth,async(rq,rs)=>{try{if(!(await requireAdmin(rq,rs)))return;rs.json(await q(`SELECT pm.*,u.username,u.display_name FROM pool_members pm JOIN users u ON pm.user_id=u.id WHERE pm.pool_id=$1 ORDER BY CASE pm.status WHEN 'pending' THEN 0 WHEN 'active' THEN 1 ELSE 2 END,pm.balance DESC`,[rq.params.poolId]));}catch(e){console.error(e);rs.status(500).json({error:"Server error"});}});
app.post("/api/pools/:poolId/members/:memberId/approve",auth,async(rq,rs)=>{try{if(!(await requireAdmin(rq,rs)))return;await pool.query("UPDATE pool_members SET status='active' WHERE id=$1 AND pool_id=$2",[rq.params.memberId,rq.params.poolId]);rs.json({success:true});}catch(e){rs.status(500).json({error:"Server error"});}});
app.post("/api/pools/:poolId/members/:memberId/deactivate",auth,async(rq,rs)=>{try{if(!(await requireAdmin(rq,rs)))return;const m=await q1("SELECT * FROM pool_members WHERE id=$1 AND pool_id=$2",[rq.params.memberId,rq.params.poolId]);if(!m)return rs.status(404).json({error:"Not found"});if(m.role==="admin")return rs.status(400).json({error:"Cannot deactivate admin"});await pool.query("UPDATE pool_members SET status='deactivated' WHERE id=$1",[rq.params.memberId]);rs.json({success:true});}catch(e){rs.status(500).json({error:"Server error"});}});
app.post("/api/pools/:poolId/members/:memberId/reactivate",auth,async(rq,rs)=>{try{if(!(await requireAdmin(rq,rs)))return;await pool.query("UPDATE pool_members SET status='active' WHERE id=$1",[rq.params.memberId]);rs.json({success:true});}catch(e){rs.status(500).json({error:"Server error"});}});
app.post("/api/pools/:poolId/members/:memberId/adjust-balance",auth,async(rq,rs)=>{try{if(!(await requireAdmin(rq,rs)))return;const{amount,reason}=rq.body;if(amount===undefined)return rs.status(400).json({error:"Amount required"});const m=await q1("SELECT * FROM pool_members WHERE id=$1 AND pool_id=$2",[rq.params.memberId,rq.params.poolId]);if(!m)return rs.status(404).json({error:"Not found"});const nb=m.balance+parseInt(amount);if(nb<0)return rs.status(400).json({error:"Balance cannot go below 0"});await pool.query("UPDATE pool_members SET balance=$1 WHERE id=$2",[nb,rq.params.memberId]);const u=await q1("SELECT display_name FROM users WHERE id=(SELECT user_id FROM pool_members WHERE id=$1)",[rq.params.memberId]);const msg=`[ADMIN] Adjusted ${u.display_name}'s balance: ${amount>0?"+":""}${amount} pts${reason?" — "+reason:""}`;await pool.query("INSERT INTO messages(id,pool_id,user_id,content)VALUES($1,$2,$3,$4)",[uuid(),rq.params.poolId,rq.user.id,msg]);rs.json({success:true,newBalance:nb});}catch(e){console.error(e);rs.status(500).json({error:"Server error"});}});

// MESSAGES
app.get("/api/pools/:poolId/messages",auth,async(rq,rs)=>{try{const m=await q1("SELECT * FROM pool_members WHERE pool_id=$1 AND user_id=$2 AND status='active'",[rq.params.poolId,rq.user.id]);if(!m)return rs.status(403).json({error:"Not in pool"});const limit=parseInt(rq.query.limit)||50;const msgs=await q(`SELECT m.*,u.display_name,u.username FROM messages m JOIN users u ON m.user_id=u.id WHERE m.pool_id=$1 ORDER BY m.created_at DESC LIMIT $2`,[rq.params.poolId,limit]);rs.json(msgs.reverse());}catch(e){console.error(e);rs.status(500).json({error:"Server error"});}});
app.post("/api/pools/:poolId/messages",auth,async(rq,rs)=>{try{const m=await q1("SELECT * FROM pool_members WHERE pool_id=$1 AND user_id=$2 AND status='active'",[rq.params.poolId,rq.user.id]);if(!m)return rs.status(403).json({error:"Not in pool"});const{content}=rq.body;if(!content||!content.trim())return rs.status(400).json({error:"Required"});if(content.length>500)return rs.status(400).json({error:"Too long"});const id=uuid();await pool.query("INSERT INTO messages(id,pool_id,user_id,content)VALUES($1,$2,$3,$4)",[id,rq.params.poolId,rq.user.id,content.trim()]);const msg=await q1("SELECT m.*,u.display_name,u.username FROM messages m JOIN users u ON m.user_id=u.id WHERE m.id=$1",[id]);rs.json(msg);}catch(e){console.error(e);rs.status(500).json({error:"Server error"});}});

// ODDS & SCORES
async function fetchOdds(){if(!ODDS_API_KEY)return 0;try{const r=await fetch(`https://api.the-odds-api.com/v4/sports/${SPORT}/odds/?apiKey=${ODDS_API_KEY}&regions=us&markets=spreads,totals,h2h&oddsFormat=american`);if(!r.ok)return 0;const data=await r.json();console.log("Odds:"+data.length+" Remaining:"+r.headers.get("x-requests-remaining"));for(const ev of data){const bk=ev.bookmakers?.[0];if(!bk)continue;let sh=null,sa=null,tot=null,mlh=null,mla=null;for(const mk of bk.markets){if(mk.key==="spreads")for(const o of mk.outcomes){if(o.name===ev.home_team)sh=o.point;else sa=o.point;}if(mk.key==="totals"){const ov=mk.outcomes.find(o=>o.name==="Over");if(ov)tot=ov.point;}if(mk.key==="h2h")for(const o of mk.outcomes){if(o.name===ev.home_team)mlh=o.price;else mla=o.price;}}const ex=await q1("SELECT * FROM games WHERE id=$1",[ev.id]);if(ex&&(ex.spread_home!==sh||ex.total!==tot||ex.moneyline_home!==mlh)){await pool.query("INSERT INTO line_history(id,game_id,spread_home,spread_away,total,moneyline_home,moneyline_away)VALUES($1,$2,$3,$4,$5,$6,$7)",[uuid(),ev.id,sh,sa,tot,mlh,mla]);}else if(!ex){await pool.query("INSERT INTO line_history(id,game_id,spread_home,spread_away,total,moneyline_home,moneyline_away)VALUES($1,$2,$3,$4,$5,$6,$7)",[uuid(),ev.id,sh,sa,tot,mlh,mla]);}await pool.query(`INSERT INTO games(id,commence_time,home_team,away_team,spread_home,spread_away,total,moneyline_home,moneyline_away,status,last_updated)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'upcoming',NOW())ON CONFLICT(id)DO UPDATE SET spread_home=$5,spread_away=$6,total=$7,moneyline_home=$8,moneyline_away=$9,last_updated=NOW(),commence_time=$2`,[ev.id,ev.commence_time,ev.home_team,ev.away_team,sh,sa,tot,mlh,mla]);}return data.length;}catch(e){console.error("Odds fail:",e.message);return 0;}}

async function fetchScores(){if(!ODDS_API_KEY)return;try{const r=await fetch(`https://api.the-odds-api.com/v4/sports/${SPORT}/scores/?apiKey=${ODDS_API_KEY}&daysFrom=3`);if(!r.ok)return;const data=await r.json();let g=0;
// FIX #1: Also update live scores for in-progress games, not just completed ones
for(const ev of data){
  if(ev.scores){
    const hs=ev.scores.find(s=>s.name===ev.home_team);
    const as=ev.scores.find(s=>s.name===ev.away_team);
    if(hs&&as){
      if(ev.completed){
        const r2=await pool.query("UPDATE games SET home_score=$1,away_score=$2,status='final' WHERE id=$3 AND status!='final' RETURNING id",[parseInt(hs.score),parseInt(as.score),ev.id]);
        if(r2.rowCount>0)g++;
      }else{
        // Game is in progress — update live scores without marking final
        await pool.query("UPDATE games SET home_score=$1,away_score=$2,last_updated=NOW() WHERE id=$3",[parseInt(hs.score),parseInt(as.score),ev.id]);
      }
    }
  }
}
if(g>0){console.log(g+" games finalized");await gradeBets();}}catch(e){console.error("Scores fail:",e.message);}}

// FIX #1b: Fetch live scores from ESPN (free, no API key needed, more frequent updates)
async function fetchESPNLiveScores(){
  try{
    const r=await fetch("https://site.api.espn.com/apis/site/v2/sports/football/ufl/scoreboard");
    if(!r.ok)return;
    const data=await r.json();
    const ourGames=await q("SELECT * FROM games WHERE status='upcoming' OR (status!='final' AND home_score IS NOT NULL)");
    let updated=0;
    for(const ev of (data.events||[])){
      const c=ev.competitions?.[0];if(!c)continue;
      const hm=c.competitors?.find(x=>x.homeAway==="home");
      const aw=c.competitors?.find(x=>x.homeAway==="away");
      if(!hm||!aw)continue;
      const hmName=hm.team?.displayName,awName=aw.team?.displayName;
      const hmScore=parseInt(hm.score||0),awScore=parseInt(aw.score||0);
      const done=c.status?.type?.completed||false;
      const inProgress=c.status?.type?.state==="in"||false;
      // Match to our games DB
      const match=ourGames.find(g=>{
        const nmMatch=g.home_team===hmName||g.away_team===awName||
          g.home_team?.includes(hm.team?.abbreviation)||g.away_team?.includes(aw.team?.abbreviation);
        const dtMatch=Math.abs(new Date(g.commence_time)-new Date(ev.date))<172800000;
        return nmMatch&&dtMatch;
      });
      if(!match)continue;
      if(done&&match.status!=="final"){
        await pool.query("UPDATE games SET home_score=$1,away_score=$2,status='final',last_updated=NOW() WHERE id=$3",[hmScore,awScore,match.id]);
        updated++;
      }else if(inProgress){
        await pool.query("UPDATE games SET home_score=$1,away_score=$2,last_updated=NOW() WHERE id=$3",[hmScore,awScore,match.id]);
        updated++;
      }
    }
    if(updated>0){console.log("ESPN live: "+updated+" games updated");await gradeBets();}
  }catch(e){console.error("ESPN live fail:",e.message);}
}

// FIX #2: Grade a single bet leg's result (shared helper)
function gradeOneLeg(b){
  const{home_score:hs,away_score:as,home_team:ht,away_team:at}=b;
  const ts=hs+as;
  let r="loss";
  if(b.bet_type==="spread"){
    const ps=b.pick===ht?hs:as,os=b.pick===ht?as:hs,m=ps-os+b.line;
    r=m>0?"win":m===0?"push":"loss";
  }else if(b.bet_type==="over")r=ts>b.line?"win":ts===b.line?"push":"loss";
  else if(b.bet_type==="under")r=ts<b.line?"win":ts===b.line?"push":"loss";
  else if(b.bet_type==="moneyline"){
    if(hs===as)r="push";else r=b.pick===(hs>as?ht:at)?"win":"loss";
  }
  return r;
}

async function gradeBets(){
  // Grade straight bets (no parlay)
  const pending=await q(`SELECT b.*,g.home_team,g.away_team,g.home_score,g.away_score FROM bets b JOIN games g ON b.game_id=g.id WHERE b.result='pending' AND g.status='final' AND b.parlay_group IS NULL`);
  for(const b of pending){
    let r=gradeOneLeg(b);
    let p=0;
    if(r==="win")p=(b.bet_type==="moneyline"&&b.odds)?(b.odds<0?b.wager+Math.round(b.wager*(100/Math.abs(b.odds))):b.wager+Math.round(b.wager*(b.odds/100))):b.wager+Math.round(b.wager*(100/110));
    else if(r==="push")p=b.wager;
    await pool.query("UPDATE bets SET result=$1,payout=$2 WHERE id=$3",[r,p,b.id]);
    if(p>0)await pool.query("UPDATE pool_members SET balance=balance+$1 WHERE id=$2",[p,b.member_id]);
  }

  // FIX #2: Grade parlays — don't wait for ALL games to finish.
  // If any leg lost, the whole parlay is dead immediately.
  const pgs=await q("SELECT DISTINCT parlay_group FROM bets WHERE parlay_group IS NOT NULL AND result='pending'");
  for(const{parlay_group:pg}of pgs){
    const legs=await q(`SELECT b.*,g.home_team,g.away_team,g.home_score,g.away_score,g.status as gs FROM bets b JOIN games g ON b.game_id=g.id WHERE b.parlay_group=$1`,[pg]);

    // First, grade any individual legs whose games are final but still pending
    for(const l of legs){
      if(l.result==="pending"&&l.gs==="final"){
        const lr=gradeOneLeg(l);
        await pool.query("UPDATE bets SET result=$1 WHERE id=$2",[lr,l.id]);
        l.result=lr; // update in memory too
      }
    }

    // Now check parlay outcome:
    // If ANY leg is a loss → entire parlay is lost
    const hasLoss=legs.some(l=>l.result==="loss");
    if(hasLoss){
      // Mark all remaining pending legs as loss too (parlay is dead)
      for(const l of legs){
        if(l.result==="pending"){
          await pool.query("UPDATE bets SET result='loss',payout=0 WHERE id=$1",[l.id]);
        }
      }
      // No payout — wager was already deducted
      console.log("Parlay "+pg+" lost (leg failed)");
      continue;
    }

    // If all legs are settled (no pending left)
    const allSettled=legs.every(l=>l.result!=="pending");
    if(!allSettled)continue; // Some games haven't finished yet, but no losses so far — wait

    // All settled, no losses — calculate payout
    const allWon=legs.every(l=>l.result==="win");
    const hasPush=legs.some(l=>l.result==="push");

    if(allWon||hasPush){
      // Calculate parlay multiplier from winning legs only (pushes reduce the parlay)
      let mt=1;
      for(const l of legs){
        if(l.result==="win"){
          if(l.bet_type==="moneyline"&&l.odds){
            const o=l.odds;
            mt*=o<0?1+100/Math.abs(o):1+o/100;
          }else mt*=1.909;
        }
        // Push legs don't multiply — they're just removed from the parlay effectively
      }
      const pp=Math.round(legs[0].wager*mt);
      if(pp>0)await pool.query("UPDATE pool_members SET balance=balance+$1 WHERE id=$2",[pp,legs[0].member_id]);
      console.log("Parlay "+pg+" won! Payout: "+pp);
    }
  }
  console.log("Grading done");
}

// GAMES & BETTING
app.get("/api/games",async(rq,rs)=>{try{rs.json(await q("SELECT * FROM games ORDER BY commence_time"));}catch(e){rs.status(500).json({error:"Server error"});}});
app.get("/api/games/upcoming",async(rq,rs)=>{try{rs.json(await q("SELECT * FROM games WHERE status='upcoming' ORDER BY commence_time"));}catch(e){rs.status(500).json({error:"Server error"});}});
app.get("/api/games/:gameId/line-history",async(rq,rs)=>{try{const h=await q("SELECT * FROM line_history WHERE game_id=$1 ORDER BY recorded_at ASC",[rq.params.gameId]);const g=await q1("SELECT * FROM games WHERE id=$1",[rq.params.gameId]);rs.json({history:h,current:g});}catch(e){rs.status(500).json({error:"Server error"});}});

app.post("/api/bet",auth,async(rq,rs)=>{try{const{pool_id,game_id,bet_type,pick,line,odds,wager,parlay_group}=rq.body;const m=await q1("SELECT * FROM pool_members WHERE pool_id=$1 AND user_id=$2 AND status='active'",[pool_id,rq.user.id]);if(!m)return rs.status(403).json({error:"Not active"});const g=await q1("SELECT * FROM games WHERE id=$1",[game_id]);if(!g)return rs.status(404).json({error:"Game not found"});if(g.status!=="upcoming")return rs.status(400).json({error:"Game started"});if(new Date(g.commence_time)<=new Date())return rs.status(400).json({error:"Betting closed"});if(!wager||wager<=0)return rs.status(400).json({error:"Invalid wager"});if(wager>m.balance)return rs.status(400).json({error:"Insufficient balance"});await pool.query("UPDATE pool_members SET balance=balance-$1 WHERE id=$2",[wager,m.id]);const id=uuid();await pool.query("INSERT INTO bets(id,member_id,pool_id,game_id,bet_type,pick,line,odds,wager,parlay_group)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",[id,m.id,pool_id,game_id,bet_type,pick,line,odds,wager,parlay_group||null]);rs.json({success:true,betId:id,newBalance:m.balance-wager});}catch(e){console.error(e);rs.status(500).json({error:"Server error"});}});

app.get("/api/pools/:poolId/activity",auth,async(rq,rs)=>{try{const m=await q1("SELECT * FROM pool_members WHERE pool_id=$1 AND user_id=$2 AND status='active'",[rq.params.poolId,rq.user.id]);if(!m)return rs.status(403).json({error:"Not in pool"});const bets=await q(`SELECT b.id,b.bet_type,b.pick,b.line,b.odds,b.wager,b.result,b.payout,b.parlay_group,b.created_at,b.member_id,b.game_id,g.home_team,g.away_team,g.commence_time,g.status as game_status,g.home_score,g.away_score,u.display_name,u.username FROM bets b JOIN games g ON b.game_id=g.id JOIN pool_members pm ON b.member_id=pm.id JOIN users u ON pm.user_id=u.id WHERE b.pool_id=$1 ORDER BY b.created_at DESC`,[rq.params.poolId]);const now=new Date();rs.json(bets.map(b=>{const started=new Date(b.commence_time)<=now||b.game_status!=="upcoming";const own=b.member_id===m.id;const rev=started||own;return{id:b.id,display_name:b.display_name,username:b.username,wager:b.wager,result:b.result,payout:b.payout,created_at:b.created_at,parlay_group:b.parlay_group,game_id:b.game_id,game_status:b.game_status,commence_time:b.commence_time,is_own:own,revealed:rev,home_team:rev?b.home_team:null,away_team:rev?b.away_team:null,home_score:rev?b.home_score:null,away_score:rev?b.away_score:null,bet_type:rev?b.bet_type:null,pick:rev?b.pick:null,line:rev?b.line:null,odds:rev?b.odds:null};}));}catch(e){console.error(e);rs.status(500).json({error:"Server error"});}});

app.get("/api/pools/:poolId/my-bets",auth,async(rq,rs)=>{try{const m=await q1("SELECT * FROM pool_members WHERE pool_id=$1 AND user_id=$2",[rq.params.poolId,rq.user.id]);if(!m)return rs.status(403).json({error:"Not in pool"});rs.json(await q("SELECT b.*,g.home_team,g.away_team,g.home_score,g.away_score,g.commence_time FROM bets b JOIN games g ON b.game_id=g.id WHERE b.member_id=$1 ORDER BY b.created_at DESC",[m.id]));}catch(e){console.error(e);rs.status(500).json({error:"Server error"});}});

app.get("/api/pools/:poolId/leaderboard",async(rq,rs)=>{try{rs.json(await q(`SELECT pm.balance,pm.status,pm.role,u.display_name,u.username,(SELECT COUNT(*)FROM bets WHERE member_id=pm.id AND result='win')as wins,(SELECT COUNT(*)FROM bets WHERE member_id=pm.id AND result='loss')as losses,(SELECT COUNT(*)FROM bets WHERE member_id=pm.id AND result='push')as pushes,(SELECT COALESCE(SUM(wager),0)FROM bets WHERE member_id=pm.id AND result='pending')as pending_amount,(pm.balance+(SELECT COALESCE(SUM(wager),0)FROM bets WHERE member_id=pm.id AND result='pending'))as display_balance FROM pool_members pm JOIN users u ON pm.user_id=u.id WHERE pm.pool_id=$1 AND pm.status='active' ORDER BY(pm.balance+(SELECT COALESCE(SUM(wager),0)FROM bets WHERE member_id=pm.id AND result='pending'))DESC`,[rq.params.poolId]));}catch(e){console.error(e);rs.status(500).json({error:"Server error"});}});

// Fetch detailed live game info from ESPN (quarter, clock, situation, last play)
async function fetchESPNLiveDetail(){
  try{
    const r=await fetch("https://site.api.espn.com/apis/site/v2/sports/football/ufl/scoreboard");
    if(!r.ok)return{};
    const data=await r.json();
    const details={};
    for(const ev of(data.events||[])){
      const c=ev.competitions?.[0];if(!c)continue;
      const hm=c.competitors?.find(x=>x.homeAway==="home");
      const aw=c.competitors?.find(x=>x.homeAway==="away");
      if(!hm||!aw)continue;
      const status=c.status||{};
      const detail={
        espn_id:ev.id,
        home_name:hm.team?.displayName,away_name:aw.team?.displayName,
        home_abbr:hm.team?.abbreviation,away_abbr:aw.team?.abbreviation,
        home_score:parseInt(hm.score||0),away_score:parseInt(aw.score||0),
        home_logo:hm.team?.logo,away_logo:aw.team?.logo,
        home_color:hm.team?.color?`#${hm.team.color}`:null,
        away_color:aw.team?.color?`#${aw.team.color}`:null,
        home_record:hm.records?.[0]?.summary,away_record:aw.records?.[0]?.summary,
        state:status.type?.state||"pre", // pre, in, post
        completed:status.type?.completed||false,
        period:status.period||0,
        clock:status.displayClock||"",
        detail:status.type?.shortDetail||"",
        description:status.type?.detail||"",
        // Situation (down & distance, possession, yard line)
        situation:null,
        lastPlay:null,
        // Leaders
        leaders:null
      };
      if(c.situation){
        detail.situation={
          down:c.situation.down,
          distance:c.situation.distance,
          yardLine:c.situation.yardLine,
          downDistanceText:c.situation.downDistanceText||
            (c.situation.down?`${c.situation.down}${c.situation.down===1?"st":c.situation.down===2?"nd":c.situation.down===3?"rd":"th"} & ${c.situation.distance}`:""),
          possession:c.situation.possession?.id||null,
          possessionText:c.situation.possessionText||null,
          isRedZone:c.situation.isRedZone||false,
          homeTimeouts:c.situation.homeTimeouts,
          awayTimeouts:c.situation.awayTimeouts
        };
        if(c.situation.lastPlay){
          detail.lastPlay={
            text:c.situation.lastPlay.text||"",
            team:c.situation.lastPlay.team?.id||null
          };
        }
      }
      // Leaders (passing, rushing, receiving)
      if(c.leaders&&c.leaders.length>0){
        detail.leaders=c.leaders.map(lg=>({
          name:lg.name||lg.displayName||"",
          shortName:lg.shortDisplayName||"",
          athletes:(lg.leaders||[]).slice(0,2).map(a=>({
            name:a.athlete?.displayName||"",
            team:a.athlete?.team?.abbreviation||"",
            value:a.displayValue||a.value||""
          }))
        }));
      }
      // Linescores (quarter-by-quarter)
      const homeLS=hm.linescores||[];
      const awayLS=aw.linescores||[];
      if(homeLS.length>0||awayLS.length>0){
        detail.linescores={
          home:homeLS.map(x=>x.value),
          away:awayLS.map(x=>x.value)
        };
      }
      // Store by team names for matching
      details[hm.team?.displayName]=detail;
      details[aw.team?.displayName]=detail;
      if(hm.team?.abbreviation)details[hm.team.abbreviation]=detail;
      if(aw.team?.abbreviation)details[aw.team.abbreviation]=detail;
    }
    return details;
  }catch(e){console.error("ESPN detail fail:",e.message);return{};}
}

// FIX #1 & #3: LIVE endpoint — fetch fresh ESPN scores + include parlay_group, commence_time, and game detail
app.get("/api/pools/:poolId/live",auth,async(rq,rs)=>{try{
  const m=await q1("SELECT * FROM pool_members WHERE pool_id=$1 AND user_id=$2 AND status='active'",[rq.params.poolId,rq.user.id]);
  if(!m)return rs.status(403).json({error:"Not in pool"});

  // FIX #1: Fetch fresh scores from ESPN before returning data
  await fetchESPNLiveScores();

  // Also trigger grading in case games just finished
  await gradeBets();

  // Fetch rich ESPN detail for live games (quarter, clock, situation)
  const espnDetail=await fetchESPNLiveDetail();

  const games=await q(`SELECT * FROM games WHERE
    (commence_time::timestamptz <= NOW() AND status='upcoming')
    OR status='final'
    OR home_score IS NOT NULL
    ORDER BY commence_time DESC LIMIT 20`);
  const result=[];
  for(const g of games){
    // FIX #3: Include parlay_group and game commence_time for each bet
    const gb=await q(`SELECT b.id,b.bet_type,b.pick,b.line,b.odds,b.wager,b.result,b.payout,b.member_id,b.parlay_group,b.game_id,
      u.display_name,u.username,
      bg.commence_time,bg.home_team as bet_home_team,bg.away_team as bet_away_team
      FROM bets b
      JOIN pool_members pm ON b.member_id=pm.id
      JOIN users u ON pm.user_id=u.id
      JOIN games bg ON b.game_id=bg.id
      WHERE b.game_id=$1 AND b.pool_id=$2
      ORDER BY b.wager DESC`,[g.id,rq.params.poolId]);

    // For parlay bets, also fetch the other legs so frontend can display the full parlay
    const parlayGroups=new Set();
    for(const b of gb){if(b.parlay_group)parlayGroups.add(b.parlay_group);}

    let extraLegs=[];
    if(parlayGroups.size>0){
      const pgArr=[...parlayGroups];
      extraLegs=await q(`SELECT b.id,b.bet_type,b.pick,b.line,b.odds,b.wager,b.result,b.payout,b.member_id,b.parlay_group,b.game_id,
        u.display_name,u.username,
        bg.commence_time,bg.home_team as bet_home_team,bg.away_team as bet_away_team
        FROM bets b
        JOIN pool_members pm ON b.member_id=pm.id
        JOIN users u ON pm.user_id=u.id
        JOIN games bg ON b.game_id=bg.id
        WHERE b.parlay_group=ANY($1) AND b.game_id!=$2 AND b.pool_id=$3`,[pgArr,g.id,rq.params.poolId]);
    }

    const allBets=[...gb,...extraLegs].map(b=>({
      ...b,
      home_team:b.bet_home_team,
      away_team:b.bet_away_team
    }));

    // Match ESPN detail to this game
    const espn=espnDetail[g.home_team]||espnDetail[g.away_team]||null;

    result.push({...g,pool_bets:allBets,espn_detail:espn});
  }
  rs.json(result);
}catch(e){console.error(e);rs.status(500).json({error:"Server error"});}});

// SCHEDULE (ESPN)
app.get("/api/schedule",async(rq,rs)=>{try{let espnWeeks=[];try{const cr=await fetch("https://site.api.espn.com/apis/site/v2/sports/football/ufl/scoreboard");const cd=await cr.json();const tw=cd.leagues?.[0]?.calendar?.[0]?.entries?.length||10;for(let w=1;w<=tw;w++){try{const wr=await fetch(`https://site.api.espn.com/apis/site/v2/sports/football/ufl/scoreboard?week=${w}`);const wd=await wr.json();if(wd.events&&wd.events.length>0){const games=wd.events.map(ev=>{const c=ev.competitions?.[0],hm=c?.competitors?.find(x=>x.homeAway==="home"),aw=c?.competitors?.find(x=>x.homeAway==="away"),done=c?.status?.type?.completed||false;
              const broadcasts=c?.geoBroadcasts||c?.broadcasts||[];
              const tvNetworks=broadcasts.map(b=>b.media?.shortName||b.names?.[0]||"").filter(Boolean);
              const tvNetwork=tvNetworks.length>0?[...new Set(tvNetworks)].join(", "):null;
              const homeStats=hm?.statistics||[];
              const awayStats=aw?.statistics||[];
              return{espn_id:ev.id,name:ev.name,date:ev.date,home_team:hm?.team?.displayName,away_team:aw?.team?.displayName,home_abbr:hm?.team?.abbreviation,away_abbr:aw?.team?.abbreviation,home_score:done?parseInt(hm?.score||0):null,away_score:done?parseInt(aw?.score||0):null,home_record:hm?.records?.[0]?.summary,away_record:aw?.records?.[0]?.summary,status:done?"final":c?.status?.type?.name||"upcoming",status_detail:c?.status?.type?.shortDetail||"",venue:c?.venue?.fullName,city:c?.venue?.address?.city,state:c?.venue?.address?.state,tv:tvNetwork,home_stats:homeStats,away_stats:awayStats,home_logo:hm?.team?.logo,away_logo:aw?.team?.logo,home_color:hm?.team?.color?`#${hm.team.color}`:null,away_color:aw?.team?.color?`#${aw.team.color}`:null};});espnWeeks.push({week:w,games});}}catch(e){}}}catch(e){console.error("ESPN fail:",e.message);}if(espnWeeks.length>0){const our=await q("SELECT * FROM games ORDER BY commence_time");for(const wk of espnWeeks){for(const g of wk.games){const m=our.find(x=>{const nm=x.home_team===g.home_team||x.away_team===g.away_team||x.home_team?.includes(g.home_abbr)||x.away_team?.includes(g.away_abbr);const dt=Math.abs(new Date(x.commence_time)-new Date(g.date))<172800000;return nm&&dt;});if(m){g.odds_game_id=m.id;g.spread_home=m.spread_home;g.spread_away=m.spread_away;g.total=m.total;g.moneyline_home=m.moneyline_home;g.moneyline_away=m.moneyline_away;await pool.query("UPDATE games SET week=$1 WHERE id=$2",[wk.week,m.id]);}}}return rs.json(espnWeeks);}const games=await q("SELECT * FROM games ORDER BY commence_time ASC");const weeks={};for(const g of games){const w=g.week||1;if(!weeks[w])weeks[w]={week:w,games:[]};weeks[w].games.push({...g,date:g.commence_time,status_detail:g.status});}rs.json(Object.values(weeks).sort((a,b)=>a.week-b.week));}catch(e){console.error(e);rs.status(500).json({error:"Server error"});}});

// ESPN PROXY
app.get("/api/espn/teams",async(rq,rs)=>{try{const r=await fetch("https://site.api.espn.com/apis/site/v2/sports/football/ufl/teams");if(!r.ok)return rs.status(502).json({error:"ESPN unavailable"});const d=await r.json();rs.json((d.sports?.[0]?.leagues?.[0]?.teams||[]).map(t=>{const x=t.team;return{id:x.id,name:x.displayName,abbr:x.abbreviation,shortName:x.shortDisplayName,nickname:x.name,color:x.color?`#${x.color}`:"#666",altColor:x.alternateColor?`#${x.alternateColor}`:"#333",logo:x.logos?.[0]?.href||null,record:x.record?.items?.[0]?.summary||null,location:x.location};}));}catch(e){rs.status(502).json({error:"ESPN unavailable"});}});
app.get("/api/espn/teams/:teamId",async(rq,rs)=>{try{const r=await fetch(`https://site.api.espn.com/apis/site/v2/sports/football/ufl/teams/${rq.params.teamId}`);if(!r.ok)return rs.status(502).json({error:"ESPN unavailable"});rs.json(await r.json());}catch(e){rs.status(502).json({error:"ESPN unavailable"});}});
app.get("/api/espn/teams/:teamId/roster",async(rq,rs)=>{try{const r=await fetch(`https://site.api.espn.com/apis/site/v2/sports/football/ufl/teams/${rq.params.teamId}/roster`);if(!r.ok)return rs.status(502).json({error:"ESPN unavailable"});rs.json(await r.json());}catch(e){rs.status(502).json({error:"ESPN unavailable"});}});
app.get("/api/espn/teams/:teamId/schedule",async(rq,rs)=>{try{const r=await fetch(`https://site.api.espn.com/apis/site/v2/sports/football/ufl/teams/${rq.params.teamId}/schedule`);if(!r.ok)return rs.status(502).json({error:"ESPN unavailable"});rs.json(await r.json());}catch(e){rs.status(502).json({error:"ESPN unavailable"});}});
app.get("/api/espn/standings",async(rq,rs)=>{try{const r=await fetch("https://site.api.espn.com/apis/v2/sports/football/ufl/standings");if(!r.ok)return rs.status(502).json({error:"ESPN unavailable"});rs.json(await r.json());}catch(e){rs.status(502).json({error:"ESPN unavailable"});}});
app.get("/api/espn/news",async(rq,rs)=>{try{const r=await fetch("https://site.api.espn.com/apis/site/v2/sports/football/ufl/news");if(!r.ok)return rs.status(502).json({error:"ESPN unavailable"});rs.json(await r.json());}catch(e){rs.status(502).json({error:"ESPN unavailable"});}});
app.get("/api/espn/scoreboard",async(rq,rs)=>{try{const w=rq.query.week?`?week=${rq.query.week}`:"";const r=await fetch(`https://site.api.espn.com/apis/site/v2/sports/football/ufl/scoreboard${w}`);if(!r.ok)return rs.status(502).json({error:"ESPN unavailable"});rs.json(await r.json());}catch(e){rs.status(502).json({error:"ESPN unavailable"});}});
app.get("/api/espn/summary/:eventId",async(rq,rs)=>{try{
  const r=await fetch(`https://site.api.espn.com/apis/site/v2/sports/football/ufl/summary?event=${rq.params.eventId}`);
  if(!r.ok)return rs.status(502).json({error:"ESPN unavailable"});
  const data=await r.json();
  // Normalize the response to ensure consistent shape for frontend
  const normalized={
    scoringPlays:data.scoringPlays||[],
    boxscore:data.boxscore||{teams:[],players:[]},
    header:data.header||null,
    drives:data.drives||null,
    leaders:data.leaders||[],
    standings:data.standings||null,
    // Also include game info if available
    gameInfo:data.gameInfo||null,
    predictor:data.predictor||null,
    winprobability:data.winprobability||null,
    // Key players / top performers
    keyEvents:data.keyEvents||[],
    // Flatten article if present
    article:data.article||null
  };
  // Ensure boxscore has the expected arrays
  if(!normalized.boxscore.teams)normalized.boxscore.teams=[];
  if(!normalized.boxscore.players)normalized.boxscore.players=[];
  rs.json(normalized);
}catch(e){rs.status(502).json({error:"ESPN unavailable"});}});

// Fallback: look up ESPN event ID by team abbreviation and get summary
app.get("/api/espn/summary-by-team/:abbr",async(rq,rs)=>{try{
  const scr=await fetch("https://site.api.espn.com/apis/site/v2/sports/football/ufl/scoreboard");
  if(!scr.ok)return rs.status(502).json({error:"ESPN unavailable"});
  const scd=await scr.json();
  const abbr=rq.params.abbr.toUpperCase();
  // Find event matching team
  const ev=(scd.events||[]).find(e=>{
    const c=e.competitions?.[0];if(!c)return false;
    return c.competitors?.some(x=>x.team?.abbreviation?.toUpperCase()===abbr);
  });
  if(!ev)return rs.status(404).json({error:"No game found for "+abbr});
  // Now fetch the summary
  const r=await fetch(`https://site.api.espn.com/apis/site/v2/sports/football/ufl/summary?event=${ev.id}`);
  if(!r.ok)return rs.status(502).json({error:"ESPN unavailable"});
  const data=await r.json();
  const normalized={
    scoringPlays:data.scoringPlays||[],
    boxscore:data.boxscore||{teams:[],players:[]},
    header:data.header||null,
    drives:data.drives||null,
    leaders:data.leaders||[],
    gameInfo:data.gameInfo||null,
    keyEvents:data.keyEvents||[],
    article:data.article||null
  };
  if(!normalized.boxscore.teams)normalized.boxscore.teams=[];
  if(!normalized.boxscore.players)normalized.boxscore.players=[];
  rs.json(normalized);
}catch(e){rs.status(502).json({error:"ESPN unavailable"});}});

// PROFILE (own)
app.get("/api/pools/:poolId/profile",auth,async(rq,rs)=>{try{const m=await q1("SELECT * FROM pool_members WHERE pool_id=$1 AND user_id=$2",[rq.params.poolId,rq.user.id]);if(!m)return rs.status(403).json({error:"Not in pool"});const u=await q1("SELECT username,display_name FROM users WHERE id=$1",[rq.user.id]);const stats=await q1(`SELECT COUNT(*)as total_bets,COUNT(*)FILTER(WHERE result='win')as wins,COUNT(*)FILTER(WHERE result='loss')as losses,COUNT(*)FILTER(WHERE result='push')as pushes,COUNT(*)FILTER(WHERE result='pending')as pending,COALESCE(SUM(wager),0)as total_wagered,COALESCE(SUM(payout),0)as total_payout,COALESCE(SUM(wager)FILTER(WHERE result='pending'),0)as pending_amount,COALESCE(SUM(CASE WHEN result='win' THEN payout-wager WHEN result='loss' THEN -wager ELSE 0 END),0)as net_profit,COALESCE(AVG(wager),0)as avg_wager FROM bets WHERE member_id=$1 AND parlay_group IS NULL`,[m.id]);const byType=await q(`SELECT bet_type,COUNT(*)as total,COUNT(*)FILTER(WHERE result='win')as wins,COUNT(*)FILTER(WHERE result='loss')as losses FROM bets WHERE member_id=$1 AND parlay_group IS NULL GROUP BY bet_type`,[m.id]);const graded=await q(`SELECT result FROM bets WHERE member_id=$1 AND result IN('win','loss')AND parlay_group IS NULL ORDER BY created_at DESC LIMIT 20`,[m.id]);let streak=0,streakType="";if(graded.length>0){streakType=graded[0].result;for(const b of graded){if(b.result===streakType)streak++;else break;}}const wr=parseInt(stats.total_bets)>0?((parseInt(stats.wins)/(parseInt(stats.wins)+parseInt(stats.losses)))*100):0;const roi=parseInt(stats.total_wagered)>0?((parseInt(stats.net_profit)/parseInt(stats.total_wagered))*100):0;rs.json({username:u.username,display_name:u.display_name,balance:m.balance,role:m.role,stats:{...stats,win_rate:Math.round(wr*10)/10,roi:Math.round(roi*10)/10},byType,streak:{count:streak,type:streakType}});}catch(e){console.error(e);rs.status(500).json({error:"Server error"});}});

// PROFILE (view any member by username)
app.get("/api/pools/:poolId/profile/:username",auth,async(rq,rs)=>{try{const viewer=await q1("SELECT * FROM pool_members WHERE pool_id=$1 AND user_id=$2 AND status='active'",[rq.params.poolId,rq.user.id]);if(!viewer)return rs.status(403).json({error:"Not in pool"});const u=await q1("SELECT id,username,display_name FROM users WHERE username=$1",[rq.params.username]);if(!u)return rs.status(404).json({error:"User not found"});const m=await q1("SELECT * FROM pool_members WHERE pool_id=$1 AND user_id=$2",[rq.params.poolId,u.id]);if(!m)return rs.status(404).json({error:"Not in this pool"});
const stats=await q1(`SELECT COUNT(*)as total_bets,COUNT(*)FILTER(WHERE result='win')as wins,COUNT(*)FILTER(WHERE result='loss')as losses,COUNT(*)FILTER(WHERE result='push')as pushes,COUNT(*)FILTER(WHERE result='pending')as pending,COALESCE(SUM(wager),0)as total_wagered,COALESCE(SUM(payout),0)as total_payout,COALESCE(SUM(wager)FILTER(WHERE result='pending'),0)as pending_amount,COALESCE(SUM(CASE WHEN result='win' THEN payout-wager WHEN result='loss' THEN -wager ELSE 0 END),0)as net_profit,COALESCE(AVG(wager),0)as avg_wager FROM bets WHERE member_id=$1 AND parlay_group IS NULL`,[m.id]);
const byType=await q(`SELECT bet_type,COUNT(*)as total,COUNT(*)FILTER(WHERE result='win')as wins,COUNT(*)FILTER(WHERE result='loss')as losses FROM bets WHERE member_id=$1 AND parlay_group IS NULL GROUP BY bet_type`,[m.id]);
const graded=await q(`SELECT result FROM bets WHERE member_id=$1 AND result IN('win','loss')AND parlay_group IS NULL ORDER BY created_at DESC LIMIT 20`,[m.id]);
let streak=0,streakType="";if(graded.length>0){streakType=graded[0].result;for(const b of graded){if(b.result===streakType)streak++;else break;}}
const wr=parseInt(stats.total_bets)>0?((parseInt(stats.wins)/(parseInt(stats.wins)+parseInt(stats.losses)))*100):0;
const roi=parseInt(stats.total_wagered)>0?((parseInt(stats.net_profit)/parseInt(stats.total_wagered))*100):0;
const recentBets=await q(`SELECT b.bet_type,b.pick,b.line,b.odds,b.wager,b.result,b.payout,b.created_at,g.home_team,g.away_team,g.home_score,g.away_score FROM bets b JOIN games g ON b.game_id=g.id WHERE b.member_id=$1 AND b.result!='pending' AND b.parlay_group IS NULL ORDER BY b.created_at DESC LIMIT 20`,[m.id]);
rs.json({username:u.username,display_name:u.display_name,balance:m.balance,role:m.role,stats:{...stats,win_rate:Math.round(wr*10)/10,roi:Math.round(roi*10)/10},byType,streak:{count:streak,type:streakType},recentBets});}catch(e){console.error(e);rs.status(500).json({error:"Server error"});}});

// WEEKLY RECAP
app.get("/api/pools/:poolId/recap/:week",auth,async(rq,rs)=>{try{const m=await q1("SELECT * FROM pool_members WHERE pool_id=$1 AND user_id=$2 AND status='active'",[rq.params.poolId,rq.user.id]);if(!m)return rs.status(403).json({error:"Not in pool"});const w=parseInt(rq.params.week);const games=await q("SELECT * FROM games WHERE week=$1 ORDER BY commence_time",[w]);const playerSummaries=await q(`SELECT u.display_name,pm.balance,COUNT(*)FILTER(WHERE b.result='win')as wins,COUNT(*)FILTER(WHERE b.result='loss')as losses,COALESCE(SUM(CASE WHEN b.result='win' THEN b.payout-b.wager WHEN b.result='loss' THEN -b.wager ELSE 0 END),0)as week_profit FROM bets b JOIN games g ON b.game_id=g.id JOIN pool_members pm ON b.member_id=pm.id JOIN users u ON pm.user_id=u.id WHERE b.pool_id=$1 AND g.week=$2 AND b.result!='pending' GROUP BY u.display_name,pm.balance ORDER BY week_profit DESC`,[rq.params.poolId,w]);const bigWin=await q1(`SELECT b.wager,b.payout,b.bet_type,b.pick,b.line,u.display_name FROM bets b JOIN pool_members pm ON b.member_id=pm.id JOIN users u ON pm.user_id=u.id JOIN games g ON b.game_id=g.id WHERE b.pool_id=$1 AND g.week=$2 AND b.result='win' ORDER BY(b.payout-b.wager)DESC LIMIT 1`,[rq.params.poolId,w]);const bigLoss=await q1(`SELECT b.wager,b.bet_type,b.pick,b.line,u.display_name FROM bets b JOIN pool_members pm ON b.member_id=pm.id JOIN users u ON pm.user_id=u.id JOIN games g ON b.game_id=g.id WHERE b.pool_id=$1 AND g.week=$2 AND b.result='loss' ORDER BY b.wager DESC LIMIT 1`,[rq.params.poolId,w]);rs.json({week:w,games,playerSummaries,bigWin,bigLoss});}catch(e){console.error(e);rs.status(500).json({error:"Server error"});}});

// CSV EXPORTS
app.get("/api/pools/:poolId/export/standings",auth,async(rq,rs)=>{try{const lb=await q(`SELECT u.display_name,u.username,pm.balance,pm.role,(SELECT COUNT(*)FROM bets WHERE member_id=pm.id AND result='win')as wins,(SELECT COUNT(*)FROM bets WHERE member_id=pm.id AND result='loss')as losses,(SELECT COUNT(*)FROM bets WHERE member_id=pm.id AND result='push')as pushes,(SELECT COALESCE(SUM(wager),0)FROM bets WHERE member_id=pm.id AND result='pending')as pending,(pm.balance+(SELECT COALESCE(SUM(wager),0)FROM bets WHERE member_id=pm.id AND result='pending'))as display_balance FROM pool_members pm JOIN users u ON pm.user_id=u.id WHERE pm.pool_id=$1 AND pm.status='active' ORDER BY display_balance DESC`,[rq.params.poolId]);let csv="Rank,Name,Username,Balance,Display Balance,Wins,Losses,Pushes,Pending,Role\n";lb.forEach((p,i)=>{csv+=`${i+1},"${p.display_name}",${p.username},${p.balance},${p.display_balance},${p.wins},${p.losses},${p.pushes},${p.pending},${p.role}\n`;});rs.setHeader("Content-Type","text/csv");rs.setHeader("Content-Disposition","attachment; filename=standings.csv");rs.send(csv);}catch(e){rs.status(500).json({error:"Server error"});}});
app.get("/api/pools/:poolId/export/bets",auth,async(rq,rs)=>{try{const m=await q1("SELECT * FROM pool_members WHERE pool_id=$1 AND user_id=$2",[rq.params.poolId,rq.user.id]);if(!m)return rs.status(403).json({error:"Not in pool"});const bets=await q(`SELECT b.*,g.home_team,g.away_team,g.home_score,g.away_score,g.week,g.commence_time FROM bets b JOIN games g ON b.game_id=g.id WHERE b.member_id=$1 ORDER BY b.created_at DESC`,[m.id]);let csv="Date,Week,Game,Type,Pick,Line,Odds,Wager,Result,Payout,Profit\n";for(const b of bets){const pr=b.result==="win"?b.payout-b.wager:b.result==="loss"?-b.wager:0;csv+=`"${new Date(b.created_at).toLocaleDateString()}",${b.week||""},"${b.away_team} @ ${b.home_team}",${b.bet_type},"${b.pick}",${b.line||""},${b.odds||""},${b.wager},${b.result},${b.payout},${pr}\n`;}rs.setHeader("Content-Type","text/csv");rs.setHeader("Content-Disposition","attachment; filename=my-bets.csv");rs.send(csv);}catch(e){rs.status(500).json({error:"Server error"});}});

// ADMIN TRIGGERS
app.post("/api/admin/refresh-odds",auth,async(rq,rs)=>{const c=await fetchOdds();rs.json({success:true,gamesUpdated:c});});
app.post("/api/admin/refresh-scores",auth,async(rq,rs)=>{await fetchScores();await fetchESPNLiveScores();rs.json({success:true});});

// HEALTH
app.get("/",(rq,rs)=>{rs.json({status:"ok",app:"UFL Fantasy Sportsbook Pool",oddsApiConfigured:!!ODDS_API_KEY});});

// FIX #1: More aggressive cron for live score updates
// Every 2 minutes on game days (Fri, Sat, Sun) during typical game hours
cron.schedule("*/2 18-23 * * 5,6",()=>{console.log("Cron:ESPN live (Fri/Sat evening)");fetchESPNLiveScores();});
cron.schedule("*/2 12-23 * * 0",()=>{console.log("Cron:ESPN live (Sunday)");fetchESPNLiveScores();});
// Odds API scores every 10 min on game days (uses API quota)
cron.schedule("*/10 * * * 0,5,6",()=>{console.log("Cron:scores");fetchScores();});
// Odds refresh every 4 hours
cron.schedule("0 */4 * * *",()=>{console.log("Cron:odds");fetchOdds();});
// Safety net: check scores on off-days
cron.schedule("0 */2 * * 1,2,3,4",()=>{console.log("Cron:safety");fetchScores();});

// START
app.listen(PORT,async()=>{console.log("UFL Pool on port "+PORT);await initDB();if(ODDS_API_KEY){console.log("Fetching odds...");const c=await fetchOdds();console.log("Loaded "+c+" games");}});
