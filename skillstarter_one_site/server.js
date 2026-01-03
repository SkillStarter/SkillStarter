import 'dotenv/config';
import express from "express";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import csrf from "csurf";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import Database from "better-sqlite3";
import { nanoid } from "nanoid";
import Stripe from "stripe";

const app = express();
const db = new Database("skillstarter.db");

const stripeKey = process.env.STRIPE_SECRET_KEY || "";
const stripe = stripeKey ? new Stripe(stripeKey) : null;

const SITE_URL = process.env.SITE_URL || "http://localhost:3000";
const PLATFORM_FEE_PERCENT = Number(process.env.PLATFORM_FEE_PERCENT ?? 18);

app.set("view engine", "ejs");
app.use(helmet({ contentSecurityPolicy: false }));
app.use("/static", express.static("public/static"));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 200 }));

// flash in cookie
app.use((req, res, next) => {
  const raw = req.cookies.flash;
  res.locals.flash = raw ? JSON.parse(raw) : [];
  res.clearCookie("flash");
  next();
});
function flash(res, type, msg) {
  res.cookie("flash", JSON.stringify([{ type, msg }]), { httpOnly: true, sameSite: "lax" });
}

// sessions
function createSession(userId) {
  const token = nanoid(48);
  const now = new Date();
  const expires = new Date(now.getTime() + 1000 * 60 * 60 * 24 * 14);
  db.prepare("INSERT INTO sessions (token,user_id,expires_at,created_at) VALUES (?,?,?,?)")
    .run(token, userId, expires.toISOString(), now.toISOString());
  return { token, expires };
}
function getUserBySession(token) {
  if (!token) return null;
  return db.prepare(
    `SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id
     WHERE s.token=? AND s.expires_at > ?`
  ).get(token, new Date().toISOString()) || null;
}
function requireAuth(req, res, next) {
  if (!req.user) {
    flash(res, "err", "Please log in first.");
    return res.redirect("/login");
  }
  next();
}
function requireRole(role) {
  return (req, res, next) => {
    if (!req.user || req.user.role !== role) {
      flash(res, "err", "Not allowed.");
      return res.redirect("/dashboard");
    }
    next();
  };
}

// CSRF
const csrfProtection = csrf({ cookie: { httpOnly: true, sameSite: "lax" } });
app.use((req, res, next) => {
  req.user = getUserBySession(req.cookies.session);
  res.locals.user = req.user;
  next();
});
app.use(csrfProtection);
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken();
  next();
});

// Safety filter (basic)
const PHONE = /\b(\+?\d[\d\s\-()]{7,}\d)\b/;
const EMAIL = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i;
function checkMessageSafety(text) {
  if (PHONE.test(text)) return { ok: false, reason: "Please don’t share phone numbers in chat." };
  if (EMAIL.test(text)) return { ok: false, reason: "Please don’t share emails in chat." };
  if (text.length > 2000) return { ok: false, reason: "Message too long." };
  return { ok: true };
}

app.get("/", (req, res) => res.render("home", { title: "Home" }));

app.get("/rules", (req, res) => res.render("rules", { title: "Rules" }));

app.get("/signup", (req, res) => {
  const defaultRole = ["client","creator","parent"].includes(req.query.role) ? req.query.role : "client";
  res.render("signup", { title: "Sign up", defaultRole });
});
app.post("/signup", (req, res) => {
  const { display_name, email, password, role } = req.body;
  if (!display_name || !email || !password) return res.status(400).send("Missing fields");
  if (!["client","creator","parent"].includes(role)) return res.status(400).send("Bad role");

  const exists = db.prepare("SELECT 1 FROM users WHERE email=?").get(email.toLowerCase());
  if (exists) { flash(res,"err","Email already used."); return res.redirect("/signup"); }

  const now = new Date().toISOString();
  const id = nanoid();
  const password_hash = bcrypt.hashSync(password, 10);
  db.prepare("INSERT INTO users (id,email,password_hash,role,display_name,created_at) VALUES (?,?,?,?,?,?)")
    .run(id, email.toLowerCase(), password_hash, role, display_name, now);

  const s = createSession(id);
  res.cookie("session", s.token, { httpOnly: true, sameSite: "lax", expires: s.expires });
  flash(res,"ok","Account created.");
  res.redirect("/dashboard");
});

app.get("/login", (req, res) => res.render("login", { title: "Log in" }));
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE email=?").get((email||"").toLowerCase());
  if (!user || !bcrypt.compareSync(password||"", user.password_hash)) {
    flash(res,"err","Invalid login.");
    return res.redirect("/login");
  }
  const s = createSession(user.id);
  res.cookie("session", s.token, { httpOnly: true, sameSite: "lax", expires: s.expires });
  flash(res,"ok","Logged in.");
  res.redirect("/dashboard");
});
app.post("/logout", (req, res) => {
  const token = req.cookies.session;
  if (token) db.prepare("DELETE FROM sessions WHERE token=?").run(token);
  res.clearCookie("session");
  flash(res,"ok","Logged out.");
  res.redirect("/");
});

app.get("/creators", (req, res) => {
  const q = (req.query.q || "").toString().trim().toLowerCase();
  const cat = (req.query.cat || "").toString().trim();

  let rows = db.prepare(
    `SELECT l.*, u.display_name as creator_name
     FROM listings l JOIN users u ON u.id=l.creator_id
     WHERE l.active=1`
  ).all();

  rows = rows.map(r => ({ ...r, tags: r.tags ? JSON.parse(r.tags) : [] }));
  if (cat) rows = rows.filter(r => r.category === cat);
  if (q) rows = rows.filter(r => {
    const hay = `${r.title} ${r.description} ${r.category} ${r.creator_name} ${(r.tags||[]).join(" ")}`.toLowerCase();
    return hay.includes(q);
  });

  res.render("creators", { title: "Creators", listings: rows, q, cat });
});

app.get("/listing/:id", (req, res) => {
  const row = db.prepare(
    `SELECT l.*, u.display_name as creator_name
     FROM listings l JOIN users u ON u.id=l.creator_id
     WHERE l.id=?`
  ).get(req.params.id);
  if (!row || !row.active) return res.status(404).send("Not found");
  const listing = { ...row, tags: row.tags ? JSON.parse(row.tags) : [] };
  res.render("listing", { title: "Listing", listing });
});

app.post("/orders/create", requireAuth, (req, res) => {
  if (req.user.role !== "client") { flash(res,"err","Only client accounts can request."); return res.redirect("/dashboard"); }
  const { listing_id, creator_id, brief, budget_gbp, deadline_text } = req.body;
  if (!brief) return res.status(400).send("Missing brief");
  const id = nanoid();
  const now = new Date().toISOString();
  db.prepare(
    `INSERT INTO orders (id,client_id,creator_id,listing_id,status,brief,budget_gbp,deadline_text,created_at)
     VALUES (?,?,?,?,?,?,?,?,?)`
  ).run(id, req.user.id, creator_id, listing_id, "requested", brief, budget_gbp ? Number(budget_gbp) : null, deadline_text || null, now);
  flash(res,"ok","Request sent.");
  res.redirect(`/orders/${id}`);
});

function orderForUser(orderId, userId) {
  return db.prepare("SELECT * FROM orders WHERE id=? AND (client_id=? OR creator_id=?)").get(orderId, userId, userId);
}

app.get("/dashboard", requireAuth, (req, res) => {
  const orders = db.prepare(
    "SELECT * FROM orders WHERE client_id=? OR creator_id=? ORDER BY created_at DESC"
  ).all(req.user.id, req.user.id);

  let listings = [];
  let parentLink = null;
  let linkedCreators = [];

  if (req.user.role === "creator") {
    listings = db.prepare("SELECT * FROM listings WHERE creator_id=? ORDER BY created_at DESC").all(req.user.id);
    const pl = db.prepare(
      `SELECT pl.*, u.email as parent_email
       FROM parent_links pl JOIN users u ON u.id=pl.parent_id
       WHERE pl.creator_id=?`
    ).get(req.user.id);
    if (pl) parentLink = pl;
  }

  if (req.user.role === "parent") {
    linkedCreators = db.prepare(
      `SELECT pl.creator_id, pl.consented, u.display_name as creator_name
       FROM parent_links pl JOIN users u ON u.id=pl.creator_id
       WHERE pl.parent_id=?`
    ).all(req.user.id);
  }

  res.render("dashboard", { title: "Dashboard", orders, listings, parentLink, linkedCreators });
});

// Creator: create listing
app.get("/creator/listings/new", requireAuth, requireRole("creator"), (req, res) => {
  res.render("new_listing", { title: "New listing" });
});
app.post("/creator/listings/new", requireAuth, requireRole("creator"), (req, res) => {
  const { category, title, description, starting_price_gbp, tags, portfolio_url } = req.body;
  const id = nanoid();
  const now = new Date().toISOString();
  const tagArr = (tags || "").split(",").map(s => s.trim()).filter(Boolean).slice(0, 10);
  db.prepare(
    `INSERT INTO listings (id,creator_id,category,title,description,starting_price_gbp,tags,portfolio_url,active,created_at)
     VALUES (?,?,?,?,?,?,?,?,?,?)`
  ).run(id, req.user.id, category, title, description, starting_price_gbp ? Number(starting_price_gbp) : null, JSON.stringify(tagArr), portfolio_url || null, 1, now);
  flash(res,"ok","Listing created.");
  res.redirect("/dashboard");
});
app.post("/creator/listings/toggle", requireAuth, requireRole("creator"), (req, res) => {
  const row = db.prepare("SELECT * FROM listings WHERE id=? AND creator_id=?").get(req.body.id, req.user.id);
  if (!row) { flash(res,"err","Not found."); return res.redirect("/dashboard"); }
  db.prepare("UPDATE listings SET active=? WHERE id=?").run(row.active ? 0 : 1, row.id);
  flash(res,"ok","Updated.");
  res.redirect("/dashboard");
});

// Creator: link parent by email (parent must have or create account)
app.post("/creator/link-parent", requireAuth, requireRole("creator"), (req, res) => {
  const email = (req.body.parent_email || "").toLowerCase().trim();
  const parent = db.prepare("SELECT * FROM users WHERE email=?").get(email);
  if (!parent) {
    flash(res,"err","Parent email not found. Ask them to sign up as Parent/Guardian first.");
    return res.redirect("/dashboard");
  }
  if (parent.role !== "parent") {
    flash(res,"err","That email exists but isn’t a Parent/Guardian account.");
    return res.redirect("/dashboard");
  }
  const id = nanoid();
  try {
    db.prepare("INSERT INTO parent_links (id,creator_id,parent_id,consented) VALUES (?,?,?,0)")
      .run(id, req.user.id, parent.id);
    flash(res,"ok","Parent linked. They must consent in their dashboard.");
  } catch {
    flash(res,"err","Already linked.");
  }
  res.redirect("/dashboard");
});

// Parent: consent
app.post("/parent/consent", requireAuth, requireRole("parent"), (req, res) => {
  const creator_id = req.body.creator_id;
  db.prepare("UPDATE parent_links SET consented=1, consented_at=? WHERE creator_id=? AND parent_id=?")
    .run(new Date().toISOString(), creator_id, req.user.id);
  // move any accepted orders to awaiting_payment
  db.prepare("UPDATE orders SET status='awaiting_payment' WHERE creator_id=? AND status='awaiting_parent_consent'")
    .run(creator_id);
  flash(res,"ok","Consent recorded.");
  res.redirect("/dashboard");
});

app.get("/orders/:id", requireAuth, (req, res) => {
  const order = orderForUser(req.params.id, req.user.id);
  if (!order) return res.status(404).send("Not found");

  // other user id for reporting
  const otherUserId = order.client_id === req.user.id ? order.creator_id : order.client_id;

  // canPay only if parent consent exists (for creators under 18 we enforce link)
  const parentConsented = db.prepare("SELECT 1 FROM parent_links WHERE creator_id=? AND consented=1").get(order.creator_id);
  const canPay = !!parentConsented;

  const msgs = db.prepare(
    `SELECT m.*, u.display_name as sender_name
     FROM messages m JOIN users u ON u.id=m.sender_id
     WHERE m.order_id=? ORDER BY m.created_at ASC`
  ).all(order.id);

  const deliverable = db.prepare(
    "SELECT * FROM deliverables WHERE order_id=? ORDER BY created_at DESC LIMIT 1"
  ).get(order.id);

  res.render("order", {
    title: "Order",
    order: { ...order, canPay },
    messages: msgs,
    deliverable,
    platformFeePercent: PLATFORM_FEE_PERCENT,
    otherUserId
  });
});

app.post("/orders/:id/accept", requireAuth, requireRole("creator"), (req, res) => {
  const order = orderForUser(req.params.id, req.user.id);
  if (!order || order.creator_id !== req.user.id) return res.status(404).send("Not found");
  if (order.status !== "requested") { flash(res,"err","Order not in requested state."); return res.redirect(`/orders/${order.id}`); }

  const price = Number(req.body.agreed_price_gbp);
  if (!price || price < 1) { flash(res,"err","Enter a valid price."); return res.redirect(`/orders/${order.id}`); }

  // If parent is linked+consented -> awaiting_payment, else awaiting_parent_consent
  const consented = db.prepare("SELECT 1 FROM parent_links WHERE creator_id=? AND consented=1").get(order.creator_id);
  const nextStatus = consented ? "awaiting_payment" : "awaiting_parent_consent";

  db.prepare("UPDATE orders SET status=?, agreed_price_gbp=? WHERE id=?").run(nextStatus, price, order.id);
  flash(res,"ok", nextStatus === "awaiting_payment" ? "Accepted. Client can pay now." : "Accepted. Waiting for parent consent.");
  res.redirect(`/orders/${order.id}`);
});

app.post("/orders/:id/message", requireAuth, (req, res) => {
  const order = orderForUser(req.params.id, req.user.id);
  if (!order) return res.status(404).send("Not found");
  const body = (req.body.body || "").trim();
  if (!body) { flash(res,"err","Empty message."); return res.redirect(`/orders/${order.id}`); }
  const safe = checkMessageSafety(body);
  if (!safe.ok) { flash(res,"err", safe.reason); return res.redirect(`/orders/${order.id}`); }
  db.prepare("INSERT INTO messages (id,order_id,sender_id,body,created_at) VALUES (?,?,?,?,?)")
    .run(nanoid(), order.id, req.user.id, body, new Date().toISOString());
  res.redirect(`/orders/${order.id}`);
});

app.post("/orders/:id/pay", requireAuth, (req, res) => {
  const order = orderForUser(req.params.id, req.user.id);
  if (!order || order.client_id !== req.user.id) return res.status(404).send("Not found");
  if (!stripe) { flash(res,"err","Stripe is not configured."); return res.redirect(`/orders/${order.id}`); }

  // must have consent
  const consented = db.prepare("SELECT 1 FROM parent_links WHERE creator_id=? AND consented=1").get(order.creator_id);
  if (!consented) { flash(res,"err","Parent consent required before payment."); return res.redirect(`/orders/${order.id}`); }
  if (!order.agreed_price_gbp) { flash(res,"err","Creator hasn’t set a price yet."); return res.redirect(`/orders/${order.id}`); }

  const baseAmount = order.agreed_price_gbp;
  const total = Math.round(baseAmount * (1 + PLATFORM_FEE_PERCENT / 100) * 100); // pence

  stripe.checkout.sessions.create({
    mode: "payment",
    line_items: [{
      price_data: {
        currency: "gbp",
        product_data: { name: `Skillstarter commission ${order.id.slice(0,8)}` },
        unit_amount: total
      },
      quantity: 1
    }],
    success_url: `${SITE_URL}/orders/${order.id}?paid=1`,
    cancel_url: `${SITE_URL}/orders/${order.id}`,
    metadata: { orderId: order.id }
  }).then(session => {
    db.prepare("UPDATE orders SET stripe_checkout_session_id=?, status='in_progress', paid=1 WHERE id=?")
      .run(session.id, order.id);
    res.redirect(session.url);
  }).catch(err => {
    console.error(err);
    flash(res,"err","Payment setup failed.");
    res.redirect(`/orders/${order.id}`);
  });
});

app.post("/orders/:id/deliver", requireAuth, requireRole("creator"), (req, res) => {
  const order = orderForUser(req.params.id, req.user.id);
  if (!order || order.creator_id !== req.user.id) return res.status(404).send("Not found");
  if (order.status !== "in_progress") { flash(res,"err","Order not in progress."); return res.redirect(`/orders/${order.id}`); }
  const link = (req.body.delivery_link || "").trim();
  if (!link.startsWith("http")) { flash(res,"err","Provide a valid link."); return res.redirect(`/orders/${order.id}`); }
  db.prepare("INSERT INTO deliverables (id,order_id,submitted_by,delivery_link,notes,created_at) VALUES (?,?,?,?,?,?)")
    .run(nanoid(), order.id, req.user.id, link, (req.body.notes||"").trim() || null, new Date().toISOString());
  db.prepare("UPDATE orders SET status='delivered' WHERE id=?").run(order.id);
  flash(res,"ok","Deliverable submitted.");
  res.redirect(`/orders/${order.id}`);
});

app.post("/orders/:id/complete", requireAuth, (req, res) => {
  const order = orderForUser(req.params.id, req.user.id);
  if (!order || order.client_id !== req.user.id) return res.status(404).send("Not found");
  if (order.status !== "delivered") { flash(res,"err","Not delivered yet."); return res.redirect(`/orders/${order.id}`); }
  db.prepare("UPDATE orders SET status='completed' WHERE id=?").run(order.id);
  flash(res,"ok","Order completed.");
  res.redirect(`/orders/${order.id}`);
});

app.post("/orders/:id/review", requireAuth, (req, res) => {
  const order = orderForUser(req.params.id, req.user.id);
  if (!order || order.client_id !== req.user.id) return res.status(404).send("Not found");
  const rating = Number(req.body.rating);
  if (!rating || rating < 1 || rating > 5) { flash(res,"err","Rating must be 1-5."); return res.redirect(`/orders/${order.id}`); }
  try {
    db.prepare("INSERT INTO reviews (id,order_id,client_id,creator_id,rating,comment,created_at) VALUES (?,?,?,?,?,?,?)")
      .run(nanoid(), order.id, order.client_id, order.creator_id, rating, (req.body.comment||"").trim() || null, new Date().toISOString());
    flash(res,"ok","Review saved.");
  } catch {
    flash(res,"err","Review already exists for this order.");
  }
  res.redirect(`/orders/${order.id}`);
});

// Reports
app.post("/reports", requireAuth, (req, res) => {
  const { order_id, reported_user_id, reason } = req.body;
  if (!reason) { flash(res,"err","Reason required."); return res.redirect("/dashboard"); }
  db.prepare("INSERT INTO reports (id,order_id,reporter_id,reported_user_id,reason,created_at,resolved) VALUES (?,?,?,?,?,?,0)")
    .run(nanoid(), order_id || null, req.user.id, reported_user_id || null, reason.trim(), new Date().toISOString());
  flash(res,"ok","Report submitted.");
  res.redirect(order_id ? `/orders/${order_id}` : "/dashboard");
});

// Admin
app.get("/admin/reports", requireAuth, requireRole("admin"), (req, res) => {
  const reports = db.prepare("SELECT * FROM reports ORDER BY created_at DESC").all();
  res.render("admin_reports", { title: "Reports", reports });
});
app.post("/admin/reports/resolve", requireAuth, requireRole("admin"), (req, res) => {
  db.prepare("UPDATE reports SET resolved=1 WHERE id=?").run(req.body.id);
  flash(res,"ok","Resolved.");
  res.redirect("/admin/reports");
});

app.use((err, req, res, next) => {
  if (err.code === "EBADCSRFTOKEN") {
    flash(res, "err", "Session expired. Please try again.");
    return res.redirect("back");
  }
  console.error(err);
  res.status(500).send("Server error");
});

const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, () => console.log(`✅ Skillstarter running on ${SITE_URL} (port ${PORT})`));
