import Database from "better-sqlite3";
import fs from "fs";

const db = new Database("skillstarter.db");

db.exec(`
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('client','creator','parent','admin')),
  display_name TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS parent_links (
  id TEXT PRIMARY KEY,
  creator_id TEXT NOT NULL,
  parent_id TEXT NOT NULL,
  consented INTEGER NOT NULL DEFAULT 0,
  consented_at TEXT,
  UNIQUE(creator_id, parent_id),
  FOREIGN KEY(creator_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(parent_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS listings (
  id TEXT PRIMARY KEY,
  creator_id TEXT NOT NULL,
  category TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  starting_price_gbp INTEGER,
  tags TEXT,
  portfolio_url TEXT,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  FOREIGN KEY(creator_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS orders (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  creator_id TEXT NOT NULL,
  listing_id TEXT,
  status TEXT NOT NULL CHECK(status IN ('requested','accepted','awaiting_parent_consent','awaiting_payment','in_progress','delivered','completed','cancelled','disputed')),
  brief TEXT NOT NULL,
  budget_gbp INTEGER,
  deadline_text TEXT,
  agreed_price_gbp INTEGER,
  stripe_checkout_session_id TEXT,
  paid INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  FOREIGN KEY(client_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(creator_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(listing_id) REFERENCES listings(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  order_id TEXT NOT NULL,
  sender_id TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE,
  FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS deliverables (
  id TEXT PRIMARY KEY,
  order_id TEXT NOT NULL,
  submitted_by TEXT NOT NULL,
  delivery_link TEXT,
  notes TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE,
  FOREIGN KEY(submitted_by) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS reviews (
  id TEXT PRIMARY KEY,
  order_id TEXT UNIQUE NOT NULL,
  client_id TEXT NOT NULL,
  creator_id TEXT NOT NULL,
  rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
  comment TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY,
  order_id TEXT,
  reporter_id TEXT NOT NULL,
  reported_user_id TEXT,
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL,
  resolved INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
`);

console.log("✅ Database initialized: skillstarter.db");

const hasAdmin = db.prepare("SELECT 1 FROM users WHERE role='admin' LIMIT 1").get();
if (!hasAdmin) {
  // Create a default admin for first login (you should change it after)
  // Email: admin@skillstarter.local  Password: Admin123!
  // NOTE: This is for local dev only. Change for production.
  const bcrypt = (await import("bcryptjs")).default;
  const { nanoid } = await import("nanoid");
  const now = new Date().toISOString();
  const hash = bcrypt.hashSync("Admin123!", 10);
  db.prepare("INSERT INTO users (id,email,password_hash,role,display_name,created_at) VALUES (?,?,?,?,?,?)")
    .run(nanoid(), "admin@skillstarter.local", hash, "admin", "Admin", now);
  console.log("✅ Created default admin (local dev): admin@skillstarter.local / Admin123!");
}
