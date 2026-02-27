/// <reference types="@cloudflare/workers-types" />
import { DurableObject } from "cloudflare:workers";

// ─── Types ───────────────────────────────────────────────────────────────────

interface Env {
  LEDGER: DurableObjectNamespace<LedgerDO>;
  TWITTER_CLIENT_ID: string;
  TWITTER_CLIENT_SECRET: string;
  STRIPE_SECRET_KEY: string;
  STRIPE_WEBHOOK_SECRET: string;
  JWT_SECRET: string;
}

interface JWTPayload {
  sub: string; // twitter user id
  username: string;
  name: string;
  exp: number;
}

// ─── JWT Helpers ─────────────────────────────────────────────────────────────

async function signJWT(payload: JWTPayload, secret: string): Promise<string> {
  const header = { alg: "HS256", typ: "JWT" };
  const enc = (obj: any) =>
    btoa(JSON.stringify(obj))
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");
  const unsigned = `${enc(header)}.${enc(payload)}`;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(unsigned)
  );
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
  return `${unsigned}.${sigB64}`;
}

async function verifyJWT(
  token: string,
  secret: string
): Promise<JWTPayload | null> {
  try {
    const [headerB64, payloadB64, sigB64] = token.split(".");
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );
    const sigStr = atob(
      sigB64.replace(/-/g, "+").replace(/_/g, "/") +
        "==".slice(0, (4 - (sigB64.length % 4)) % 4)
    );
    const sig = new Uint8Array([...sigStr].map((c) => c.charCodeAt(0)));
    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      sig,
      new TextEncoder().encode(`${headerB64}.${payloadB64}`)
    );
    if (!valid) return null;
    const payload = JSON.parse(
      atob(
        payloadB64.replace(/-/g, "+").replace(/_/g, "/") +
          "==".slice(0, (4 - (payloadB64.length % 4)) % 4)
      )
    );
    if (payload.exp < Date.now() / 1000) return null;
    return payload;
  } catch {
    return null;
  }
}

function getCookie(req: Request, name: string): string | null {
  const cookies = req.headers.get("cookie") || "";
  const match = cookies.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

async function getUser(req: Request, env: Env): Promise<JWTPayload | null> {
  const token = getCookie(req, "session");
  if (!token) return null;
  return verifyJWT(token, env.JWT_SECRET);
}

// ─── Stripe Helpers ──────────────────────────────────────────────────────────

async function stripeRequest(
  env: Env,
  method: string,
  path: string,
  body?: Record<string, string>
): Promise<any> {
  const url = `https://api.stripe.com/v1${path}`;
  const headers: Record<string, string> = {
    Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`
  };
  let init: RequestInit = { method, headers };
  if (body) {
    headers["Content-Type"] = "application/x-www-form-urlencoded";
    init.body = new URLSearchParams(body).toString();
  }
  const res = await fetch(url, init);
  return res.json();
}

async function verifyStripeWebhook(
  req: Request,
  secret: string
): Promise<{ valid: boolean; event?: any }> {
  const body = await req.text();
  const sig = req.headers.get("stripe-signature") || "";
  const parts: Record<string, string> = {};
  for (const part of sig.split(",")) {
    const [k, v] = part.split("=");
    parts[k.trim()] = v.trim();
  }
  const timestamp = parts["t"];
  const v1 = parts["v1"];
  if (!timestamp || !v1) return { valid: false };

  // Check timestamp is within 5 minutes
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - parseInt(timestamp)) > 300) return { valid: false };

  const payload = `${timestamp}.${body}`;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const mac = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(payload)
  );
  const expected = [...new Uint8Array(mac)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  if (expected !== v1) return { valid: false };

  return { valid: true, event: JSON.parse(body) };
}

// ─── Twitter API Helpers ─────────────────────────────────────────────────

async function lookupTwitterUsername(
  accessToken: string,
  username: string
): Promise<{ id: string; username: string; name: string } | null> {
  const res = await fetch(
    `https://api.twitter.com/2/users/by/username/${encodeURIComponent(username)}`,
    { headers: { Authorization: `Bearer ${accessToken}` } }
  );
  if (!res.ok) return null;
  const data: any = await res.json();
  if (data.errors || !data.data) return null;
  return { id: data.data.id, username: data.data.username, name: data.data.name };
}

// ─── PKCE Helpers ────────────────────────────────────────────────────────────

function generateCodeVerifier(): string {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return btoa(String.fromCharCode(...arr))
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

async function generateCodeChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier)
  );
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

// ─── Durable Object: Global Ledger ──────────────────────────────────────────

export class LedgerDO extends DurableObject<Env> {
  private sql: SqlStorage;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS users (
        twitter_id TEXT PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL,
        balance_cents INTEGER NOT NULL DEFAULT 0,
        stripe_connect_id TEXT,
        stripe_connect_ready INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE TABLE IF NOT EXISTS transactions (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        from_user TEXT,
        to_user TEXT,
        amount_cents INTEGER NOT NULL,
        description TEXT,
        stripe_session_id TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE TABLE IF NOT EXISTS oauth_states (
        state TEXT PRIMARY KEY,
        code_verifier TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
      CREATE INDEX IF NOT EXISTS idx_tx_from ON transactions(from_user);
      CREATE INDEX IF NOT EXISTS idx_tx_to ON transactions(to_user);
    `);
    // Migration: add twitter_access_token column
    try {
      this.sql.exec("ALTER TABLE users ADD COLUMN twitter_access_token TEXT");
    } catch { /* column already exists */ }
  }

  // ── OAuth state management ──

  async storeOAuthState(state: string, codeVerifier: string) {
    this.sql.exec(
      "INSERT OR REPLACE INTO oauth_states (state, code_verifier) VALUES (?, ?)",
      state,
      codeVerifier
    );
  }

  async getOAuthState(state: string): Promise<string | null> {
    const rows = [
      ...this.sql.exec(
        "SELECT code_verifier FROM oauth_states WHERE state = ?",
        state
      )
    ];
    if (rows.length === 0) return null;
    this.sql.exec("DELETE FROM oauth_states WHERE state = ?", state);
    // Clean old states
    this.sql.exec(
      "DELETE FROM oauth_states WHERE created_at < datetime('now', '-10 minutes')"
    );
    return rows[0].code_verifier as string;
  }

  // ── User management ──

  async upsertUser(twitterId: string, username: string, displayName: string, accessToken?: string) {
    const existing = [
      ...this.sql.exec(
        "SELECT twitter_id FROM users WHERE twitter_id = ?",
        twitterId
      )
    ];
    if (existing.length === 0) {
      this.sql.exec(
        "INSERT INTO users (twitter_id, username, display_name, twitter_access_token) VALUES (?, ?, ?, ?)",
        twitterId,
        username.toLowerCase(),
        displayName,
        accessToken || null
      );
    } else {
      if (accessToken) {
        this.sql.exec(
          "UPDATE users SET username = ?, display_name = ?, twitter_access_token = ? WHERE twitter_id = ?",
          username.toLowerCase(),
          displayName,
          accessToken,
          twitterId
        );
      } else {
        this.sql.exec(
          "UPDATE users SET username = ?, display_name = ? WHERE twitter_id = ?",
          username.toLowerCase(),
          displayName,
          twitterId
        );
      }
    }
  }

  async getUser(twitterId: string): Promise<any> {
    const rows = [
      ...this.sql.exec("SELECT * FROM users WHERE twitter_id = ?", twitterId)
    ];
    return rows[0] || null;
  }

  async getUserByUsername(username: string): Promise<any> {
    const rows = [
      ...this.sql.exec(
        "SELECT * FROM users WHERE username = ?",
        username.toLowerCase()
      )
    ];
    return rows[0] || null;
  }

  async getAllUsers(): Promise<any[]> {
    return [
      ...this.sql.exec(
        "SELECT twitter_id, username, display_name, balance_cents, created_at FROM users ORDER BY created_at DESC"
      )
    ];
  }

  async ensureUser(twitterId: string, username: string, displayName: string) {
    const existing = [
      ...this.sql.exec(
        "SELECT twitter_id FROM users WHERE twitter_id = ?",
        twitterId
      )
    ];
    if (existing.length === 0) {
      this.sql.exec(
        "INSERT INTO users (twitter_id, username, display_name) VALUES (?, ?, ?)",
        twitterId,
        username.toLowerCase(),
        displayName
      );
    }
  }

  // ── Deposits ──

  async creditDeposit(
    twitterId: string,
    amountCents: number,
    stripeSessionId: string
  ) {
    // Idempotency check
    const existing = [
      ...this.sql.exec(
        "SELECT id FROM transactions WHERE stripe_session_id = ?",
        stripeSessionId
      )
    ];
    if (existing.length > 0) return { already: true };

    const txId = crypto.randomUUID();
    this.sql.exec(
      "UPDATE users SET balance_cents = balance_cents + ? WHERE twitter_id = ?",
      amountCents,
      twitterId
    );
    this.sql.exec(
      `INSERT INTO transactions (id, type, to_user, amount_cents, description, stripe_session_id)
       VALUES (?, 'deposit', ?, ?, 'Stripe deposit', ?)`,
      txId,
      twitterId,
      amountCents,
      stripeSessionId
    );
    return { already: false, txId };
  }

  // ── Send money ──

  async sendMoney(
    fromId: string,
    toUsername: string,
    amountCents: number,
    note: string
  ): Promise<{ ok: boolean; error?: string }> {
    if (amountCents <= 0)
      return { ok: false, error: "Amount must be positive" };

    const sender = [
      ...this.sql.exec("SELECT * FROM users WHERE twitter_id = ?", fromId)
    ];
    if (sender.length === 0) return { ok: false, error: "Sender not found" };
    if ((sender[0].balance_cents as number) < amountCents) {
      return { ok: false, error: "Insufficient balance" };
    }

    const recipient = [
      ...this.sql.exec(
        "SELECT * FROM users WHERE username = ?",
        toUsername.toLowerCase()
      )
    ];
    if (recipient.length === 0)
      return { ok: false, error: "Recipient not found" };
    if (recipient[0].twitter_id === fromId)
      return { ok: false, error: "Cannot send to yourself" };

    const txId = crypto.randomUUID();
    this.sql.exec(
      "UPDATE users SET balance_cents = balance_cents - ? WHERE twitter_id = ?",
      amountCents,
      fromId
    );
    this.sql.exec(
      "UPDATE users SET balance_cents = balance_cents + ? WHERE twitter_id = ?",
      amountCents,
      recipient[0].twitter_id as string
    );
    this.sql.exec(
      `INSERT INTO transactions (id, type, from_user, to_user, amount_cents, description)
       VALUES (?, 'transfer', ?, ?, ?, ?)`,
      txId,
      fromId,
      recipient[0].twitter_id as string,
      amountCents,
      note || `Payment to @${toUsername}`
    );
    return { ok: true };
  }

  // ── Stripe Connect ──

  async setStripeConnectId(twitterId: string, connectId: string) {
    this.sql.exec(
      "UPDATE users SET stripe_connect_id = ? WHERE twitter_id = ?",
      connectId,
      twitterId
    );
  }

  async setStripeConnectReady(twitterId: string) {
    this.sql.exec(
      "UPDATE users SET stripe_connect_ready = 1 WHERE twitter_id = ?",
      twitterId
    );
  }

  // ── Withdraw ──

  async debitWithdraw(
    twitterId: string,
    amountCents: number
  ): Promise<{ ok: boolean; error?: string; connectId?: string }> {
    if (amountCents <= 0)
      return { ok: false, error: "Amount must be positive" };
    if (amountCents < 100)
      return { ok: false, error: "Minimum withdrawal is $1.00" };

    const user = [
      ...this.sql.exec("SELECT * FROM users WHERE twitter_id = ?", twitterId)
    ];
    if (user.length === 0) return { ok: false, error: "User not found" };
    if (!user[0].stripe_connect_id || !user[0].stripe_connect_ready) {
      return { ok: false, error: "Stripe Connect not set up" };
    }
    if ((user[0].balance_cents as number) < amountCents) {
      return { ok: false, error: "Insufficient balance" };
    }

    const txId = crypto.randomUUID();
    this.sql.exec(
      "UPDATE users SET balance_cents = balance_cents - ? WHERE twitter_id = ?",
      amountCents,
      twitterId
    );
    this.sql.exec(
      `INSERT INTO transactions (id, type, from_user, amount_cents, description)
       VALUES (?, 'withdrawal', ?, ?, 'Payout to bank')`,
      txId,
      twitterId,
      amountCents
    );
    return { ok: true, connectId: user[0].stripe_connect_id as string };
  }

  // ── Transaction history ──

  async getTransactions(twitterId: string, limit = 50): Promise<any[]> {
    return [
      ...this.sql.exec(
        `SELECT t.*,
           su.username as from_username,
           ru.username as to_username
         FROM transactions t
         LEFT JOIN users su ON t.from_user = su.twitter_id
         LEFT JOIN users ru ON t.to_user = ru.twitter_id
         WHERE t.from_user = ? OR t.to_user = ?
         ORDER BY t.created_at DESC LIMIT ?`,
        twitterId,
        twitterId,
        limit
      )
    ];
  }
}

// ─── Worker (Router) ─────────────────────────────────────────────────────────

function getLedger(env: Env): DurableObjectStub<LedgerDO> {
  const id = env.LEDGER.idFromName("global");
  return env.LEDGER.get(id);
}

function json(
  data: any,
  status = 200,
  headers?: Record<string, string>
): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...headers }
  });
}

function html(
  body: string,
  status = 200,
  extraHeaders?: Record<string, string>
): Response {
  return new Response(body, {
    status,
    headers: { "Content-Type": "text/html;charset=utf-8", ...extraHeaders }
  });
}

export default {
  async fetch(
    req: Request,
    env: Env,
    ctx: ExecutionContext
  ): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname;
    const ledger = getLedger(env);

    // ── Static pages ──

    if (path === "/" && req.method === "GET") {
      const user = await getUser(req, env);
      if (!user) {
        return html(renderLogin(env));
      }
      const dbUser = await ledger.getUser(user.sub);

      // Sync Connect status from Stripe if we have an account but it's not marked ready
      if (dbUser?.stripe_connect_id && !dbUser.stripe_connect_ready) {
        const account = await stripeRequest(env, "GET", `/accounts/${dbUser.stripe_connect_id}`);
        if (account.charges_enabled && account.payouts_enabled) {
          await ledger.setStripeConnectReady(user.sub);
          dbUser.stripe_connect_ready = 1;
        }
      }

      const transactions = await ledger.getTransactions(user.sub);
      const allUsers = await ledger.getAllUsers();
      return html(renderDashboard(user, dbUser, transactions, allUsers, env));
    }

    // ── Twitter OAuth ──

    if (path === "/auth/twitter" && req.method === "GET") {
      const state = crypto.randomUUID();
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = await generateCodeChallenge(codeVerifier);

      await ledger.storeOAuthState(state, codeVerifier);

      const params = new URLSearchParams({
        response_type: "code",
        client_id: env.TWITTER_CLIENT_ID,
        redirect_uri: `${url.origin}/auth/twitter/callback`,
        scope: "tweet.read users.read",
        state,
        code_challenge: codeChallenge,
        code_challenge_method: "S256"
      });
      return Response.redirect(
        `https://twitter.com/i/oauth2/authorize?${params}`,
        302
      );
    }

    if (path === "/auth/twitter/callback" && req.method === "GET") {
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");
      if (!code || !state) return json({ error: "Missing params" }, 400);

      const codeVerifier = await ledger.getOAuthState(state);
      if (!codeVerifier) return json({ error: "Invalid state" }, 400);

      // Exchange code for token
      const tokenRes = await fetch("https://api.twitter.com/2/oauth2/token", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `Basic ${btoa(`${env.TWITTER_CLIENT_ID}:${env.TWITTER_CLIENT_SECRET}`)}`
        },
        body: new URLSearchParams({
          code,
          grant_type: "authorization_code",
          redirect_uri: `${url.origin}/auth/twitter/callback`,
          code_verifier: codeVerifier
        })
      });
      const tokenData: any = await tokenRes.json();
      if (!tokenData.access_token) {
        return json(
          { error: "Token exchange failed", details: tokenData },
          400
        );
      }

      // Get user info
      const userRes = await fetch("https://api.twitter.com/2/users/me", {
        headers: { Authorization: `Bearer ${tokenData.access_token}` }
      });
      const userData: any = await userRes.json();
      const twUser = userData.data;

      // Upsert user in DB (store access token for X API lookups)
      await ledger.upsertUser(twUser.id, twUser.username, twUser.name, tokenData.access_token);

      // Create JWT session
      const jwt = await signJWT(
        {
          sub: twUser.id,
          username: twUser.username,
          name: twUser.name,
          exp: Math.floor(Date.now() / 1000) + 7 * 24 * 3600
        },
        env.JWT_SECRET
      );

      return new Response(null, {
        status: 302,
        headers: {
          Location: "/",
          "Set-Cookie": `session=${jwt}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${7 * 24 * 3600}`
        }
      });
    }

    if (path === "/auth/logout") {
      return new Response(null, {
        status: 302,
        headers: {
          Location: "/",
          "Set-Cookie":
            "session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
        }
      });
    }

    // ── Deposit (create Stripe Checkout Session) ──

    if (path === "/api/deposit" && req.method === "POST") {
      const user = await getUser(req, env);
      if (!user) return json({ error: "Not authenticated" }, 401);

      const body: any = await req.json();
      const amountCents = Math.round(parseFloat(body.amount) * 100);
      if (!amountCents || amountCents < 100)
        return json({ error: "Minimum $1.00" }, 400);
      if (amountCents > 99999) return json({ error: "Maximum $999.99" }, 400);

      const session = await stripeRequest(env, "POST", "/checkout/sessions", {
        mode: "payment",
        "line_items[0][price_data][currency]": "usd",
        "line_items[0][price_data][unit_amount]": amountCents.toString(),
        "line_items[0][price_data][product_data][name]": "Wallet Deposit",
        "line_items[0][quantity]": "1",
        success_url: `${url.origin}/?deposit=success`,
        cancel_url: `${url.origin}/?deposit=cancelled`,
        "metadata[twitter_id]": user.sub,
        "metadata[type]": "deposit"
      });

      return json({ url: session.url });
    }

    // ── Stripe Webhook ──

    if (path === "/webhook/stripe" && req.method === "POST") {
      const { valid, event } = await verifyStripeWebhook(
        req,
        env.STRIPE_WEBHOOK_SECRET
      );
      if (!valid) return json({ error: "Invalid signature" }, 400);

      if (event.type === "checkout.session.completed") {
        const session = event.data.object;
        if (
          session.metadata?.type === "deposit" &&
          session.payment_status === "paid"
        ) {
          const twitterId = session.metadata.twitter_id;
          const amountCents = session.amount_total;
          await ledger.creditDeposit(twitterId, amountCents, session.id);
        }
      }

      if (event.type === "account.updated") {
        const account = event.data.object;
        if (account.charges_enabled && account.payouts_enabled) {
          // Find user by connect id and mark ready
          // We store metadata when creating the account
          if (account.metadata?.twitter_id) {
            await ledger.setStripeConnectReady(account.metadata.twitter_id);
          }
        }
      }

      return json({ received: true });
    }

    // ── Send Money ──

    if (path === "/api/send" && req.method === "POST") {
      const user = await getUser(req, env);
      if (!user) return json({ error: "Not authenticated" }, 401);

      const body: any = await req.json();
      const toUsername = (body.to || "").trim().replace(/^@/, "");
      const amountCents = Math.round(parseFloat(body.amount) * 100);
      const note = body.note || "";

      if (!toUsername)
        return json({ error: "Recipient username required" }, 400);
      if (!amountCents || amountCents < 1)
        return json({ error: "Amount must be positive" }, 400);

      // Check if recipient exists in DB; if not, verify via X API and create
      const existingRecipient = await ledger.getUserByUsername(toUsername);
      if (!existingRecipient) {
        const senderDb = await ledger.getUser(user.sub);
        const accessToken = senderDb?.twitter_access_token;
        if (!accessToken) {
          return json({ error: "Please log out and log in again to enable sending to new users" }, 400);
        }
        try {
          const xUser = await lookupTwitterUsername(accessToken, toUsername);
          if (!xUser) {
            return json({ error: `@${toUsername} does not exist on X` }, 400);
          }
          await ledger.ensureUser(xUser.id, xUser.username, xUser.name);
        } catch (e: any) {
          return json({ error: "Failed to verify X username: " + e.message }, 500);
        }
      }

      const result = await ledger.sendMoney(
        user.sub,
        toUsername,
        amountCents,
        note
      );
      if (!result.ok) return json({ error: result.error }, 400);
      return json({ ok: true });
    }

    // ── Stripe Connect Onboarding ──

    if (path === "/api/connect/onboard" && req.method === "POST") {
      const user = await getUser(req, env);
      if (!user) return json({ error: "Not authenticated" }, 401);

      try {
        const dbUser = await ledger.getUser(user.sub);
        let connectId = dbUser?.stripe_connect_id;

        if (!connectId) {
          // Create Express account
          const account = await stripeRequest(env, "POST", "/accounts", {
            type: "express",
            "metadata[twitter_id]": user.sub,
            "metadata[username]": user.username
          });
          if (account.error) {
            return json({ error: account.error.message || "Failed to create Stripe account" }, 400);
          }
          connectId = account.id;
          await ledger.setStripeConnectId(user.sub, connectId);
        }

        // Create account link
        const link = await stripeRequest(env, "POST", "/account_links", {
          account: connectId,
          refresh_url: `${url.origin}/?connect=refresh`,
          return_url: `${url.origin}/?connect=success`,
          type: "account_onboarding"
        });
        if (link.error) {
          return json({ error: link.error.message || "Failed to create onboarding link" }, 400);
        }

        return json({ url: link.url });
      } catch (e: any) {
        return json({ error: e.message || "Unexpected error during Connect setup" }, 500);
      }
    }

    // ── Withdraw ──

    if (path === "/api/withdraw" && req.method === "POST") {
      const user = await getUser(req, env);
      if (!user) return json({ error: "Not authenticated" }, 401);

      const body: any = await req.json();
      const amountCents = Math.round(parseFloat(body.amount) * 100);
      if (!amountCents || amountCents < 100)
        return json({ error: "Minimum $1.00" }, 400);

      const result = await ledger.debitWithdraw(user.sub, amountCents);
      if (!result.ok) return json({ error: result.error }, 400);

      // Create transfer to connected account
      const transfer = await stripeRequest(env, "POST", "/transfers", {
        amount: amountCents.toString(),
        currency: "usd",
        destination: result.connectId!,
        "metadata[twitter_id]": user.sub
      });

      if (transfer.error) {
        // Rollback — re-credit the balance
        // In production you'd want a more robust saga pattern
        await ledger.creditDeposit(
          user.sub,
          amountCents,
          `rollback-${crypto.randomUUID()}`
        );
        return json({ error: `Stripe error: ${transfer.error.message}` }, 500);
      }

      return json({ ok: true, transfer_id: transfer.id });
    }

    // ── All Users API ──

    if (path === "/api/users" && req.method === "GET") {
      const user = await getUser(req, env);
      if (!user) return json({ error: "Not authenticated" }, 401);
      const users = await ledger.getAllUsers();
      return json({ users });
    }

    // ── Balance API ──

    if (path === "/api/balance" && req.method === "GET") {
      const user = await getUser(req, env);
      if (!user) return json({ error: "Not authenticated" }, 401);
      const dbUser = await ledger.getUser(user.sub);

      // Sync Connect status from Stripe if pending
      if (dbUser?.stripe_connect_id && !dbUser.stripe_connect_ready) {
        const account = await stripeRequest(env, "GET", `/accounts/${dbUser.stripe_connect_id}`);
        if (account.charges_enabled && account.payouts_enabled) {
          await ledger.setStripeConnectReady(user.sub);
          dbUser.stripe_connect_ready = 1;
        }
      }

      return json({
        balance_cents: dbUser?.balance_cents || 0,
        stripe_connect_ready: !!dbUser?.stripe_connect_ready
      });
    }

    return json({ error: "Not found" }, 404);
  }
} satisfies ExportedHandler<Env>;

// ─── HTML Templates ──────────────────────────────────────────────────────────

function renderLogin(env: Env): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>P2P Pay</title>
  <style>${CSS}</style>
</head>
<body>
  <div class="container">
    <div class="card" style="text-align:center;margin-top:15vh">
      <h1>💸 P2P Pay</h1>
      <p class="muted">Send money to anyone on X, instantly.</p>
      <a href="/auth/twitter" class="btn btn-primary" style="display:inline-block;margin-top:1.5rem;font-size:1.1rem">
        Sign in with 𝕏
      </a>
    </div>
  </div>
</body>
</html>`;
}

function renderDashboard(
  user: JWTPayload,
  dbUser: any,
  transactions: any[],
  allUsers: any[],
  env: Env
): string {
  const balance = ((dbUser?.balance_cents || 0) / 100).toFixed(2);
  const connectReady = !!dbUser?.stripe_connect_ready;
  const hasConnect = !!dbUser?.stripe_connect_id;

  const txRows = transactions
    .map((tx: any) => {
      const isDeposit = tx.type === "deposit";
      const isWithdrawal = tx.type === "withdrawal";
      const isSender = tx.from_user === user.sub;
      const sign = isDeposit || (!isSender && !isWithdrawal) ? "+" : "-";
      const color = sign === "+" ? "var(--green)" : "var(--red)";
      const amount = (tx.amount_cents / 100).toFixed(2);
      let desc = tx.description || tx.type;
      if (tx.type === "transfer") {
        desc = isSender
          ? `Sent to @${tx.to_username}`
          : `Received from @${tx.from_username}`;
      }
      return `<div class="tx-row">
        <div>
          <div class="tx-desc">${escHtml(desc)}</div>
          <div class="tx-date">${tx.created_at}</div>
        </div>
        <div class="tx-amount" style="color:${color}">${sign}$${amount}</div>
      </div>`;
    })
    .join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>P2P Pay — Dashboard</title>
  <style>${CSS}</style>
</head>
<body>
  <div class="container">
    <header class="header">
      <h1>💸 P2P Pay</h1>
      <div>
        <span class="muted">@${escHtml(user.username)}</span>
        <a href="/auth/logout" class="btn btn-sm">Logout</a>
      </div>
    </header>

    <div class="card balance-card">
      <div class="muted">Your Balance</div>
      <div class="balance" id="balance">$${balance}</div>
    </div>

    <div class="grid">
      <div class="card">
        <h3>💰 Deposit</h3>
        <div class="form-group">
          <label>Amount (USD)</label>
          <input type="number" id="deposit-amount" min="1" max="999.99" step="0.01" placeholder="10.00">
        </div>
        <button class="btn btn-primary" onclick="deposit()">Deposit via Stripe</button>
        <div id="deposit-msg" class="msg"></div>
      </div>

      <div class="card">
        <h3>📤 Send Money</h3>
        <div class="form-group">
          <label>Recipient (X username)</label>
          <input type="text" id="send-to" placeholder="@username">
        </div>
        <div class="form-group">
          <label>Amount (USD)</label>
          <input type="number" id="send-amount" min="0.01" step="0.01" placeholder="5.00">
        </div>
        <div class="form-group">
          <label>Note (optional)</label>
          <input type="text" id="send-note" placeholder="For lunch 🍕">
        </div>
        <button class="btn btn-primary" onclick="sendMoney()">Send</button>
        <div id="send-msg" class="msg"></div>
      </div>
    </div>

    <div class="card">
      <h3>🏦 Withdraw</h3>
      ${
        !hasConnect
          ? `<p class="muted">Connect your bank account to withdraw funds.</p>
             <button class="btn btn-primary" onclick="connectStripe()">Set up Stripe Connect</button>`
          : !connectReady
            ? `<p class="muted">Your Stripe Connect account is pending verification.</p>
             <button class="btn" onclick="connectStripe()">Continue Setup</button>`
            : `<div class="form-group" style="display:flex;gap:0.5rem;align-items:end">
               <div style="flex:1">
                 <label>Amount (USD)</label>
                 <input type="number" id="withdraw-amount" min="1" step="0.01" placeholder="10.00">
               </div>
               <button class="btn btn-primary" onclick="withdraw()">Withdraw</button>
             </div>`
      }
      <div id="withdraw-msg" class="msg"></div>
    </div>

    <div class="card">
      <h3>📜 Transactions</h3>
      ${txRows || '<p class="muted">No transactions yet.</p>'}
    </div>

    <div class="card">
      <h3>👥 All Users</h3>
      ${
        allUsers.length === 0
          ? '<p class="muted">No users yet.</p>'
          : `<div class="users-table">
              <div class="users-header">
                <span>User</span>
                <span style="text-align:right">Balance</span>
              </div>
              ${allUsers
                .map(
                  (u: any) =>
                    `<div class="user-row">
                      <div>
                        <span class="user-display">${escHtml(u.display_name)}</span>
                        <span class="muted"> @${escHtml(u.username)}</span>
                      </div>
                      <div class="user-balance">$${(u.balance_cents / 100).toFixed(2)}</div>
                    </div>`
                )
                .join("")}
            </div>`
      }
    </div>
  </div>

  <script>
    async function apiPost(url, body) {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      return res.json();
    }

    async function deposit() {
      const amount = document.getElementById('deposit-amount').value;
      const msg = document.getElementById('deposit-msg');
      if (!amount) { msg.textContent = 'Enter an amount'; return; }
      msg.textContent = 'Redirecting to Stripe...';
      const data = await apiPost('/api/deposit', { amount });
      if (data.url) window.location.href = data.url;
      else msg.textContent = data.error || 'Error';
    }

    async function sendMoney() {
      const to = document.getElementById('send-to').value;
      const amount = document.getElementById('send-amount').value;
      const note = document.getElementById('send-note').value;
      const msg = document.getElementById('send-msg');
      if (!to || !amount) { msg.textContent = 'Fill in recipient and amount'; return; }
      msg.textContent = 'Sending...';
      const data = await apiPost('/api/send', { to, amount, note });
      if (data.ok) {
        msg.style.color = 'var(--green)';
        msg.textContent = 'Sent!';
        setTimeout(() => location.reload(), 1000);
      } else {
        msg.style.color = 'var(--red)';
        msg.textContent = data.error || 'Error';
      }
    }

    async function connectStripe() {
      const msg = document.getElementById('withdraw-msg');
      msg.style.color = '';
      msg.textContent = 'Redirecting to Stripe...';
      try {
        const data = await apiPost('/api/connect/onboard', {});
        if (data.url) window.location.href = data.url;
        else {
          msg.style.color = 'var(--red)';
          msg.textContent = data.error || 'Unknown error — no onboarding URL returned';
        }
      } catch (e) {
        msg.style.color = 'var(--red)';
        msg.textContent = 'Network error: ' + e.message;
      }
    }

    async function withdraw() {
      const amount = document.getElementById('withdraw-amount').value;
      const msg = document.getElementById('withdraw-msg');
      if (!amount) { msg.textContent = 'Enter an amount'; return; }
      msg.textContent = 'Processing...';
      const data = await apiPost('/api/withdraw', { amount });
      if (data.ok) {
        msg.style.color = 'var(--green)';
        msg.textContent = 'Withdrawal initiated! ✅';
        setTimeout(() => location.reload(), 1500);
      } else {
        msg.style.color = 'var(--red)';
        msg.textContent = data.error || 'Error';
      }
    }
  </script>
</body>
</html>`;
}

function escHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

const CSS = `
  :root {
    --bg: #0a0a0a; --card: #141414; --border: #222; --text: #e5e5e5;
    --muted: #888; --primary: #3b82f6; --primary-hover: #2563eb;
    --green: #22c55e; --red: #ef4444;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }
  .container { max-width: 680px; margin: 0 auto; padding: 1.5rem; }
  .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; }
  .header h1 { font-size: 1.3rem; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; margin-bottom: 1rem; }
  .balance-card { text-align: center; }
  .balance { font-size: 2.5rem; font-weight: 700; margin-top: 0.25rem; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
  @media (max-width: 600px) { .grid { grid-template-columns: 1fr; } }
  h3 { margin-bottom: 1rem; font-size: 1rem; }
  .form-group { margin-bottom: 0.75rem; }
  .form-group label { display: block; font-size: 0.8rem; color: var(--muted); margin-bottom: 0.25rem; }
  input[type="text"], input[type="number"] { width: 100%; padding: 0.6rem 0.75rem; background: var(--bg); border: 1px solid var(--border); border-radius: 8px; color: var(--text); font-size: 0.95rem; }
  input:focus { outline: none; border-color: var(--primary); }
  .btn { display: inline-block; padding: 0.6rem 1.2rem; border: 1px solid var(--border); border-radius: 8px; background: var(--card); color: var(--text); cursor: pointer; font-size: 0.9rem; text-decoration: none; }
  .btn-primary { background: var(--primary); border-color: var(--primary); color: #fff; }
  .btn-primary:hover { background: var(--primary-hover); }
  .btn-sm { padding: 0.3rem 0.7rem; font-size: 0.8rem; }
  .muted { color: var(--muted); }
  .msg { margin-top: 0.5rem; font-size: 0.85rem; min-height: 1.2em; }
  .tx-row { display: flex; justify-content: space-between; align-items: center; padding: 0.75rem 0; border-bottom: 1px solid var(--border); }
  .tx-row:last-child { border-bottom: none; }
  .tx-desc { font-size: 0.9rem; }
  .tx-date { font-size: 0.75rem; color: var(--muted); }
  .tx-amount { font-weight: 600; font-size: 0.95rem; white-space: nowrap; }
  .users-table { }
  .users-header { display: flex; justify-content: space-between; padding: 0.5rem 0; border-bottom: 1px solid var(--border); font-size: 0.8rem; color: var(--muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
  .user-row { display: flex; justify-content: space-between; align-items: center; padding: 0.6rem 0; border-bottom: 1px solid var(--border); }
  .user-row:last-child { border-bottom: none; }
  .user-display { font-size: 0.9rem; }
  .user-balance { font-weight: 600; font-size: 0.95rem; color: var(--green); }
`;
