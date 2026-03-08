// server.js — Dalaran backend v2
const express  = require("express");
const cors     = require("cors");
const bcrypt   = require("bcryptjs");
const jwt      = require("jsonwebtoken");
const { Resend } = require("resend");
const crypto = require("crypto");

const {
  insertOrder, getAllOrders, getOrderById, getOrdersByUser, updateOrderStatus,
  createUser, getUserByEmail, getUserById, updateUser,
  addToWishlist, removeFromWishlist, getWishlist, getWishlistItem,
  setResetToken, getUserByToken, clearResetToken,
} = require("./db");
const { buildOrderEmail, buildCustomerEmail } = require("./email");

const app  = express();
const PORT = process.env.PORT || 3000;

const RESEND_API_KEY    = process.env.RESEND_API_KEY;
const ADMIN_KEY        = process.env.ADMIN_KEY; // kept for backward compat
const ADMIN_EMAIL      = process.env.ADMIN_EMAIL || "gonzalo@dalaran.uy";
const ADMIN_PASSWORD   = process.env.ADMIN_PASSWORD; // bcrypt hash or plaintext fallback
const JWT_SECRET       = process.env.JWT_SECRET || "dalaran_jwt_secret_change_me";
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || JWT_SECRET + "_admin";
const FROM_EMAIL       = process.env.FROM_EMAIL || "pedidos@dalaran.uy";
const TO_EMAIL         = process.env.TO_EMAIL   || "gonzalo@dalaran.uy";
const SITE_URL         = process.env.SITE_URL   || "https://dalaran.uy";
const SHIPPING_COST    = 175;

const resend = RESEND_API_KEY ? new Resend(RESEND_API_KEY) : null;

app.use(cors({ origin: true, methods: ["GET","POST","PATCH","PUT","DELETE"] }));
app.use(express.json());

function requireAdmin(req, res, next) {
  // Support both legacy x-admin-key and new JWT
  const legacyOk = ADMIN_KEY && req.headers["x-admin-key"] === ADMIN_KEY;
  if (legacyOk) return next();
  const token = (req.headers["authorization"]||"").replace("Bearer ","");
  if (!token) return res.status(401).json({ error: "No autorizado" });
  try { req.admin = jwt.verify(token, ADMIN_JWT_SECRET); next(); }
  catch(e) { return res.status(401).json({ error: "Token admin inválido" }); }
}

function requireAuth(req, res, next) {
  const token = (req.headers["authorization"]||"").replace("Bearer ","");
  if (!token) return res.status(401).json({ error: "Token requerido" });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch(e) { return res.status(401).json({ error: "Token inválido o expirado" }); }
}

function optionalAuth(req, res, next) {
  const token = (req.headers["authorization"]||"").replace("Bearer ","");
  if (token) { try { req.user = jwt.verify(token, JWT_SECRET); } catch(e) {} }
  next();
}

function validateOrder(body) {
  const e = [];
  if (!body.name    || body.name.trim().length  < 2) e.push("name requerido");
  if (!body.email   || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email)) e.push("email inválido");
  if (!body.phone   || body.phone.trim().length  < 6) e.push("phone requerido");
  if (!body.address || body.address.trim().length < 5) e.push("address requerida");
  if (!Array.isArray(body.items) || !body.items.length) e.push("items requeridos");
  return e;
}

// ── Health ────────────────────────────────────────────────────
app.get("/", (req, res) => res.json({ status:"ok", service:"Dalaran API", version:"2.0.0" }));

// ── Auth ──────────────────────────────────────────────────────
app.post("/api/auth/register", async (req, res) => {
  const { email, password, name, newsletter, terms_accepted } = req.body;
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error:"Email inválido" });
  if (!password || password.length < 6) return res.status(400).json({ error:"Contraseña mínimo 6 caracteres" });
  if (!terms_accepted) return res.status(400).json({ error:"Debés aceptar los términos y condiciones" });
  try {
    if (getUserByEmail.get(email)) return res.status(409).json({ error:"Ya existe una cuenta con ese email" });
    const hash = await bcrypt.hash(password, 10);
    const result = createUser.run({ email:email.trim().toLowerCase(), password:hash, name:(name||"").trim(), phone:"", address:"", newsletter:newsletter?1:0, terms_accepted:1 });
    const user = getUserById.get(result.lastInsertRowid);
    const token = jwt.sign({ id:user.id, email:user.email }, JWT_SECRET, { expiresIn:"30d" });
    res.status(201).json({ token, user });
  } catch(err) { console.error(err); res.status(500).json({ error:"Error al crear la cuenta" }); }
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error:"Email y contraseña requeridos" });
  const user = getUserByEmail.get(email);
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ error:"Email o contraseña incorrectos" });
  const token = jwt.sign({ id:user.id, email:user.email }, JWT_SECRET, { expiresIn:"30d" });
  const { password:_, ...safeUser } = user;
  res.json({ token, user:safeUser });
});

app.get("/api/auth/me", requireAuth, (req, res) => {
  const user = getUserById.get(req.user.id);
  if (!user) return res.status(404).json({ error:"Usuario no encontrado" });
  res.json({ user });
});

app.put("/api/auth/me", requireAuth, (req, res) => {
  const { name, phone, address } = req.body;
  updateUser.run({ id:req.user.id, name:(name||"").trim(), phone:(phone||"").trim(), address:(address||"").trim() });
  res.json({ user: getUserById.get(req.user.id) });
});

// ── Suggestions proxy (CORS fix for cart page) ───────────────
const https = require("https");
const http  = require("http");

function httpsGet(url, redirectCount = 0) {
  return new Promise((resolve, reject) => {
    if (redirectCount > 5) return reject(new Error("Too many redirects"));
    const lib = url.startsWith("https") ? https : http;
    const req = lib.get(url, {
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; Dalaran/1.0)",
        "Accept": "application/json"
      }
    }, (res) => {
      // Follow redirects (301, 302, 307, 308)
      if ([301,302,307,308].includes(res.statusCode) && res.headers.location) {
        const next = res.headers.location.startsWith("http")
          ? res.headers.location
          : new URL(res.headers.location, url).href;
        res.resume();
        return httpsGet(next, redirectCount + 1).then(resolve).catch(reject);
      }
      let data = "";
      res.on("data", chunk => data += chunk);
      res.on("end", () => {
        try { resolve(JSON.parse(data)); }
        catch(e) {
          console.error("JSON parse error for URL:", url, "| Status:", res.statusCode, "| Body preview:", data.slice(0,200));
          reject(new Error("JSON parse error"));
        }
      });
    });
    req.on("error", reject);
    req.setTimeout(12000, () => { req.destroy(); reject(new Error("timeout")); });
  });
}

app.get("/api/suggestions", async (req, res) => {
  try {
    const url = "https://montevideogaminghouse.com/wp-json/wc/store/v1/products?per_page=40&orderby=popularity&order=desc&stock_status=instock";
    const products = await httpsGet(url);
    if (!Array.isArray(products)) return res.json({ products: [] });
    // Shuffle and take 20, apply 1.25x markup
    const shuffled = products.sort(() => Math.random() - 0.5).slice(0, 20);
    const result = shuffled.map(p => {
      const minor = p.prices?.currency_minor_unit ?? 2;
      const raw = Number(p.prices?.price ?? 0) / Math.pow(10, minor);
      const price = Math.round(raw * 1.25);
      return {
        id: p.id,
        name: p.name,
        image: p.images?.[0]?.src || "",
        priceValue: price
      };
    });
    res.json({ products: result });
  } catch(err) {
    console.error("suggestions error:", err.message);
    res.status(500).json({ products: [], error: err.message });
  }
});

// ── MGH Proxy (replaces Cloudflare Worker) ───────────────────
// Proxies WooCommerce store/v1 API from montevideogaminghouse.com server-side,
// bypassing CORS restrictions in browsers.

const MGH_BASE = "https://montevideogaminghouse.com/wp-json/wc/store/v1";

// Categorías a EXCLUIR del catálogo Dalaran (TCG, miniaturas, accesorios, libros, etc.)
const EXCLUDE_CATEGORY_SLUGS = new Set([
  "cartas", "tcg", "miniaturas", "accesorio", "libro", "manual-de-rol",
  "magic-the-gathering", "digimon", "disney-lorcana", "flesh-blood",
  "atrum-arena", "gundam", "40k", "age-of-sigmar", "bolt-action",
  "achtung-panzer", "konflikt-47", "binders", "deckboxs", "ingles"
]);

function isBoardGame(product) {
  const cats = (product.categories || []).map(c => c.slug);
  return !cats.some(s => EXCLUDE_CATEGORY_SLUGS.has(s));
}

app.get("/api/proxy/products/tags", async (req, res) => {
  try {
    const qs = new URLSearchParams(req.query).toString();
    const data = await httpsGet(`${MGH_BASE}/products/tags?${qs}`);
    res.json(data);
  } catch(err) {
    console.error("proxy tags error:", err.message);
    res.status(502).json({ error: "Upstream error", message: err.message });
  }
});

// /api/proxy/products?page=1&per_page=25  → normal single page (for first render)
// /api/proxy/products/all                  → fetches ALL pages in parallel, returns everything
app.get("/api/proxy/products", async (req, res) => {
  try {
    const qs = new URLSearchParams(req.query).toString();
    const data = await httpsGet(`${MGH_BASE}/products?${qs}`);
    if (!Array.isArray(data)) return res.json(data);
    res.json(data.filter(isBoardGame));
  } catch(err) {
    console.error("proxy products error:", err.message);
    res.status(502).json({ error: "Upstream error", message: err.message });
  }
});

app.get("/api/proxy/products/all", async (req, res) => {
  try {
    const stock = req.query.stock_status || "instock";
    const tag   = req.query.tag || "";
    const tagParam = tag ? `&tag=${tag}` : "";
    const PER_PAGE = 100;

    // Fetch page 1 first to find total count
    const first = await httpsGet(`${MGH_BASE}/products?per_page=${PER_PAGE}&page=1&stock_status=${stock}${tagParam}`);
    if (!Array.isArray(first)) return res.json([]);

    // If we got a full page, fetch remaining pages in parallel
    if (first.length === PER_PAGE) {
      // Estimate: fetch up to 20 more pages in parallel (covers 2000+ products)
      const pageNums = [];
      for (let p = 2; p <= 20; p++) pageNums.push(p);

      const rest = await Promise.allSettled(
        pageNums.map(p =>
          httpsGet(`${MGH_BASE}/products?per_page=${PER_PAGE}&page=${p}&stock_status=${stock}${tagParam}`)
        )
      );

      let all = [...first].filter(isBoardGame);
      for (const r of rest) {
        if (r.status === "fulfilled" && Array.isArray(r.value) && r.value.length > 0) {
          all = all.concat(r.value.filter(isBoardGame));
          if (r.value.length < PER_PAGE) break; // last page reached
        }
      }
      return res.json(all);
    }

    res.json(first.filter(isBoardGame));
  } catch(err) {
    console.error("proxy all error:", err.message);
    res.status(502).json({ error: "Upstream error", message: err.message });
  }
});

app.get("/api/proxy/products/:id", async (req, res) => {
  try {
    const data = await httpsGet(`${MGH_BASE}/products/${req.params.id}`);
    res.json(data);
  } catch(err) {
    console.error("proxy product error:", err.message);
    res.status(502).json({ error: "Upstream error", message: err.message });
  }
});

// ── Admin Auth ───────────────────────────────────────────────
app.post("/api/admin/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error:"Email y contraseña requeridos" });
  if (email.toLowerCase() !== ADMIN_EMAIL.toLowerCase())
    return res.status(401).json({ error:"Credenciales incorrectas" });
  // ADMIN_PASSWORD can be a bcrypt hash or plaintext (for initial setup)
  let ok = false;
  if (ADMIN_PASSWORD) {
    if (ADMIN_PASSWORD.startsWith("$2")) {
      ok = await bcrypt.compare(password, ADMIN_PASSWORD);
    } else {
      ok = password === ADMIN_PASSWORD; // plaintext fallback
    }
  } else if (ADMIN_KEY) {
    ok = password === ADMIN_KEY; // legacy: use ADMIN_KEY as password
  }
  if (!ok) return res.status(401).json({ error:"Credenciales incorrectas" });
  const token = jwt.sign({ admin:true, email }, ADMIN_JWT_SECRET, { expiresIn:"12h" });
  res.json({ token });
});

app.get("/api/admin/me", requireAdmin, (req, res) => {
  res.json({ admin:true, email: req.admin?.email || ADMIN_EMAIL });
});

// ── Password Reset ────────────────────────────────────────────
app.post("/api/auth/forgot-password", async (req, res) => {
  const { email } = req.body;
  // Always return 200 to avoid email enumeration
  res.json({ success:true, message:"Si el email existe, recibirás un enlace en minutos." });
  const user = getUserByEmail.get((email||"").trim().toLowerCase());
  if (!user || !resend) return;
  const token = crypto.randomBytes(32).toString("hex");
  const expires = new Date(Date.now() + 60*60*1000).toISOString().replace("T"," ").slice(0,19); // 1h
  setResetToken.run({ token, expires, id:user.id });
  const resetUrl = SITE_URL + "/auth.html?reset=" + token;
  resend.emails.send({
    from: FROM_EMAIL, to: user.email,
    subject: "Restablecer contraseña — Dalaran",
    html: `<!DOCTYPE html><html><body style="font-family:sans-serif;background:#f5f4f0;padding:32px;">
  <div style="max-width:480px;margin:0 auto;background:#fff;border-radius:12px;padding:32px;border:1px solid #e2e0db;">
    <div style="font-size:24px;font-weight:900;margin-bottom:8px;">Dala<span style="color:#ffd666;">ran</span></div>
    <h2 style="font-size:18px;margin:0 0 16px;">Restablecer contraseña</h2>
    <p style="color:#6b6760;font-size:14px;margin-bottom:24px;">Recibimos una solicitud para restablecer la contraseña de tu cuenta. El enlace expira en 1 hora.</p>
    <a href="${resetUrl}" style="display:inline-block;background:#2c4a7c;color:#fff;padding:14px 28px;border-radius:8px;font-weight:700;text-decoration:none;font-size:14px;">Restablecer contraseña →</a>
    <p style="color:#9b9890;font-size:12px;margin-top:24px;">Si no solicitaste esto, ignorá este email.</p>
  </div></body></html>`
  }).catch(console.error);
});

app.post("/api/auth/reset-password", async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password || password.length < 6)
    return res.status(400).json({ error:"Token y contraseña (mín. 6 caracteres) requeridos" });
  const user = getUserByToken.get(token);
  if (!user) return res.status(400).json({ error:"Enlace inválido o expirado" });
  const hash = await bcrypt.hash(password, 10);
  clearResetToken.run({ password:hash, id:user.id });
  res.json({ success:true, message:"Contraseña actualizada correctamente." });
});

// ── Admin Users ───────────────────────────────────────────────
app.get("/api/admin/users", requireAdmin, (req, res) => {
  const { db: _db, ...rest } = require("./db");
  // Direct query since we don't have a prepared statement for all users
  const Database = require("better-sqlite3");
  const path = require("path");
  const DB_PATH = process.env.DB_PATH || path.join(__dirname, "dalaran.db");
  const tmpDb = new Database(DB_PATH, { readonly:true });
  const users = tmpDb.prepare("SELECT id, email, name, phone, created_at, newsletter, terms_accepted FROM users ORDER BY created_at DESC").all();
  tmpDb.close();
  res.json({ users, total:users.length });
});

// ── Orders ────────────────────────────────────────────────────
app.post("/api/orders", optionalAuth, async (req, res) => {
  const errors = validateOrder(req.body);
  if (errors.length) return res.status(400).json({ error:"Datos inválidos", details:errors });
  const { name, email, phone, address, notes, items } = req.body;
  const subtotal = items.reduce((s,i) => s + (Number(i.priceValue)||0)*(Number(i.qty)||1), 0);
  const total    = subtotal + SHIPPING_COST;
  let order;
  try {
    const r = insertOrder.run({ user_id:req.user?req.user.id:null, name:name.trim(), email:email.trim().toLowerCase(), phone:phone.trim(), address:address.trim(), notes:(notes||"").trim()||null, items_json:JSON.stringify(items), subtotal, shipping:SHIPPING_COST, total });
    order = getOrderById.get(r.lastInsertRowid);
  } catch(err) { console.error(err); return res.status(500).json({ error:"Error al guardar el pedido" }); }
  if (resend) {
    const { subject, html } = buildOrderEmail(order);
    resend.emails.send({ from:FROM_EMAIL, to:TO_EMAIL, reply_to:email, subject, html }).catch(console.error);
    // Send confirmation to customer
    const cust = buildCustomerEmail(order);
    resend.emails.send({ from:FROM_EMAIL, to:order.email, subject:cust.subject, html:cust.html }).catch(console.error);
  }
  res.status(201).json({ success:true, order:{ id:order.id, created_at:order.created_at, status:order.status, total:order.total, subtotal:order.subtotal, shipping:order.shipping, name:order.name, email:order.email, address:order.address, items:JSON.parse(order.items_json) } });
});

app.get("/api/orders/mine", requireAuth, (req, res) => {
  const orders = getOrdersByUser.all(req.user.id).map(o => ({ ...o, items:JSON.parse(o.items_json) }));
  res.json({ orders });
});

// ── Wishlist ──────────────────────────────────────────────────
app.get("/api/wishlist", requireAuth, (req, res) => res.json({ items:getWishlist.all(req.user.id) }));

app.post("/api/wishlist", requireAuth, (req, res) => {
  const { product_id, product_name, image, price_text, price_value } = req.body;
  if (!product_id||!product_name) return res.status(400).json({ error:"product_id y product_name requeridos" });
  addToWishlist.run({ user_id:req.user.id, product_id, product_name, image:image||"", price_text:price_text||"", price_value:price_value||0 });
  res.json({ success:true });
});

app.delete("/api/wishlist/:productId", requireAuth, (req, res) => {
  removeFromWishlist.run(req.user.id, Number(req.params.productId));
  res.json({ success:true });
});

app.get("/api/wishlist/:productId", requireAuth, (req, res) => {
  const item = getWishlistItem.get(req.user.id, Number(req.params.productId));
  res.json({ inWishlist:!!item });
});

// ── Admin ─────────────────────────────────────────────────────
app.get("/api/admin/orders", requireAdmin, (req, res) => {
  const orders = getAllOrders.all().map(o => ({ ...o, items:JSON.parse(o.items_json) }));
  res.json({ orders, total:orders.length });
});

app.get("/api/admin/orders/:id", requireAdmin, (req, res) => {
  const order = getOrderById.get(Number(req.params.id));
  if (!order) return res.status(404).json({ error:"Pedido no encontrado" });
  res.json({ ...order, items:JSON.parse(order.items_json) });
});

app.patch("/api/admin/orders/:id/status", requireAdmin, (req, res) => {
  const { status } = req.body;
  const valid = ["pendiente","confirmado","enviado","entregado","cancelado"];
  if (!valid.includes(status)) return res.status(400).json({ error:"Estado inválido", valid });
  const result = updateOrderStatus.run(status, Number(req.params.id));
  if (!result.changes) return res.status(404).json({ error:"Pedido no encontrado" });
  res.json({ success:true, id:Number(req.params.id), status });
});

app.listen(PORT, () => {
  console.log(`✅ Dalaran API v2 en puerto ${PORT}`);
  console.log(`   Email: ${resend?"✅ Resend OK":"⚠️  Sin RESEND_API_KEY"}`);
  console.log(`   JWT:   ${JWT_SECRET!=="dalaran_jwt_secret_change_me"?"✅ Custom":"⚠️  Agregar JWT_SECRET en Railway"}`);
});
