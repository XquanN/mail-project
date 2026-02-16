require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const imaps = require("imap-simple");
const { simpleParser } = require("mailparser");
const cors = require("cors");
const crypto = require("crypto");
const path = require("path");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

const DEFAULT_KEY_DURATION_SECONDS = Number(process.env.DEFAULT_KEY_DURATION_SECONDS || 60 * 60);
const MIN_KEY_DURATION_SECONDS = 5 * 60;
const MAX_KEY_DURATION_SECONDS = 30 * 24 * 60 * 60;
const SUPER_TOKEN = process.env.SUPER_TOKEN || "dev-super-token";

/* =============================
   MongoDB
============================= */
mongoose
  .connect(process.env.MONGO)
  .then(() => console.log("✅ MongoDB bağlandı"))
  .catch((err) => console.log("❌ MongoDB hata:", err));

/* =============================
   Key Model
============================= */
const keySchema = new mongoose.Schema({
  key: { type: String, required: true, unique: true },
  usesLeft: { type: Number, default: 2 },
  durationSeconds: { type: Number, min: MIN_KEY_DURATION_SECONDS, max: MAX_KEY_DURATION_SECONDS },
  expiresAt: { type: Date },
  createdAt: { type: Date, default: Date.now },
});
const Key = mongoose.model("Key", keySchema);

/* =============================
   Admin Model
============================= */
const adminSchema = new mongoose.Schema(
  {
    username: { type: String, required: true, unique: true, trim: true },
    password: { type: String, required: true },
    suspended: { type: Boolean, default: false },
  },
  { timestamps: true }
);
const Admin = mongoose.models.Admin || mongoose.model("Admin", adminSchema);

/* =============================
   IMAP Config
============================= */
const imapConfig = {
  imap: {
    user: process.env.EMAIL,
    password: process.env.PASSWORD,
    host: process.env.IMAP_HOST || "imap.gmail.com",
    port: Number(process.env.IMAP_PORT || 993),
    tls: String(process.env.IMAP_TLS || "true").toLowerCase() !== "false",
    tlsOptions: { rejectUnauthorized: false },
    authTimeout: 10000,
  },
};

// Sabit FROM filtresi (kullanıcı istedi)
const OTP_FROM = "kivancergul10@gmail.com";

// Debug istersen .env: DEBUG=true
const DEBUG = String(process.env.DEBUG || "false").toLowerCase() === "true";

/* =============================
   Helpers
============================= */
function generate12DigitKey() {
  const n = crypto.randomInt(0, 1_000_000_000_000);
  return n.toString().padStart(12, "0");
}
function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function normalizeDurationSeconds(rawMinutes) {
  const minutes = Number(rawMinutes);
  if (!Number.isFinite(minutes)) return null;
  const duration = Math.round(minutes * 60);
  if (duration < MIN_KEY_DURATION_SECONDS || duration > MAX_KEY_DURATION_SECONDS) return null;
  return duration;
}

function getKeyTiming(keyDoc) {
  const createdAt = keyDoc.createdAt ? new Date(keyDoc.createdAt) : new Date();
  const durationSeconds =
    Number(keyDoc.durationSeconds) > 0 ? Number(keyDoc.durationSeconds) : DEFAULT_KEY_DURATION_SECONDS;
  const expiresAt = keyDoc.expiresAt
    ? new Date(keyDoc.expiresAt)
    : new Date(createdAt.getTime() + durationSeconds * 1000);

  const remainingMs = expiresAt.getTime() - Date.now();
  const expired = remainingMs <= 0;

  return {
    durationSeconds,
    expiresAt,
    remainingSeconds: expired ? 0 : Math.floor(remainingMs / 1000),
    remainingText: expired
      ? "Expired"
      : `${Math.floor(remainingMs / (1000 * 60 * 60))}h ${Math.floor((remainingMs % (1000 * 60 * 60)) / (1000 * 60))}m left`,
  };
}

function serializeKey(keyDoc) {
  const obj = keyDoc.toObject ? keyDoc.toObject() : { ...keyDoc };
  const timing = getKeyTiming(obj);

  return {
    ...obj,
    durationSeconds: timing.durationSeconds,
    expiresAt: timing.expiresAt,
    remainingSeconds: timing.remainingSeconds,
    remainingText: timing.remainingText,
  };
}

function superAuth(req, res, next) {
  const token = req.headers["x-super-token"] || req.headers.authorization?.replace(/^Bearer\s+/i, "");
  if (!token || token !== SUPER_TOKEN) {
    return res.status(401).json({ error: "Unauthorized super admin" });
  }
  next();
}

// 628018 veya "6 2 8 0 1 8" hatta "6-2-8-0-1-8" / araya enter falan girse de yakala
function extract6DigitCode(text) {
  if (!text) return null;

  const t = String(text)
    .replace(/&nbsp;|&#160;/gi, " ")
    .replace(/[\u200B-\u200D\uFEFF]/g, " ")
    .replace(/[\r\n\t]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();

  const straight = t.match(/\b\d{6}\b/);
  if (straight) return straight[0];

  const loose = t.match(/(?<!\d)(\d(?:[^\d]{0,3}\d){5})(?!\d)/);
  if (loose) {
    const digits = loose[1].replace(/\D/g, "");
    if (digits.length === 6) return digits;
  }

  const any = t.replace(/\D/g, "").match(/\d{6}/);
  return any ? any[0] : null;
}

function buildImapSearchCriteria(uidFrom, uidTo) {
  // UID aralığı + FROM filtresi
  return [["UID", `${uidFrom}:${uidTo}`], ["FROM", OTP_FROM]];
}

/* =============================
   Root
============================= */
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

/* =============================
   Admin
============================= */
app.post("/admin/create-key", async (req, res) => {
  try {
    const durationSeconds = normalizeDurationSeconds(req.body?.durationMinutes ?? 60);
    if (!durationSeconds) {
      return res.status(400).json({ error: "durationMinutes must be between 5 and 43200" });
    }

    let newKey = generate12DigitKey();
    for (let i = 0; i < 5; i++) {
      const exists = await Key.findOne({ key: newKey });
      if (!exists) break;
      newKey = generate12DigitKey();
    }

    const createdAt = new Date();
    const expiresAt = new Date(createdAt.getTime() + durationSeconds * 1000);

    const doc = await Key.create({
      key: newKey,
      usesLeft: 2,
      createdAt,
      durationSeconds,
      expiresAt,
    });

    res.json(serializeKey(doc));
  } catch (err) {
    console.log("ADMIN create-key hata:", err);
    res.status(500).json({ error: "Key üretilemedi" });
  }
});

app.get("/admin/keys", async (req, res) => {
  const keys = await Key.find().sort({ createdAt: -1 });
  res.json(keys.map(serializeKey));
});

app.delete("/admin/delete/:id", async (req, res) => {
  await Key.findByIdAndDelete(req.params.id);
  res.json({ message: "Silindi" });
});

app.get("/api/super/admins", superAuth, async (req, res) => {
  const admins = await Admin.find().sort({ createdAt: -1 }).select("username suspended createdAt updatedAt");
  res.json(admins);
});

app.post("/api/super/admins/:id/suspend", superAuth, async (req, res) => {
  const { suspended } = req.body || {};
  if (typeof suspended !== "boolean") {
    return res.status(400).json({ error: "suspended must be boolean" });
  }

  const admin = await Admin.findByIdAndUpdate(
    req.params.id,
    { suspended },
    { new: true, runValidators: true }
  ).select("username suspended createdAt updatedAt");

  if (!admin) return res.status(404).json({ error: "Admin not found" });

  return res.json({ message: suspended ? "Admin suspended" : "Admin unsuspended", admin });
});

app.post("/api/admin/login", async (req, res) => {
  const username = String(req.body?.username || "").trim();
  const password = String(req.body?.password || "");
  if (!username || !password) {
    return res.status(400).json({ error: "username and password are required" });
  }

  const admin = await Admin.findOne({ username });
  if (!admin || admin.password !== password) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  if (admin.suspended) {
    return res.status(403).json({ error: "Admin account is suspended" });
  }

  return res.json({ message: "Login successful", adminId: admin._id });
});

/* =============================
   IMAP: tek bağlantı + UID takip
============================= */
let imapConn = null;
let connecting = null;
let lastSeenUid = 0;

function resetImapConn() {
  try {
    if (imapConn) imapConn.end();
  } catch (_) {}
  imapConn = null;
  connecting = null;
}

async function getImapConnection() {
  if (imapConn) return imapConn;
  if (connecting) return connecting;

  connecting = (async () => {
    const c = await imaps.connect(imapConfig);
    await c.openBox("INBOX");
    console.log("📬 IMAP hazır");
    imapConn = c;

    // uidnext baseline
    try {
      const box = await imapConn.openBox("INBOX");
      const uidNext = Number(box?.uidnext || 0);
      if (uidNext > 0) lastSeenUid = uidNext - 1;
      if (DEBUG) console.log("[IMAP] uidNext:", uidNext, "lastSeenUid:", lastSeenUid);
    } catch (e) {
      if (DEBUG) console.log("[IMAP] baseline fail:", e?.message || e);
    }

    // koparsa reset
    try {
      const raw = imapConn?.imap;
      raw?.once?.("close", resetImapConn);
      raw?.once?.("error", resetImapConn);
      raw?.once?.("end", resetImapConn);
    } catch (_) {}

    return imapConn;
  })();

  try {
    return await connecting;
  } catch (e) {
    resetImapConn();
    throw e;
  } finally {
    connecting = null;
  }
}

/* =============================
   GET CODE (MAX 20sn)
   - Key kontrol + usesLeft
   - Sadece FROM filtresi
   - Sadece son 12 UID'ye bakar (çok hızlı)
   - TEXT ile başlar, gerekirse full raw fallback
============================= */
app.post("/get-code", async (req, res) => {
  const userKey = (req.body?.key || "").trim();
  if (!userKey) return res.json({ message: "Key gir" });

  const keyDoc = await Key.findOne({ key: userKey });
  if (!keyDoc) return res.json({ message: "Geçersiz key" });

  if (getKeyTiming(keyDoc).remainingText === "Expired") {
    await Key.deleteOne({ _id: keyDoc._id });
    return res.json({ message: "Key süresi dolmuş" });
  }

  if (keyDoc.usesLeft <= 0) {
    await Key.deleteOne({ _id: keyDoc._id });
    return res.json({ message: "Key kullanım hakkı bitmiş" });
  }

  const start = Date.now();
  const timeoutMs = 20_000;
  const intervalMs = 200; // daha hızlı polling

  let foundCode = null;

  while (!foundCode && Date.now() - start < timeoutMs) {
    try {
      const c = await getImapConnection();
      const box = await c.openBox("INBOX");
      const uidNext = Number(box?.uidnext || 0);

      // Son 12 UID aralığı (dar aralık = hız)
      const uidTo = uidNext > 0 ? uidNext - 1 : lastSeenUid;
      const uidFrom = Math.max(1, uidTo - 12);

      // 1) Önce TEXT (hızlı)
      const results = await c.search(buildImapSearchCriteria(uidFrom, uidTo), {
        bodies: ["TEXT"],
        markSeen: false,
      });

      if (DEBUG) console.log("[SEARCH] results:", results.length, "uidFrom:", uidFrom, "uidTo:", uidTo);

      // son mailden başla
      for (const msg of results.reverse()) {
        const uid = Number(msg.attributes?.uid || 0);
        if (uid && uid > lastSeenUid) lastSeenUid = uid;

        const textPart = msg.parts?.find((p) => p.which === "TEXT")?.body;
        const text = typeof textPart === "string" ? textPart : textPart?.toString?.() || "";

        let code = extract6DigitCode(text);
        if (code) {
          foundCode = code;
          break;
        }

        // 2) Fallback: sadece gerekirse full raw parse
        // (sonuç çoksa fallback'i tetikleme => hız)
        if (!code && uid && results.length <= 5) {
          const full = await c.search([["UID", String(uid)], ["FROM", OTP_FROM]], {
            bodies: [""],
            markSeen: false,
          });

          const raw = full?.[0]?.parts?.[0]?.body;
          if (raw) {
            const parsed = await simpleParser(raw);
            const body = (parsed.text || "") + " " + (parsed.html || "");
            code = extract6DigitCode(body);
            if (code) {
              foundCode = code;
              break;
            }
          }
        }
      }
    } catch (err) {
      console.log("MAIL CHECK ERROR:", err?.message || err);
      resetImapConn();
    }

    if (!foundCode) await sleep(intervalMs);
  }

  // her istek 1 kullanım
  keyDoc.usesLeft -= 1;
  if (keyDoc.usesLeft <= 0) {
    await Key.deleteOne({ _id: keyDoc._id });
  } else {
    await keyDoc.save();
  }

  if (foundCode) return res.json({ code: foundCode });
  return res.json({ message: "Kod bulunamadı" });
});

/* =============================
   Server
============================= */
const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, () => {
  console.log(`🚀 Server ${PORT} portunda çalışıyor`);
});
