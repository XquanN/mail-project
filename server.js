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
  createdAt: { type: Date, default: Date.now },
});
const Key = mongoose.model("Key", keySchema);

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
    let newKey = generate12DigitKey();
    for (let i = 0; i < 5; i++) {
      const exists = await Key.findOne({ key: newKey });
      if (!exists) break;
      newKey = generate12DigitKey();
    }
    const doc = await Key.create({ key: newKey, usesLeft: 2 });
    res.json(doc);
  } catch (err) {
    console.log("ADMIN create-key hata:", err);
    res.status(500).json({ error: "Key üretilemedi" });
  }
});

app.get("/admin/keys", async (req, res) => {
  const keys = await Key.find().sort({ createdAt: -1 });
  res.json(keys);
});

app.delete("/admin/delete/:id", async (req, res) => {
  await Key.findByIdAndDelete(req.params.id);
  res.json({ message: "Silindi" });
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
        const text = typeof textPart === "string" ? textPart : (textPart?.toString?.() || "");

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
