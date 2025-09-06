// server/src/index.ts
import express from "express";
import dotenv from "dotenv";
import axios from "axios";
import bodyParser from "body-parser";
import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";
import { randomInt } from "crypto";

dotenv.config();
const app = express();
app.use(bodyParser.json());

const {
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  AAKASHSMS_AUTH_TOKEN,
  JWT_SIGNING_SECRET,
  JWT_REFRESH_SECRET,
  OTP_TTL_SECONDS = "300"
} = process.env;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || !AAKASHSMS_AUTH_TOKEN || !JWT_SIGNING_SECRET || !JWT_REFRESH_SECRET) {
  console.error("Missing env vars");
  process.exit(1);
}

const otpTTL = parseInt(OTP_TTL_SECONDS, 10);

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  // service role key runs server-side
});

function generateOtp() {
  // 6-digit numeric OTP
  return String(randomInt(100000, 999999));
}

// POST /send-otp { phone }
app.post("/send-otp", async (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ error: "phone required" });

    const code = generateOtp();
    const expires_at = new Date(Date.now() + otpTTL * 1000).toISOString();

    // upsert OTP into DB
    await supabase.from("otps").insert([{ phone, code, expires_at }]);

    // prepare text message
    const text = `Your app OTP is: ${code}`;

    // send via Aakashsms
    // Aakashsms endpoint per your description: https[sms aakashsmscom/smsIv3/send
    // We'll use a proper URL: https://sms.aakashsms.com/smsIv3/send (update if different)
    const url = "https://sms.aakashsms.com/smsIv3/send";

    // Aakashsms supports POST or GET per your note: use POST with form-encoded
    const params = new URLSearchParams();
    params.append("auth_token", AAKASHSMS_AUTH_TOKEN!);
    params.append("to", phone);
    params.append("text", text);

    await axios.post(url, params.toString(), {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      timeout: 10000,
    });

    return res.json({ success: true });
  } catch (err: any) {
    console.error(err?.response?.data || err.message || err);
    return res.status(500).json({ error: "Failed to send OTP" });
  }
});

// POST /verify-otp { phone, code, full_name? }
// If user exists, returns user profile; otherwise creates user with provided full_name
app.post("/verify-otp", async (req, res) => {
  try {
    const { phone, code, full_name } = req.body;
    if (!phone || !code) return res.status(400).json({ error: "phone+code required" });

    // find the OTP record
    const { data: otps } = await supabase
      .from("otps")
      .select("*")
      .eq("phone", phone)
      .order("created_at", { ascending: false })
      .limit(1);

    const otp = otps?.[0];
    if (!otp || otp.code !== String(code)) return res.status(400).json({ error: "Invalid OTP" });
    if (new Date(otp.expires_at) < new Date()) return res.status(400).json({ error: "OTP expired" });

    // upsert user
    const { data: existingUsers } = await supabase
      .from("users")
      .select("*")
      .eq("phone", phone)
      .limit(1);

    let user = existingUsers?.[0];
    if (!user) {
      const insertRes = await supabase.from("users").insert([{ phone, full_name }]).select().single();
      user = insertRes.data;
    }

    // create JWT (6 months expiry)
    const sixMonthsInSeconds = 60 * 60 * 24 * 30 * 6;
    const token = jwt.sign({ sub: user.id, phone: user.phone }, JWT_SIGNING_SECRET!, {
      expiresIn: sixMonthsInSeconds,
    });

    // create refresh token (longer lived)
    const refreshToken = jwt.sign({ sub: user.id }, JWT_REFRESH_SECRET!, { expiresIn: "1y" });

    // Optionally: store refresh token hashed in DB to allow revocation
    // For brevity we skip storage here

    // delete used OTPs for phone (cleanup)
    await supabase.from("otps").delete().eq("phone", phone);

    return res.json({ token, refreshToken, user });
  } catch (err: any) {
    console.error(err);
    return res.status(500).json({ error: "verify error" });
  }
});

// POST /refresh-token { refreshToken }
app.post("/refresh-token", async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ error: "refreshToken required" });

    let payload;
    try {
      payload = jwt.verify(refreshToken, JWT_REFRESH_SECRET!) as any;
    } catch (e) {
      return res.status(401).json({ error: "Invalid refresh token" });
    }

    const userId = payload.sub;
    // optionally verify refresh token against DB

    // create new 6-month token
    const sixMonthsInSeconds = 60 * 60 * 24 * 30 * 6;
    const token = jwt.sign({ sub: userId }, JWT_SIGNING_SECRET!, { expiresIn: sixMonthsInSeconds });

    return res.json({ token });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "refresh error" });
  }
});

app.listen(process.env.PORT || 3000, () => {
  console.log("Server listening on", process.env.PORT || 3000);
});
