import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";

const supabase = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!
);

export default async function handler(req: any, res: any) {
  // CORS headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const { phone, code, full_name } = req.body;
    if (!phone || !code) return res.status(400).json({ error: "phone+code required" });

    const { data: otps } = await supabase
      .from("otps")
      .select("*")
      .eq("phone", phone)
      .order("created_at", { ascending: false })
      .limit(1);

    const otp = otps?.[0];
    if (!otp || otp.code !== String(code)) return res.status(400).json({ error: "Invalid OTP" });
    if (new Date(otp.expires_at) < new Date()) return res.status(400).json({ error: "OTP expired" });

    const { data: existingUsers } = await supabase.from("users").select("*").eq("phone", phone).limit(1);

    let user = existingUsers?.[0];

    if (!user && !full_name) {
      return res.status(400).json({ error: "Full name required for new users" });
    }
    if (!user) {
      const insertRes = await supabase.from("users").insert([{ phone, full_name }]).select().single();
      user = insertRes.data;
    }

    const sixMonthsInSeconds = 60 * 60 * 24 * 30 * 6;
    const token = jwt.sign({ sub: user.id, phone: user.phone }, process.env.JWT_SIGNING_SECRET!, {
      expiresIn: sixMonthsInSeconds,
    });

    const refreshToken = jwt.sign({ sub: user.id }, process.env.JWT_REFRESH_SECRET!, {
      expiresIn: "1y",
    });

    await supabase.from("otps").delete().eq("phone", phone);

    return res.status(200).json({ token, refreshToken, user });
  } catch (err: any) {
    console.error(err);
    return res.status(500).json({ error: "verify-otp failed" });
  }
}
