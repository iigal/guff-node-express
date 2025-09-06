import { createClient } from "@supabase/supabase-js";
import axios from "axios";

const supabase = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!
);

function generateOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

export default async function handler(req: any, res: any) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  try {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ error: "phone required" });

    const code = generateOtp();
    const expires_at = new Date(Date.now() + 5 * 60 * 1000).toISOString();

    await supabase.from("otps").insert([{ phone, code, expires_at }]);

    const text = `Your OTP is: ${code}`;
    const url = "https://sms.aakashsms.com/smsIv3/send";

    const params = new URLSearchParams();
    params.append("auth_token", process.env.AAKASHSMS_AUTH_TOKEN!);
    params.append("to", phone);
    params.append("text", text);

    await axios.post(url, params.toString(), {
      headers: { "Content-Type": "application/x-www-form-urlencoded" }
    });

    return res.status(200).json({ success: true });
  } catch (err: any) {
    console.error(err);
    return res.status(500).json({ error: "send-otp failed" });
  }
}
