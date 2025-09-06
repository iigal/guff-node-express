import jwt from "jsonwebtoken";

export default async function handler(req: any, res: any) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ error: "refreshToken required" });

    let payload;
    try {
      payload = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET!) as any;
    } catch {
      return res.status(401).json({ error: "Invalid refresh token" });
    }

    const userId = payload.sub;
    const sixMonthsInSeconds = 60 * 60 * 24 * 30 * 6;
    const token = jwt.sign({ sub: userId }, process.env.JWT_SIGNING_SECRET!, { expiresIn: sixMonthsInSeconds });

    return res.status(200).json({ token });
  } catch (err: any) {
    console.error(err);
    return res.status(500).json({ error: "refresh-token failed" });
  }
}
