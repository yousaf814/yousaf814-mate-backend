import { createClient } from "@supabase/supabase-js";
import crypto from "crypto";

/* ---------- HARD FAILS (so we stop guessing) ---------- */
if (!process.env.SUPABASE_URL) {
  throw new Error("SUPABASE_URL missing");
}
if (!process.env.SUPABASE_SERVICE_ROLE_KEY) {
  throw new Error("SUPABASE_SERVICE_ROLE_KEY missing");
}
if (!process.env.WHOP_WEBHOOK_SECRET) {
  throw new Error("WHOP_WEBHOOK_SECRET missing");
}

/* ---------- SUPABASE ---------- */
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
);

/* ---------- VERCEL HANDLER ---------- */
export default async function handler(req, res) {
  // Health check
  if (req.method === "GET") {
    return res.status(200).send("Backend alive");
  }

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  // Whop signature check
  const signature = req.headers["x-whop-signature"];
  if (!signature) {
    return res.status(401).json({ error: "Missing Whop signature" });
  }

  const body = JSON.stringify(req.body);
  const expected = crypto
    .createHmac("sha256", process.env.WHOP_WEBHOOK_SECRET)
    .update(body)
    .digest("hex");

  if (signature !== expected) {
    return res.status(401).json({ error: "Invalid signature" });
  }

  // Handle payment
  if (req.body?.type === "payment.succeeded") {
    const { user_id, plan_id } = req.body.data;

    const { error } = await supabase.from("subscriptions").upsert({
      user_id,
      plan_id,
      active: true,
      updated_at: new Date().toISOString(),
    });

    if (error) {
      console.error(error);
      return res.status(500).json({ error: "DB error" });
    }
  }

  return res.status(200).json({ ok: true });
}
