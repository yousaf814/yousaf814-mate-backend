import { createClient } from "@supabase/supabase-js";
import crypto from "crypto";

// 🚨 HARD FAIL if env vars are missing
if (!process.env.SUPABASE_URL) {
  throw new Error("SUPABASE_URL is missing");
}

if (!process.env.SUPABASE_SERVICE_ROLE_KEY) {
  throw new Error("SUPABASE_SERVICE_ROLE_KEY is missing");
}

if (!process.env.WHOP_WEBHOOK_SECRET) {
  throw new Error("WHOP_WEBHOOK_SECRET is missing");
}

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
);

export default async function handler(req, res) {
  if (req.method === "GET") {
    return res.status(200).send("Mate backend running");
  }

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const signature = req.headers["x-whop-signature"];
  if (!signature) {
    return res.status(401).json({ error: "Missing signature" });
  }

  const rawBody = JSON.stringify(req.body);
  const expectedSignature = crypto
    .createHmac("sha256", process.env.WHOP_WEBHOOK_SECRET)
    .update(rawBody)
    .digest("hex");

  if (signature !== expectedSignature) {
    return res.status(401).json({ error: "Invalid signature" });
  }

  const event = req.body;

  if (event.type === "payment.succeeded") {
    const { user_id, plan_id } = event.data;

    await supabase.from("subscriptions").upsert({
      user_id,
      plan_id,
      active: true,
      updated_at: new Date().toISOString(),
    });
  }

  return res.status(200).json({ received: true });
}
