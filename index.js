import express from "express";
import crypto from "crypto";
import { createClient } from "@supabase/supabase-js";

const app = express();

/**
 * Whop requires RAW body for signature verification
 */
app.use("/webhooks/whop", express.raw({ type: "application/json" }));

/**
 * Supabase admin client
 * ❗ Will crash if env vars are missing (as it should)
 */
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
);

/**
 * Verify Whop webhook signature
 */
function verifyWhopSignature(req) {
  const signature = req.headers["x-whop-signature"];
  if (!signature) return false;

  const expected = crypto
    .createHmac("sha256", process.env.WHOP_WEBHOOK_SECRET)
    .update(req.body)
    .digest("hex");

  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}

/**
 * WHOP WEBHOOK
 */
app.post("/webhooks/whop", async (req, res) => {
  if (!verifyWhopSignature(req)) {
    return res.status(401).send("Invalid signature");
  }

  const event = JSON.parse(req.body.toString());
  const { type, data } = event;

  try {
    if (type === "membership_activated") {
      await supabase.from("entitlements").upsert({
        user_id: data.user_id,
        plan_id: data.product_id,
        active: true,
      });
    }

    if (type === "membership_deactivated") {
      await supabase
        .from("entitlements")
        .update({ active: false })
        .eq("user_id", data.user_id);
    }

    res.status(200).send("OK");
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

/**
 * Health check
 */
app.get("/", (req, res) => {
  res.send("Mate backend running");
});

export default app;
