import express from "express";
import cors from "cors";
import crypto from "crypto";
import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";

dotenv.config();

const app = express();

/**
 * IMPORTANT:
 * Whop requires RAW body for signature verification
 */
app.use("/webhooks/whop", express.raw({ type: "application/json" }));

app.use(cors());
app.use(express.json());

/**
 * Supabase admin client
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
 * SESSION MAPPING (SOURCE OF TRUTH)
 * Replace keys with REAL Whop price IDs
 */
const PLAN_SESSIONS = {
  price_104: 1,
  price_204: 3,
  price_324: 5,
};

/**
 * WHOP WEBHOOK ENDPOINT
 */
app.post("/webhooks/whop", async (req, res) => {
  if (!verifyWhopSignature(req)) {
    return res.status(401).send("Invalid signature");
  }

  const event = JSON.parse(req.body.toString());
  const { type, data } = event;

  try {
    switch (type) {
      case "membership_activated": {
        const userId = data.user_id;
        const planId = data.product_id;

        const sessionsTotal = PLAN_SESSIONS[planId] ?? 0;

        await supabase.from("entitlements").upsert({
          user_id: userId,
          plan_id: planId,
          active: true,
          sessions_total: sessionsTotal,
          sessions_used: 0,
        });

        break;
      }

      case "membership_deactivated": {
        const userId = data.user_id;

        await supabase
          .from("entitlements")
          .update({ active: false })
          .eq("user_id", userId);

        break;
      }

      default:
        console.log("Unhandled event:", type);
    }

    res.status(200).send("OK");
  } catch (err) {
    console.error("Webhook error:", err);
    res.status(500).send("Server error");
  }
});

/**
 * Health check
 */
app.get("/", (req, res) => {
  res.send("Mate backend running");
});

const PORT = process.env.PORT || 3000;
module.exports = app;
