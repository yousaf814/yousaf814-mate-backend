import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import crypto from "crypto";
import { createClient } from "@supabase/supabase-js";

dotenv.config();

const app = express();

/**
 * RAW body ONLY for webhook
 */
app.post(
  "/webhooks/whop",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, WHOP_WEBHOOK_SECRET } =
        process.env;

      // 🔒 HARD FAIL if env missing
      if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || !WHOP_WEBHOOK_SECRET) {
        console.error("❌ Missing environment variables");
        return res.status(500).send("Server misconfigured");
      }

      const signature = req.headers["x-whop-signature"];
      if (!signature) {
        return res.status(401).send("Missing signature");
      }

      const expectedSignature = crypto
        .createHmac("sha256", WHOP_WEBHOOK_SECRET)
        .update(req.body)
        .digest("hex");

      if (
        !crypto.timingSafeEqual(
          Buffer.from(signature),
          Buffer.from(expectedSignature),
        )
      ) {
        return res.status(401).send("Invalid signature");
      }

      const event = JSON.parse(req.body.toString());

      // ✅ Create Supabase client ONLY HERE
      const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

      if (event.type === "membership_activated") {
        await supabase.from("entitlements").upsert({
          user_id: event.data.user_id,
          plan_id: event.data.product_id,
          active: true,
          updated_at: new Date().toISOString(),
        });
      }

      if (event.type === "membership_deactivated") {
        await supabase
          .from("entitlements")
          .update({ active: false })
          .eq("user_id", event.data.user_id);
      }

      return res.status(200).send("OK");
    } catch (err) {
      console.error("Webhook error:", err);
      return res.status(500).send("Server error");
    }
  },
);

/**
 * Normal middleware AFTER webhook
 */
app.use(cors());
app.use(express.json());

/**
 * Health check — MUST NOT touch Supabase
 */
app.get("/", (_req, res) => {
  res.json({
    status: "SehatMate backend running",
    env: process.env.VERCEL_ENV || "local",
  });
});

export default app;
