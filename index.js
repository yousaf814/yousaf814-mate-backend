import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import crypto from "crypto";
import { createClient } from "@supabase/supabase-js";

/**
 * Load environment variables
 * NOTE: On Vercel, these come from Project Settings → Environment Variables
 */
dotenv.config();

const app = express();

/**
 * IMPORTANT:
 * Whop requires RAW body for signature verification
 * So this route MUST come before express.json()
 */
app.post(
  "/webhooks/whop",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      const signature = req.headers["x-whop-signature"];
      if (!signature) {
        return res.status(401).send("Missing signature");
      }

      const expectedSignature = crypto
        .createHmac("sha256", process.env.WHOP_WEBHOOK_SECRET)
        .update(req.body)
        .digest("hex");

      const valid = crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(expectedSignature),
      );

      if (!valid) {
        return res.status(401).send("Invalid signature");
      }

      const event = JSON.parse(req.body.toString());
      const { type, data } = event;

      const supabase = createClient(
        process.env.SUPABASE_URL,
        process.env.SUPABASE_SERVICE_ROLE_KEY,
      );

      switch (type) {
        case "membership_activated": {
          await supabase.from("entitlements").upsert({
            user_id: data.user_id,
            plan_id: data.product_id,
            active: true,
            updated_at: new Date().toISOString(),
          });
          break;
        }

        case "membership_deactivated": {
          await supabase
            .from("entitlements")
            .update({ active: false, updated_at: new Date().toISOString() })
            .eq("user_id", data.user_id);
          break;
        }

        default:
          console.log("Unhandled Whop event:", type);
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
 * Health check (VERY IMPORTANT for sanity)
 */
app.get("/", (req, res) => {
  res.json({
    status: "SehatMate backend running",
    timestamp: new Date().toISOString(),
  });
});

/**
 * Vercel requires default export
 */
export default app;
