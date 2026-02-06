import crypto from "crypto";
import { createClient } from "@supabase/supabase-js";

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
);

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).send("Method Not Allowed");
  }

  let body = "";

  req.on("data", (chunk) => {
    body += chunk.toString();
  });

  req.on("end", async () => {
    try {
      const event = JSON.parse(body);
      const { type, data } = event;

      if (type === "membership_activated") {
        await supabase.from("subscriptions").upsert({
          whop_user_id: data.user_id,
          plan: data.product_id,
          active: true,
          updated_at: new Date().toISOString(),
        });
      }

      if (type === "membership_deactivated") {
        await supabase
          .from("subscriptions")
          .update({ active: false })
          .eq("whop_user_id", data.user_id);
      }

      return res.status(200).send("OK");
    } catch (err) {
      console.error(err);
      return res.status(500).send("Webhook error");
    }
  });
}
