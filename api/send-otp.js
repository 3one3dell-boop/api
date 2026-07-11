// ============================================================
// POST /api/send-otp  — إرسال كود OTP عبر Twilio Verify (SMS)
// الجسم: { "phone": "+9647701234567" }
// كل مفاتيح Twilio تبقى في متغيّرات البيئة على الخادم فقط.
// ============================================================
const { applyCors, validE164, rateLimit, readJson, clientIp } = require("./_lib");

module.exports = async (req, res) => {
  if (applyCors(req, res)) return;
  if (req.method !== "POST") return res.status(405).json({ error: "method_not_allowed" });

  try {
    const { phone } = await readJson(req);

    // 1) تحقّق من صيغة الرقم
    if (!validE164(phone)) {
      return res.status(400).json({ error: "invalid_phone", message: "صيغة الرقم غير صحيحة (E.164، مثال: +9647701234567)" });
    }

    // 2) تحديد المعدّل: 3 إرسالات لكل رقم في 15 دقيقة + حاجز على IP
    const ip = clientIp(req);
    const perPhone = rateLimit(`send:${phone}`, 3, 15 * 60 * 1000);
    if (!perPhone.ok) {
      return res.status(429).json({ error: "too_many_requests", retryAfter: perPhone.retryAfter, message: "محاولات كثيرة، جرّب لاحقاً" });
    }
    const perIp = rateLimit(`send-ip:${ip}`, 10, 15 * 60 * 1000);
    if (!perIp.ok) {
      return res.status(429).json({ error: "too_many_requests", retryAfter: perIp.retryAfter });
    }

    // 3) استدعاء Twilio Verify
    const sid = process.env.TWILIO_ACCOUNT_SID;
    const token = process.env.TWILIO_AUTH_TOKEN;
    const service = process.env.TWILIO_VERIFY_SERVICE_SID;
    if (!sid || !token || !service) {
      return res.status(500).json({ error: "server_misconfigured" });
    }

    const body = new URLSearchParams({ To: phone, Channel: "sms" });
    const twRes = await fetch(
      `https://verify.twilio.com/v2/Services/${service}/Verifications`,
      {
        method: "POST",
        headers: {
          Authorization: "Basic " + Buffer.from(`${sid}:${token}`).toString("base64"),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: body.toString(),
      }
    );

    const data = await twRes.json().catch(() => ({}));
    if (!twRes.ok) {
      // نُخفي تفاصيل Twilio الحساسة، ونرجّع رسالة عامة + رمز للتشخيص
      console.error("twilio send error:", data);
      const msg = data && data.code === 60203 ? "تجاوزت حد المحاولات لهذا الرقم"
                : data && data.code === 21608 ? "الرقم غير موثّق (حساب تجريبي) — وثّقه في Twilio"
                : "تعذّر إرسال الكود، تأكد من الرقم وحاول لاحقاً";
      return res.status(502).json({ error: "send_failed", code: data.code || null, message: msg });
    }

    return res.status(200).json({ ok: true, status: data.status || "pending" });
  } catch (e) {
    console.error("send-otp:", e);
    return res.status(500).json({ error: "internal_error" });
  }
};
