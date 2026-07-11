// ============================================================
// POST /api/verify-otp — التحقق من الكود ثم إصدار Firebase Custom Token
// الجسم: { "phone": "+9647701234567", "code": "123456" }
// عند النجاح: نُنشئ/نجلب مستخدم Firebase بالـ phone كـ uid ونعيد customToken.
// الواجهة تسجّل الدخول بـ signInWithCustomToken(customToken).
// ============================================================
const { getAdmin, applyCors, validE164, rateLimit, readJson, clientIp } = require("./_lib");

module.exports = async (req, res) => {
  if (applyCors(req, res)) return;
  if (req.method !== "POST") return res.status(405).json({ error: "method_not_allowed" });

  try {
    const { phone, code } = await readJson(req);

    if (!validE164(phone)) {
      return res.status(400).json({ error: "invalid_phone" });
    }
    if (!/^\d{4,8}$/.test(String(code || ""))) {
      return res.status(400).json({ error: "invalid_code", message: "الكود غير صحيح" });
    }

    // تحديد المعدّل على التحقق: 6 محاولات لكل رقم في 15 دقيقة
    const ip = clientIp(req);
    const rl = rateLimit(`verify:${phone}`, 6, 15 * 60 * 1000);
    if (!rl.ok) return res.status(429).json({ error: "too_many_requests", retryAfter: rl.retryAfter });
    const rlIp = rateLimit(`verify-ip:${ip}`, 20, 15 * 60 * 1000);
    if (!rlIp.ok) return res.status(429).json({ error: "too_many_requests", retryAfter: rlIp.retryAfter });

    const sid = process.env.TWILIO_ACCOUNT_SID;
    const token = process.env.TWILIO_AUTH_TOKEN;
    const service = process.env.TWILIO_VERIFY_SERVICE_SID;
    if (!sid || !token || !service) return res.status(500).json({ error: "server_misconfigured" });

    // 1) التحقق من الكود عند Twilio
    const body = new URLSearchParams({ To: phone, Code: String(code) });
    const twRes = await fetch(
      `https://verify.twilio.com/v2/Services/${service}/VerificationCheck`,
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
      console.error("twilio verify error:", data);
      // 20404 = انتهت صلاحية الكود أو لا يوجد تحقق جارٍ
      const msg = data && data.code === 20404 ? "انتهت صلاحية الكود، اطلب كوداً جديداً" : "تعذّر التحقق، حاول لاحقاً";
      return res.status(502).json({ error: "verify_failed", code: data.code || null, message: msg });
    }
    if (data.status !== "approved") {
      return res.status(401).json({ error: "wrong_code", message: "الكود غير صحيح" });
    }

    // 2) الكود صحيح — نُنشئ/نجلب المستخدم في Firebase
    const admin = getAdmin();
    // uid ثابت مشتق من الرقم (بدون + والرموز) ليكون متسقاً
    const uid = "phone_" + phone.replace(/[^\d]/g, "");
    let isNew = false;
    try {
      await admin.auth().getUser(uid);
    } catch (e) {
      if (e.code === "auth/user-not-found") {
        await admin.auth().createUser({ uid, phoneNumber: phone });
        isNew = true;
      } else {
        throw e;
      }
    }

    // 3) إصدار Custom Token لتسجيل الدخول في الواجهة
    const customToken = await admin.auth().createCustomToken(uid, { phone });

    return res.status(200).json({ ok: true, customToken, uid, phone, isNew });
  } catch (e) {
    console.error("verify-otp:", e);
    return res.status(500).json({ error: "internal_error" });
  }
};
