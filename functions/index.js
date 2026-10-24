const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { defineSecret } = require("firebase-functions/params");
const { initializeApp } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");

initializeApp();

const ADMIN_ACCESS_KEY = defineSecret("ADMIN_ACCESS_KEY");

exports.redeemAdminKey = onCall(
  { region: "us-central1", secrets: [ADMIN_ACCESS_KEY], enforceAppCheck: false },
  async (request) => {
    if (!request.auth) {
      throw new HttpsError("unauthenticated", "Faça login antes de validar a chave.");
    }

    const key = request.data && typeof request.data.key === "string"
      ? request.data.key.trim()
      : "";

    if (!key || key.length > 256) {
      throw new HttpsError("invalid-argument", "Chave inválida.");
    }

    const expectedKey = ADMIN_ACCESS_KEY.value();
    if (!expectedKey || key !== expectedKey) {
      // Não revelar se a chave está parcialmente correta.
      throw new HttpsError("permission-denied", "Chave incorreta.");
    }

    const user = await getAuth().getUser(request.auth.uid);
    const claims = { ...(user.customClaims || {}), admin: true };
    await getAuth().setCustomUserClaims(request.auth.uid, claims);

    return { success: true, message: "👑 Acesso administrativo liberado. Saia e entre novamente se o selo não atualizar." };
  }
);
