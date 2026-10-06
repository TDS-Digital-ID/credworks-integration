let csrf, interaction;
const byId = (id) => document.getElementById(id);
const messages = {
  ENROLMENT_REQUIRED:
    "Access declined. Current enrolment is required. No new account session was created.",
  INSTITUTION_NOT_ALLOWED: "Access declined. This institution is not accepted.",
  RESULT_PENDING:
    "Still waiting for wallet completion. No account session has been created.",
  EVIDENCE_STALE: "Evidence expired. Start a fresh request.",
  INTERACTION_EXPIRED: "This interaction expired. Start a fresh request.",
};
async function session() {
  const response = await fetch("/api/session", {
    credentials: "same-origin",
    cache: "no-store",
  });
  if (!response.ok) throw Error("APPLICATION_UNAVAILABLE");
  const value = await response.json();
  csrf = value.csrf;
  if (value.status === "signed_in") {
    byId("outcome").textContent = "Signed in";
    byId("detail").textContent =
      "Credential verification and this application’s enrolment policy passed.";
    byId("account").textContent = "Application account: " + value.account_id;
  }
}
async function post(path, value) {
  const response = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json", "x-csrf-token": csrf },
    body: JSON.stringify(value),
  });
  const result = await response.json();
  if (!response.ok)
    throw Error(result.error?.code ?? "APPLICATION_UNAVAILABLE");
  return result;
}
function failure(error) {
  const code = /^[A-Z_]+$/.test(error.message)
    ? error.message
    : "APPLICATION_UNAVAILABLE";
  byId("outcome").textContent =
    code === "RESULT_PENDING" ? "Awaiting wallet" : "Request refused";
  byId("detail").textContent =
    messages[code] ??
    "No new account session was created. Check the configuration or start again.";
  byId("account").textContent = code;
}
async function begin(profile) {
  try {
    await session();
    interaction = await post("/api/interactions", { profile });
    byId("ceremony").hidden = false;
    byId("activation").href = interaction.activation_uri;
    byId("activation-text").textContent = interaction.activation_uri;
    byId("outcome").textContent = "Awaiting wallet";
    byId("detail").textContent =
      "Delivery acknowledgement alone does not establish verification or sign-in.";
    byId("account").textContent = "";
  } catch (error) {
    failure(error);
  }
}
byId("sign-in").onclick = () => begin("education_sign_in");
byId("eligibility").onclick = () => begin("education_eligibility");
byId("complete").onclick = async () => {
  if (!interaction) return;
  try {
    const value = await post(
      "/api/interactions/" + interaction.id + "/complete",
      {},
    );
    byId("ceremony").hidden = true;
    if (value.status === "eligible") {
      byId("outcome").textContent = "Eligibility confirmed";
      byId("detail").textContent =
        "Current enrolment and the accepted institution passed application policy. No student ID or account was requested.";
    } else {
      await session();
    }
  } catch (error) {
    failure(error);
  }
};
session().catch(failure);
