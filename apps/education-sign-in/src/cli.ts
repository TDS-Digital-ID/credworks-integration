import { startApplication } from "./server.js";
const missing = [
  "EDUCATION_APP_ORIGIN",
  "EDUCATION_RUNTIME_MANAGEMENT",
  "PARTNER_MANAGEMENT_TOKEN",
  "EDUCATION_TRUSTED_ISSUER",
  "EDUCATION_VERIFIER_DID",
  "EDUCATION_INSTITUTION",
  "EDUCATION_APP_DATABASE_URL",
].filter((name) => !process.env[name]);
try {
  const required = (name: string) => {
    const value = process.env[name];
    if (!value) throw Error("configuration unavailable");
    return value;
  };
  const port = Number(process.env.EDUCATION_APP_PORT ?? 3082);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535)
    throw Error("configuration unavailable");
  const app = await startApplication({
    origin: required("EDUCATION_APP_ORIGIN"),
    port,
    listenHost: "0.0.0.0",
    runtimeManagement: required("EDUCATION_RUNTIME_MANAGEMENT"),
    runtimeToken: required("PARTNER_MANAGEMENT_TOKEN"),
    issuer: required("EDUCATION_TRUSTED_ISSUER"),
    verifierDid: required("EDUCATION_VERIFIER_DID"),
    institution: required("EDUCATION_INSTITUTION"),
    database: required("EDUCATION_APP_DATABASE_URL"),
  });
  console.log("education_application_ready");
  for (const signal of ["SIGINT", "SIGTERM"] as const)
    process.once(signal, () => {
      void app.close().then(() => process.exit(0));
    });
} catch {
  console.error(
    missing.length
      ? `education_application_configuration_missing: ${missing.join(", ")}`
      : "education_application_unavailable: check configuration, database connectivity and listener availability",
  );
  process.exitCode = 1;
}
