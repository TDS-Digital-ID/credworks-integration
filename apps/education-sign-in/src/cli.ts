import { startApplication } from "./server.js";
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
  console.error("education_application_unavailable");
  process.exitCode = 1;
}
