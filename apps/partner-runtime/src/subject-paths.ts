import type { ScalarCredentialDefinition } from "@unsw-vc/identity-core-node";

// Paths and subject values have already been validated by the shared core.
export function declaredPath(
  claim: ScalarCredentialDefinition["claims"][number],
): string[] {
  return claim.path ?? ["credentialSubject", claim.name];
}
export function subjectValue(
  subject: unknown,
  path: readonly string[],
): unknown {
  let value = subject;
  for (const component of path.slice(1)) {
    if (
      !value ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      !Object.hasOwn(value, component)
    )
      return undefined;
    value = (value as Record<string, unknown>)[component];
  }
  return value;
}

// The core materializes disclosures but retains `_sd` on their containers.
// Only strict prefixes of declared paths are containers; a declared whole value
// must remain untouched, including any invalid metadata for core validation.
export function materializedBusinessSubject(
  definition: ScalarCredentialDefinition,
  subject: unknown,
): Record<string, unknown> {
  const paths = definition.claims.map(declaredPath);
  const visit = (value: unknown, path: string[]): Record<string, unknown> => {
    if (!value || typeof value !== "object" || Array.isArray(value))
      throw Error("invalid materialized subject container");
    return Object.fromEntries(
      Object.entries(value)
        .filter(([name]) => name !== "_sd")
        .map(([name, child]) => {
          const childPath = [...path, name];
          const implicit = paths.some(
            (declared) =>
              declared.length > childPath.length &&
              childPath.every(
                (component, index) => declared[index] === component,
              ),
          );
          return [name, implicit ? visit(child, childPath) : child];
        }),
    );
  };
  return visit(subject, ["credentialSubject"]);
}
