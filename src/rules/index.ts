import type { Revision, RuleDescriptor } from "../types.js";
import { rules as rules04 } from "./-04.js";
import { rules as rules05 } from "./-05.js";

export const defaultRevision: Revision = "-05";

const REGISTRY: Record<Revision, RuleDescriptor[]> = {
  "-04": rules04,
  "-05": rules05,
};

// Fail fast on data drift: a descriptor living in a revision file must carry
// that file's revision. Runs at import time.
for (const [revision, rules] of Object.entries(REGISTRY)) {
  for (const rule of rules) {
    if (rule.revision !== revision) {
      throw new Error(`Rule ${rule.id} carries revision ${rule.revision} but lives in the ${revision} ruleset.`);
    }
    const ids = rules.filter((other) => other.id === rule.id);
    if (ids.length > 1) {
      throw new Error(`Rule id ${rule.id} appears ${ids.length} times in the ${revision} ruleset.`);
    }
  }
}

export function getRuleset(revision: Revision): RuleDescriptor[] {
  const rules = REGISTRY[revision];
  if (!rules) {
    throw new Error(`Unknown revision ${JSON.stringify(revision)}; available: ${Object.keys(REGISTRY).join(", ")}.`);
  }
  return rules;
}
