import type { DynamicGroup, DynamicGroupCondition, DynamicGroupMatch, DynamicGroupOperator } from "./console_api";

export const MAX_DYNAMIC_GROUP_CONDITIONS = 10;

export const dynamicGroupFields = {
  property: "Property",
  os: "OS",
  hostname: "Hostname or alias",
  online: "Online",
  agent_version: "Agent version",
};

export type DynamicGroupField = keyof typeof dynamicGroupFields;

export const dynamicGroupOperatorLabels: Record<DynamicGroupOperator, string> = {
  equals: "=",
  not_equals: "≠",
  contains: "contains",
  starts_with: "starts with",
  exists: "exists",
  not_exists: "does not exist",
  version_at_least: "≥",
};

const textOperators = ["equals", "not_equals", "contains", "starts_with"] as const;
export const dynamicGroupOperators: Record<DynamicGroupField, readonly DynamicGroupOperator[]> = {
  property: [...textOperators, "exists", "not_exists"],
  os: textOperators,
  hostname: textOperators,
  online: ["equals"],
  agent_version: [...textOperators, "version_at_least"],
};

export function conditionTakesValue(op: DynamicGroupOperator): boolean {
  return op !== "exists" && op !== "not_exists";
}

export function summarizeDynamicGroup(group: DynamicGroup): string {
  const conditions = group.conditions ?? [{
    field: `property:${group.property_key}`,
    op: group.property_value ? "equals" : "exists",
    value: group.property_value,
  } satisfies DynamicGroupCondition];
  return conditions.map(({ field, op, value }) => {
    const label = field.startsWith("property:") ? field.slice("property:".length) : field.replace("_", " ");
    const predicate = `${label} ${dynamicGroupOperatorLabels[op]}`;
    return conditionTakesValue(op) ? `${predicate} ${value === "" ? '""' : value}` : predicate;
  }).join(group.match === "any" ? " OR " : " AND ");
}

export function validateDynamicGroup(name: string, match: DynamicGroupMatch, conditions: DynamicGroupCondition[]): string | null {
  const encoder = new TextEncoder();
  if (!name.trim() || encoder.encode(name.trim()).length > 128) return "Enter a name of at most 128 bytes.";
  if (match !== "all" && match !== "any") return "Choose Match all or Match any.";
  if (!conditions.length || conditions.length > MAX_DYNAMIC_GROUP_CONDITIONS) {
    return `Add 1 to ${MAX_DYNAMIC_GROUP_CONDITIONS} conditions.`;
  }
  for (const [index, { field, op, value }] of conditions.entries()) {
    const prefix = `Condition ${index + 1}:`;
    const property = field.startsWith("property:");
    const fieldType = property ? "property" : field;
    if ((!property && field === "property") || !Object.prototype.hasOwnProperty.call(dynamicGroupOperators, fieldType)) {
      return `${prefix} unknown field.`;
    }
    if (!dynamicGroupOperators[fieldType as DynamicGroupField].includes(op)) return `${prefix} invalid operator.`;
    if (property) {
      const key = field.slice("property:".length);
      if (!key || encoder.encode(key).length > 128) return `${prefix} enter a property key of 1 to 128 bytes.`;
    }
    if (encoder.encode(value).length > 4096) return `${prefix} value exceeds 4096 bytes.`;
    if (!conditionTakesValue(op) && value !== "") return `${prefix} leave the value empty.`;
    if (field === "online" && value !== "true" && value !== "false") return `${prefix} choose true or false.`;
    if (op === "version_at_least") {
      const components = value.split("+", 1)[0].split(".");
      if (components.some((component) => !component || /[^0-9]/.test(component))) {
        return `${prefix} enter a dotted numeric version.`;
      }
    }
  }
  return null;
}
