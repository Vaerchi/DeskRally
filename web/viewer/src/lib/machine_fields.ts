import type { MachineField, MachineRecord } from "./console_api";

type FieldValueType = Pick<MachineField, "type" | "choices">;

export function canonicalFieldValue(field: FieldValueType, input: string): string | undefined {
  if (field.type === "text") return input;
  if (/[\p{Cc}\p{Cs}]/u.test(input)) return undefined;
  const value = input.replace(/^ +| +$/g, "");
  if (!value) return undefined;

  switch (field.type) {
    case "number": {
      if (input.length > 64 || !/^-?[0-9]+(?:\.[0-9]+)?(?![\s\S])/.test(value)) return undefined;
      const negative = value.startsWith("-");
      const [whole, decimals = ""] = (negative ? value.slice(1) : value).split(".");
      const integer = whole.replace(/^0+/, "") || "0";
      const fraction = decimals.replace(/0+$/, "");
      if (integer.length > 15 || fraction.length > 6 || (negative && integer === "0" && !fraction)) return undefined;
      return (negative ? "-" : "") + integer + (fraction ? "." + fraction : "");
    }
    case "date":
      if (!/^[0-9]{4}-[0-9]{2}-[0-9]{2}(?![\s\S])/.test(value) || value < "1900-01-01" || value > "2999-12-31") return undefined;
      {
        const date = new Date(value + "T00:00:00Z");
        return Number.isFinite(date.getTime()) && date.toISOString().slice(0, 10) === value ? value : undefined;
      }
    case "boolean":
      return value === "true" || value === "false" ? value : undefined;
    case "choice":
      return field.choices?.includes(value) ? value : undefined;
  }
}

/** Empty operands retain the API's existing key-exists behavior. */
export function fieldFilterOperand(field: FieldValueType | undefined, input: string): string | undefined {
  return field && input !== "" ? canonicalFieldValue(field, input) : input;
}

export function compareCanonicalDecimals(a: string, b: string): number {
  const aNegative = a.startsWith("-");
  const bNegative = b.startsWith("-");
  if (aNegative !== bNegative) return aNegative ? -1 : 1;
  const [aWhole, aFraction = ""] = (aNegative ? a.slice(1) : a).split(".");
  const [bWhole, bFraction = ""] = (bNegative ? b.slice(1) : b).split(".");
  const magnitude = aWhole.length - bWhole.length || compareStrings(aWhole, bWhole) ||
    compareStrings(aFraction.padEnd(6, "0"), bFraction.padEnd(6, "0"));
  return aNegative && magnitude !== 0 ? -magnitude : magnitude;
}

function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export function storedFieldValue(row: Pick<MachineRecord, "properties">, key: string): string | undefined {
  const properties = row.properties;
  return properties && Object.prototype.hasOwnProperty.call(properties, key) ? properties[key] : undefined;
}

export function compareFieldValues(field: FieldValueType, a: string | undefined, b: string | undefined, descending: boolean): number {
  const rank = (value: string | undefined) => value === undefined ? 1 : canonicalFieldValue(field, value) === value ? 0 : 2;
  const aRank = rank(a);
  const bRank = rank(b);
  if (aRank !== bRank) return aRank - bRank;
  if (aRank !== 0 || a === undefined || b === undefined) return 0;
  const comparison = field.type === "number" ? compareCanonicalDecimals(a, b)
    : field.type === "choice" ? (field.choices?.indexOf(a) ?? 0) - (field.choices?.indexOf(b) ?? 0)
    : field.type === "text" ? a.localeCompare(b)
    : compareStrings(a, b);
  return descending ? -comparison : comparison;
}

export function fieldsInPositionOrder(fields: readonly MachineField[]): MachineField[] {
  return [...fields].sort((a, b) => a.position - b.position);
}

