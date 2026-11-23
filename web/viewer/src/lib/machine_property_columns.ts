import type { MachineRecord } from "./console_api";

export function machinePropertyKeys(rows: readonly Pick<MachineRecord, "properties">[]): string[] {
  const keys = new Set<string>();
  for (const row of rows) {
    for (const key of Object.keys(row.properties ?? {})) keys.add(key);
  }
  return [...keys].sort();
}

export function togglePropertyColumn(selected: readonly string[], key: string): string[] {
  return selected.includes(key) ? selected.filter((column) => column !== key) : [...selected, key];
}

export function machinePropertyValue(row: Pick<MachineRecord, "properties">, key: string): string {
  const bag = row.properties;
  return bag && Object.prototype.hasOwnProperty.call(bag, key) ? bag[key] : "";
}
