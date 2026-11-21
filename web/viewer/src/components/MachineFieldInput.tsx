import type { MachineField } from "../lib/console_api";

export function MachineFieldInput({ field, value, onChange, disabled, testId, maxLength, emptyLabel }: {
  field?: MachineField;
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
  testId?: string;
  maxLength?: number;
  emptyLabel?: string;
}) {
  if (field?.type === "choice" || field?.type === "boolean") {
    const options = field.type === "boolean" ? ["true", "false"] : field.choices ?? [];
    return (
      <select className="panel__input" value={value} onChange={(e) => onChange(e.target.value)} disabled={disabled} data-testid={testId}>
        <option value="" disabled={!emptyLabel}>{emptyLabel ?? "Unset"}</option>
        {options.map((option) => <option key={option} value={option}>{option}</option>)}
      </select>
    );
  }
  return (
    <input
      className="panel__input"
      type={field?.type === "date" ? "date" : "text"}
      min={field?.type === "date" ? "1900-01-01" : undefined}
      max={field?.type === "date" ? "2999-12-31" : undefined}
      inputMode={field?.type === "number" ? "decimal" : undefined}
      maxLength={maxLength}
      placeholder={emptyLabel}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      disabled={disabled}
      data-testid={testId}
    />
  );
}

