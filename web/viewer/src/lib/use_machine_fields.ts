import { useEffect, useState } from "react";
import type { ConsoleApi, MachineField } from "./console_api";
import { fieldsInPositionOrder } from "./machine_fields";

export function useMachineFields(api: ConsoleApi) {
  const [fields, setFields] = useState<MachineField[]>([]);
  const [unavailable, setUnavailable] = useState(false);
  useEffect(() => {
    let current = true;
    setFields([]);
    setUnavailable(false);
    void (async () => {
      try {
        const list = await api.listMachineFields();
        if (current) setFields(fieldsInPositionOrder(list.fields));
      } catch {
        if (current) setUnavailable(true);
      }
    })();
    return () => { current = false; };
  }, [api]);
  return { fields, unavailable };
}

