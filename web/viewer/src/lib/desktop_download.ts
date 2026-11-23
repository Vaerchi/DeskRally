/** Resolve only the published Windows client path, never an arbitrary manifest URL. */
export function desktopDownload(data: unknown, origin: string): { version: string; url: string } | null {
  if (!data || typeof data !== "object") return null;
  const m = data as Record<string, unknown>;
  if (typeof m.version !== "string" || !/^(0|[1-9]\d{0,4})\.(0|[1-9]\d{0,4})\.(0|[1-9]\d{0,4})$/.test(m.version)) return null;
  const path = `/download/client/releases/${m.version}/DeskRallyClient.exe`;
  if (m.url !== new URL(path, origin).href && m.url !== `https://main.deskrally.com${path}`) return null;
  if (typeof m.sha256 !== "string" || !/^[a-f0-9]{64}$/i.test(m.sha256)) return null;
  if (typeof m.size !== "number" || !Number.isSafeInteger(m.size) || m.size <= 0) return null;
  return { version: m.version, url: path };
}
