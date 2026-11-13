import native from "../../../../docs/guides/native-server.md?raw";
import docker from "../../../../docs/guides/server-deployment.md?raw";
import clients from "../../../../docs/guides/client-deployment.md?raw";
import deployment from "../../../../docs/10-deployment.md?raw";
import backups from "../../../../docs/22-backup-and-restore.md?raw";
import troubleshooting from "../../../../docs/connection-troubleshooting.md?raw";
import configuration from "../../../../docs/guides/server-configuration.md?raw";
import environmentTemplate from "../../../../deploy/.env.example?raw";

export interface PublicDoc {
  id: string;
  title: string;
  summary: string;
  group: "Installation guides" | "Technical reference";
  source: string;
  text: string;
}

// Explicit publication list. Internal handoffs, audit reports and other repository files are
// never exposed by a glob or by a user-supplied path.
export const PUBLIC_DOCS: PublicDoc[] = [
  { id: "docker", title: "Docker on Linux", group: "Installation guides", source: "docs/guides/server-deployment.md", text: docker,
    summary: "Install the release, migrate the database, bootstrap an owner and publish agents." },
  { id: "native", title: "Windows & Linux without Docker", group: "Installation guides", source: "docs/guides/native-server.md", text: native,
    summary: "Build native packages and configure Windows services or Linux systemd. Preview deployment path." },
  { id: "clients", title: "Install agents", group: "Installation guides", source: "docs/guides/client-deployment.md", text: clients,
    summary: "Interactive and silent installation, enrollment, support tools and desktop clients." },
  { id: "deployment", title: "Build & deployment reference", group: "Technical reference", source: "docs/10-deployment.md", text: deployment,
    summary: "Full source-build instructions: codecs, backend processes, migrations, agent identity, HTTPS and TURN." },
  { id: "configuration", title: "Server configuration reference", group: "Technical reference", source: "docs/guides/server-configuration.md",
    text: `${configuration}\n\n## Complete Compose environment template\n\nThis is the checked-in deploy/.env.example from the same source revision as this website. It is a template, not a populated operator configuration.\n\n\`\`\`dotenv\n${environmentTemplate}\n\`\`\`\n`,
    summary: "Database roles, persistent keys, service-token pairs, proxy trust, recordings, TURN and the complete environment template." },
  { id: "backups", title: "Backup & restore runbook", group: "Technical reference", source: "docs/22-backup-and-restore.md", text: backups,
    summary: "Encrypted database dumps, key and recording backups, restore commands, audit checks and recovery drills." },
  { id: "troubleshooting", title: "Connection troubleshooting", group: "Technical reference", source: "docs/connection-troubleshooting.md", text: troubleshooting,
    summary: "Interpret video counters, diagnose relay-credential limits and capture useful failure evidence." },
];

export function findPublicDoc(id: string) {
  return PUBLIC_DOCS.find(doc => doc.id === id);
}

export function resolveDocLink(href: string, source: string): string | null {
  if (/^https:\/\//i.test(href) || href.startsWith("#")) return href;
  if (/^\/(?!\/)/.test(href) && !href.split(/[?#]/)[0].endsWith(".md")) return href;
  if (/^[a-z][a-z0-9+.-]*:/i.test(href) || href.startsWith("//")) return null;
  try {
    const target = new URL(href, `https://docs.invalid/${source}`);
    const doc = PUBLIC_DOCS.find(item => `/${item.source}` === target.pathname);
    return doc ? `/docs/${doc.id}${target.hash}` : null;
  } catch { return null; }
}

export interface DocHeading { line: number; level: number; title: string; id: string }
export function docHeadings(source: string): DocHeading[] {
  const headings: DocHeading[] = [];
  const used = new Map<string, number>();
  let fence: string | null = null;
  source.replace(/\r/g, "").split("\n").forEach((text, line) => {
    const marker = /^\s*(`{3,}|~{3,})/.exec(text)?.[1];
    if (marker) {
      if (!fence) fence = marker;
      else if (marker[0] === fence[0] && marker.length >= fence.length) fence = null;
      return;
    }
    if (fence) return;
    const match = /^(#{1,6})\s+(.+?)\s*#*\s*$/.exec(text);
    if (!match) return;
    const title = match[2];
    const base = title.toLowerCase().replace(/[^a-z0-9\s-]/g, "").trim().replace(/\s+/g, "-");
    const count = used.get(base) ?? 0;
    used.set(base, count + 1);
    headings.push({ line, level: match[1].length, title, id: count ? `${base}-${count}` : base });
  });
  return headings;
}
