/**
 * Backstage system-info panel: a read-only summary of the remote machine's identity and resource
 * usage, rendered natively in the technician's browser (docs/04-backstage.md Part 1).
 *
 * Presentational only: the `SystemInfo` comes in as a prop from a typed source. Null fields render
 * as "—"; memory/uptime are humanized via the shared formatters.
 */

import {
  formatBytes,
  formatOptional,
  formatUptime,
  type SystemInfo,
} from "../backstage/panels";

export interface SystemInfoPanelProps {
  info: SystemInfo;
}

export function SystemInfoPanel({ info }: SystemInfoPanelProps) {
  const memUsage = memPercent(info.used_memory_bytes, info.total_memory_bytes);
  const swapUsage = memPercent(info.used_swap_bytes, info.total_swap_bytes);
  const cores =
    info.physical_cores != null
      ? `${info.logical_cpus} logical / ${info.physical_cores} physical`
      : `${info.logical_cpus} logical`;

  const rows: [string, string][] = [
    ["Hostname", formatOptional(info.hostname)],
    ["Logged-in user", formatOptional(info.logged_in_user)],
    ["OS", formatOptional(info.os_long_version ?? info.os_name)],
    ["Kernel / build", formatOptional(info.kernel_version)],
    ["CPU", info.cpu_brand],
    ["Architecture", info.cpu_arch],
    ["Cores", cores],
    ["Memory", `${formatBytes(info.used_memory_bytes)} / ${formatBytes(info.total_memory_bytes)}${memUsage}`],
    ["Swap", `${formatBytes(info.used_swap_bytes)} / ${formatBytes(info.total_swap_bytes)}${swapUsage}`],
    ["Uptime", formatUptime(info.uptime_seconds)],
  ];

  return (
    <div className="panel panel--sysinfo">
      <dl className="sysinfo__grid">
        {rows.map(([label, value]) => (
          <div className="sysinfo__row" key={label}>
            <dt className="sysinfo__label">{label}</dt>
            <dd className="sysinfo__value">{value}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function memPercent(used: number, total: number): string {
  if (!Number.isFinite(used) || !Number.isFinite(total) || total <= 0) return "";
  return ` (${((used / total) * 100).toFixed(0)}%)`;
}
