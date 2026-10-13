import { normalizeExposeName } from "@/lib/exposeName";
import type { ShareKind } from "@/lib/shareLink";

const OFFICIAL_INSTALLER_BASE_URL =
  "https://github.com/gosuda/portal-tunnel/releases/latest/download";

export type TunnelCommandOS = "unix" | "windows";

export interface TunnelCommandOptions {
  currentOrigin: string;
  target: string;
  name: string;
  relayUrls: string[];
  discovery: boolean;
  thumbnailURL: string;
  enableUDP?: boolean;
  udpPort?: string;
  os: TunnelCommandOS;
  /** How the share input was classified; defaults to "port". */
  shareKind?: ShareKind;
  /** Local path passed to `--serve` when shareKind is "file". */
  servePath?: string;
}


export function buildTunnelCommand(options: TunnelCommandOptions): string {
  const { installLine, exposeHead, exposeOptions } =
    buildTunnelCommandParts(options);

  return joinTunnelCommand(installLine, exposeHead, exposeOptions);
}

function buildTunnelCommandParts({
  currentOrigin,
  discovery,
  enableUDP = false,
  name,
  os,
  relayUrls,
  target,
  thumbnailURL,
  udpPort = "",
  shareKind = "port",
  servePath = "",
}: TunnelCommandOptions): {
  installLine: string;
  exposeHead: string;
  exposeOptions: string[];
} {
  const isFile = shareKind === "file";
  const targetValue = target.trim() === "" ? "3000" : target.trim();
  const normalizedName = normalizeExposeName(name);
  const relayURLValue =
    relayUrls.length > 0 ? relayUrls.join(",") : currentOrigin;
  const leadingArgs = isFile
    ? ["--serve", formatToken(servePath, os)]
    : [formatToken(targetValue, os)];
  const installScriptURL = `${OFFICIAL_INSTALLER_BASE_URL}/install.sh`;
  const installPowerShellURL = `${OFFICIAL_INSTALLER_BASE_URL}/install.ps1`;

  const exposeArgs: string[] = [];

  if (normalizedName !== "") {
    exposeArgs.push(`--name ${formatToken(normalizedName, os)}`);
  }
  if (relayUrls.length > 0) {
    exposeArgs.push(`--relays ${formatToken(relayURLValue, os)}`);
  }
  if (!discovery) {
    exposeArgs.push("--discovery=false");
  }

  const normalizedThumbnailURL = normalizeAbsoluteHTTPURL(thumbnailURL);
  if (normalizedThumbnailURL !== "") {
    exposeArgs.push(`--thumbnail ${formatToken(normalizedThumbnailURL, os)}`);
  }
  if (enableUDP) {
    exposeArgs.push("--udp");
    const normalizedUDPPort = udpPort.trim();
    if (normalizedUDPPort !== "") {
      exposeArgs.push(`--udp-addr ${formatToken(normalizedUDPPort, os)}`);
    }
  }

  if (os === "windows") {
    return {
      installLine: [
        `$ProgressPreference = 'SilentlyContinue'`,
        `irm ${formatToken(installPowerShellURL, os)} | iex`,
      ].join("\n"),
      exposeHead: "portal expose",
      exposeOptions: [...leadingArgs, ...exposeArgs],
    };
  }

  return {
    // bash runs the installer in a subshell, so add its install dirs to this shell's PATH.
    installLine: `curl -fsSL ${formatToken(installScriptURL, os)} | bash && export PATH="$HOME/.local/bin:$HOME/bin:$PATH"`,
    exposeHead: "portal expose",
    exposeOptions: [...leadingArgs, ...exposeArgs],
  };
}

export function buildTunnelPreviewURL(
  origin: string,
  name: string
): string {
  const normalized = normalizeExposeName(name);
  if (normalized === "") {
    return "";
  }
  const baseHost = getRelayOriginHost(origin);
  if (baseHost === "") {
    return "";
  }
  return `https://${normalized}.${baseHost}`;
}

export function buildServiceStatusHostname(
  origin: string,
  name: string
): string {
  const relayHost = getRelayOriginHost(origin);
  if (relayHost === "") {
    return "";
  }
  const normalized = normalizeExposeName(name);
  if (normalized === "") {
    return "";
  }
  return `${normalized}.${relayHost}`;
}

export function normalizeAbsoluteHTTPURL(raw: string): string {
  const trimmed = raw.trim();
  if (trimmed === "") {
    return "";
  }

  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return "";
    }
    return parsed.toString();
  } catch {
    return "";
  }
}

function getRelayOriginHost(origin: string): string {
  try {
    const parsed = new URL(origin);
    return parsed.hostname.trim().toLowerCase();
  } catch {
    return "";
  }
}

function quoteShellValue(value: string): string {
  return "'" + value.replace(/'/g, `'"'"'`) + "'";
}

function quotePowerShellValue(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

function formatToken(value: string, os: TunnelCommandOS): string {
  if (/^[A-Za-z0-9:/.=_-]+$/.test(value)) {
    return value;
  }
  return os === "windows" ? quotePowerShellValue(value) : quoteShellValue(value);
}

function joinTunnelCommand(
  installLine: string,
  exposeHead: string,
  exposeOptions: string[]
): string {
  return [installLine, [exposeHead, ...exposeOptions].join(" ")].join("\n");
}
