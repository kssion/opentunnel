import { createRequire } from "node:module";
import * as Net from "node:net";

/** Proxy URL schemes the SDK connects through. */
const SCHEMES = new Set(["http:", "https:"]);

type Env = Readonly<Record<string, string | undefined>>;

/**
 * Parses a proxy URL, taking a value without a scheme as `http://` like curl.
 * `source` names where the value came from; errors never include the URL,
 * which may carry credentials.
 */
export const parseProxy = (value: string, source: string): URL => {
  const trimmed = value.trim();
  let url: URL;
  try {
    url = new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`);
  } catch {
    throw new Error(`${source} is not a valid proxy URL`);
  }
  if (!SCHEMES.has(url.protocol)) {
    throw new Error(
      `${source} uses an unsupported proxy scheme '${url.protocol.slice(0, -1)}': OpenTunnel connects through http:// and https:// proxies`,
    );
  }
  return url;
};

const secure = (url: URL) => url.protocol === "https:" || url.protocol === "wss:";

const sameAddress = (entry: string, host: string): boolean => {
  const [address, bits] = entry.split("/", 2) as [string, string | undefined];
  const family = Net.isIP(address);
  if (family === 0 || Net.isIP(host) !== family) return false;
  const type = family === 4 ? "ipv4" : "ipv6";
  const list = new Net.BlockList();
  if (bits === undefined) list.addAddress(address, type);
  else if (/^\d+$/.test(bits)) list.addSubnet(address, Number(bits), type);
  else return false;
  return list.check(host, type);
};

/**
 * Whether `NO_PROXY` exempts `url`: comma or space separated entries, each
 * `*`, a domain that also covers its subdomains (a leading `.` or `*.` is
 * optional), an IP address or CIDR range, optionally with `:port`.
 */
export const bypassesProxy = (url: URL, noProxy: string): boolean => {
  const host = url.hostname.toLowerCase().replace(/^\[(.*)\]$/, "$1");
  const port = url.port === "" ? (secure(url) ? 443 : 80) : Number(url.port);
  for (const raw of noProxy.toLowerCase().split(/[\s,]+/)) {
    if (raw === "") continue;
    if (raw === "*") return true;
    let entry = raw;
    let entryPort: number | undefined;
    const bracketed = /^\[([^\]]+)\](?::(\d+))?$/.exec(raw);
    if (bracketed) {
      entry = bracketed[1]!;
      entryPort = bracketed[2] === undefined ? undefined : Number(bracketed[2]);
    } else {
      const parts = raw.split(":");
      if (parts.length === 2 && /^\d+$/.test(parts[1]!)) {
        entry = parts[0]!;
        entryPort = Number(parts[1]);
      }
    }
    if (entryPort !== undefined && entryPort !== port) continue;
    if (sameAddress(entry, host)) return true;
    const domain = entry.replace(/^\*?\./, "");
    if (domain !== "" && (host === domain || host.endsWith(`.${domain}`))) return true;
  }
  return false;
};

/**
 * The proxy the environment selects for `url`: `HTTPS_PROXY` for `https:`
 * and `wss:`, `HTTP_PROXY` for `http:` and `ws:`, then `ALL_PROXY` (each
 * upper case first), unless `NO_PROXY` exempts the host. Throws when the
 * selected proxy is not an `http://` or `https://` URL.
 */
export const proxyFromEnv = (url: URL, env: Env): URL | undefined => {
  const names = secure(url)
    ? ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]
    : ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"];
  const name = names.find((name) => env[name]?.trim());
  if (name === undefined) return undefined;
  if (bypassesProxy(url, env.NO_PROXY || env.no_proxy || "")) return undefined;
  return parseProxy(env[name]!, name);
};

/** How the SDK reaches the API and the bridge. */
export interface Transport {
  /** Replaces the runtime's `fetch` for API calls; `undefined` uses it as is. */
  readonly fetch?: typeof globalThis.fetch;
  /** Opens the bridge WebSocket. Throws when the environment selects an unusable proxy. */
  readonly webSocket: (url: URL, protocols: string[], headers: Record<string, string>) => WebSocket;
}

/** Bun's and Node's WebSocket take options with request headers, Bun's also a proxy, Deno's a client. */
type WebSocketOptions = {
  readonly protocols: string[];
  readonly headers: Record<string, string>;
  readonly proxy?: string;
  readonly dispatcher?: unknown;
  readonly client?: unknown;
};
type WebSocketConstructor = new (url: URL, options: WebSocketOptions) => WebSocket;
type Fetch = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

const runtimeWebSocket = (url: URL, options: WebSocketOptions) =>
  new (WebSocket as unknown as WebSocketConstructor)(url, options);

const withInit = (fetch: Fetch, extra: Record<string, unknown>) =>
  ((input: string | URL | Request, init?: RequestInit) =>
    fetch(input, { ...init, ...extra } as RequestInit)) as typeof globalThis.fetch;

interface Undici {
  readonly ProxyAgent: new (options: { readonly uri: string; readonly proxyTunnel: boolean }) => unknown;
  readonly fetch: Fetch;
  readonly WebSocket: WebSocketConstructor;
}

const loadUndici = (): Undici => {
  try {
    return createRequire(import.meta.url)("undici") as Undici;
  } catch (cause) {
    throw new Error(
      "The proxy option needs the 'undici' package on Node: install it next to @opentunnel/client, or let Node use HTTPS_PROXY with NODE_USE_ENV_PROXY=1",
      { cause },
    );
  }
};

const runtime = (): "bun" | "deno" | "node" =>
  "Bun" in globalThis ? "bun" : "Deno" in globalThis ? "deno" : "node";

/**
 * Connects through `proxy` when given (an `http://` or `https://` URL, for
 * the API and the bridge), else through the proxy the environment selects,
 * as the runtime's `fetch` does: Bun's WebSocket ignores the environment, so
 * the SDK resolves it for the bridge; Node's and Deno's apply it themselves.
 * Throws when `proxy` is not usable.
 */
export const makeTransport = (proxy?: string, env: Env = process.env): Transport => {
  const explicit = proxy === undefined ? undefined : parseProxy(proxy, "The proxy option").href;
  switch (runtime()) {
    case "bun":
      return {
        ...(explicit === undefined ? {} : { fetch: withInit(globalThis.fetch, { proxy: explicit }) }),
        webSocket: (url, protocols, headers) => {
          const selected = explicit ?? proxyFromEnv(url, env)?.href;
          return runtimeWebSocket(url, { protocols, headers, ...(selected ? { proxy: selected } : {}) });
        },
      };
    case "deno": {
      if (explicit === undefined) break;
      const Deno = (globalThis as unknown as {
        readonly Deno: { createHttpClient(options: { readonly proxy: { readonly url: string } }): unknown };
      }).Deno;
      const client = Deno.createHttpClient({ proxy: { url: explicit } });
      return {
        fetch: withInit(globalThis.fetch, { client }),
        webSocket: (url, protocols, headers) => runtimeWebSocket(url, { protocols, headers, client }),
      };
    }
    case "node": {
      if (explicit === undefined) break;
      const undici = loadUndici();
      const dispatcher = new undici.ProxyAgent({ uri: explicit, proxyTunnel: true });
      return {
        fetch: withInit(undici.fetch, { dispatcher }),
        webSocket: (url, protocols, headers) => new undici.WebSocket(url, { protocols, headers, dispatcher }),
      };
    }
  }
  return { webSocket: (url, protocols, headers) => runtimeWebSocket(url, { protocols, headers }) };
};
