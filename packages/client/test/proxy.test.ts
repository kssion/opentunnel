import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { create, OpenTunnelClientError, OpenTunnelStorage, type OpenTunnelClientEvent } from "../src/promise/index.js";
import { bypassesProxy, makeTransport, proxyFromEnv } from "../src/effect/proxy.js";
import { fakeRelay, testIdentity, type FakeRelay } from "./fake-relay.js";
import { httpProxy, type HttpProxy } from "./http-proxy.js";

const PROXY_ENV = [
  "HTTP_PROXY",
  "http_proxy",
  "HTTPS_PROXY",
  "https_proxy",
  "ALL_PROXY",
  "all_proxy",
  "NO_PROXY",
  "no_proxy",
];

let identity: Awaited<ReturnType<typeof testIdentity>>;
let relay: FakeRelay;
let proxy: HttpProxy;
let saved: Record<string, string | undefined>;

beforeEach(async () => {
  saved = Object.fromEntries(PROXY_ENV.map((name) => [name, process.env[name]]));
  // Empty rather than deleted: Bun's fetch no longer sees a proxy variable set again after a delete.
  for (const name of PROXY_ENV) process.env[name] = "";
  identity = await testIdentity();
  relay = fakeRelay(identity);
  proxy = await httpProxy();
});

afterEach(async () => {
  for (const [name, value] of Object.entries(saved)) process.env[name] = value ?? "";
  relay.stop();
  await proxy.stop();
});

/** The relay under a name only the test proxy resolves. */
const viaName = () => `http://relay.test:${relay.url.port}`;

const clientFor = async (api: string, proxyOption?: string) => {
  const store = OpenTunnelStorage.memory();
  await store.save("default", identity);
  return create({ api, store, ...(proxyOption === undefined ? {} : { proxy: proxyOption }) });
};

describe("bridge proxy", () => {
  test("goes through HTTP_PROXY for ws://", async () => {
    process.env.HTTP_PROXY = proxy.url;
    const client = await clientFor(viaName());
    const connection = await client.tunnel.connect({ routes: { api: "127.0.0.1:9" } });
    expect(await relay.next()).toBeDefined();
    expect(proxy.connects().map((request) => request.target)).toEqual([`relay.test:${relay.url.port}`]);
    await connection.close();
    await client.dispose();
  });

  test("goes through ALL_PROXY when no scheme-specific proxy is set", async () => {
    process.env.all_proxy = proxy.url;
    // Bun's fetch ignores ALL_PROXY, so the API is reached directly.
    const client = await clientFor(relay.url.href);
    const connection = await client.tunnel.connect({ routes: { api: "127.0.0.1:9" } });
    expect(proxy.connects().map((request) => request.target)).toEqual([`127.0.0.1:${relay.url.port}`]);
    await connection.close();
    await client.dispose();
  });

  test("connects directly to hosts NO_PROXY exempts", async () => {
    process.env.HTTP_PROXY = proxy.url;
    process.env.NO_PROXY = "localhost, 127.0.0.1";
    const client = await clientFor(relay.url.href);
    const connection = await client.tunnel.connect({ routes: { api: "127.0.0.1:9" } });
    expect(proxy.requests).toEqual([]);
    await connection.close();
    await client.dispose();
  });

  test("the proxy option overrides the environment for the API and the bridge", async () => {
    process.env.HTTP_PROXY = "http://127.0.0.1:1";
    const authenticated = proxy.url.replace("http://", "http://user:p%40ss@");
    const client = await clientFor(viaName(), authenticated);
    const connection = await client.tunnel.connect({ routes: { api: "127.0.0.1:9" } });
    const target = `relay.test:${relay.url.port}`;
    expect(proxy.connects().map((request) => request.target)).toEqual([target]);
    expect(proxy.requests.some((request) => request.method === "GET" && request.target.includes(target))).toBe(true);
    const basic = `Basic ${Buffer.from("user:p@ss").toString("base64")}`;
    expect(proxy.requests.every((request) => request.authorization === basic)).toBe(true);
    await connection.close();
    await client.dispose();
  });

  test("an unsupported proxy scheme stops the tunnel with a clear error", async () => {
    process.env.ALL_PROXY = "socks5://user:secret@127.0.0.1:1080";
    const client = await clientFor(relay.url.href);
    const events: OpenTunnelClientEvent[] = [];
    const error = await client.tunnel
      .connect({ routes: { api: "127.0.0.1:9" }, onEvent: (event) => events.push(event) })
      .catch((error: unknown) => error);
    expect(error).toBeInstanceOf(OpenTunnelClientError);
    const message = (error as Error).message;
    expect(message).toContain("ALL_PROXY uses an unsupported proxy scheme 'socks5'");
    expect(message).not.toContain("secret");
    expect(events.at(-1)).toMatchObject({ type: "stopped", error: expect.stringContaining("socks5") });
    expect(relay.sockets.opened).toBe(0);
    await client.dispose();
  });

  test("create rejects a proxy option it cannot use", () => {
    expect(() => create({ proxy: "socks5://127.0.0.1:1080" })).toThrow(OpenTunnelClientError);
    expect(() => create({ proxy: "http://[::1" })).toThrow("The proxy option is not a valid proxy URL");
  });

  test("wss:// goes through HTTPS_PROXY", async () => {
    const transport = makeTransport(undefined, { HTTPS_PROXY: proxy.url, HTTP_PROXY: "http://127.0.0.1:1" });
    const socket = transport.webSocket(new URL("wss://relay.test:4443/api/tunnel/demo/connect"), ["opentunnel"], {});
    await new Promise((resolve) => socket.addEventListener("close", resolve));
    expect(proxy.connects().map((request) => request.target)).toEqual(["relay.test:4443"]);
  });
});

describe("proxyFromEnv", () => {
  const wss = new URL("wss://opentunnel.xyz/api/tunnel/x/connect");
  const ws = new URL("ws://relay.internal:8080/api/tunnel/x/connect");

  test("selects the scheme's proxy, then ALL_PROXY", () => {
    const env = { HTTPS_PROXY: "http://secure:1", HTTP_PROXY: "http://plain:1", ALL_PROXY: "http://all:1" };
    expect(proxyFromEnv(wss, env)?.host).toBe("secure:1");
    expect(proxyFromEnv(ws, env)?.host).toBe("plain:1");
    expect(proxyFromEnv(wss, { HTTP_PROXY: "http://plain:1", all_proxy: "http://all:1" })?.host).toBe("all:1");
    expect(proxyFromEnv(wss, { HTTP_PROXY: "http://plain:1" })).toBeUndefined();
    expect(proxyFromEnv(wss, { https_proxy: "http://lower:1" })?.host).toBe("lower:1");
    expect(proxyFromEnv(wss, { HTTPS_PROXY: "http://upper:1", https_proxy: "http://lower:1" })?.host).toBe("upper:1");
    expect(proxyFromEnv(wss, { HTTPS_PROXY: " ", ALL_PROXY: "http://all:1" })?.host).toBe("all:1");
    expect(proxyFromEnv(wss, {})).toBeUndefined();
  });

  test("takes a proxy without a scheme as http:// and keeps https:// proxies", () => {
    expect(proxyFromEnv(wss, { HTTPS_PROXY: "proxy.corp:3128" })?.href).toBe("http://proxy.corp:3128/");
    expect(proxyFromEnv(wss, { HTTPS_PROXY: "https://proxy.corp" })?.href).toBe("https://proxy.corp/");
  });

  test("rejects unsupported schemes without leaking credentials", () => {
    expect(() => proxyFromEnv(wss, { HTTPS_PROXY: "socks5h://u:secret@proxy:1080" })).toThrow(
      "HTTPS_PROXY uses an unsupported proxy scheme 'socks5h'",
    );
    // An exempted host never reads the proxy.
    expect(proxyFromEnv(wss, { HTTPS_PROXY: "socks5://proxy:1080", NO_PROXY: "opentunnel.xyz" })).toBeUndefined();
  });

  test("honors NO_PROXY, then no_proxy", () => {
    expect(proxyFromEnv(wss, { HTTPS_PROXY: "http://p:1", no_proxy: "opentunnel.xyz" })).toBeUndefined();
    expect(proxyFromEnv(wss, { HTTPS_PROXY: "http://p:1", NO_PROXY: "other", no_proxy: "opentunnel.xyz" })).toBeDefined();
  });
});

describe("bypassesProxy", () => {
  const cases: Array<[string, string, boolean]> = [
    ["https://opentunnel.xyz/", "*", true],
    ["https://opentunnel.xyz/", "opentunnel.xyz", true],
    ["https://api.opentunnel.xyz/", "opentunnel.xyz", true],
    ["https://api.opentunnel.xyz/", ".opentunnel.xyz", true],
    ["https://api.opentunnel.xyz/", "*.opentunnel.xyz", true],
    ["https://OpenTunnel.XYZ/", "opentunnel.xyz", true],
    ["https://notopentunnel.xyz/", "opentunnel.xyz", false],
    ["https://opentunnel.xyz/", "tunnel.xyz", false],
    ["https://opentunnel.xyz/", "example.com, opentunnel.xyz", true],
    ["https://opentunnel.xyz/", "example.com opentunnel.xyz", true],
    ["https://opentunnel.xyz/", "opentunnel.xyz:443", true],
    ["https://opentunnel.xyz/", "opentunnel.xyz:8443", false],
    ["http://opentunnel.xyz:8080/", "opentunnel.xyz:8080", true],
    ["http://opentunnel.xyz/", "opentunnel.xyz:80", true],
    ["http://10.1.2.3/", "10.1.2.3", true],
    ["http://10.1.2.3/", "10.0.0.0/8", true],
    ["http://11.1.2.3/", "10.0.0.0/8", false],
    ["http://10.1.2.3:8080/", "10.1.2.3:8080", true],
    ["http://[::1]:8080/", "::1", true],
    ["http://[::1]:8080/", "[::1]:8080", true],
    ["http://[::1]:8080/", "[::1]:80", false],
    ["http://[0:0::1]/", "::1", true],
    ["http://[fd00::5]/", "fd00::/8", true],
    ["http://127.0.0.1/", "localhost", false],
    ["http://localhost/", "", false],
  ];
  for (const [url, noProxy, expected] of cases) {
    test(`${url} with NO_PROXY=${JSON.stringify(noProxy)}`, () => {
      expect(bypassesProxy(new URL(url), noProxy)).toBe(expected);
    });
  }
});
