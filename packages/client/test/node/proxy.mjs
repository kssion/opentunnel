// Node checks for the proxy transport, run on the built `dist` with `node --test` (Node 22.18+ for the
// TypeScript test proxy): Bun's test runner covers the rest of the SDK.
import assert from "node:assert/strict";
import * as ChildProcess from "node:child_process";
import { createHash } from "node:crypto";
import * as Http from "node:http";
import { after, before, test } from "node:test";
import { promisify } from "node:util";
import { makeTransport } from "../../dist/effect/proxy.js";
import { httpProxy } from "../http-proxy.ts";

const execFile = promisify(ChildProcess.execFile);

let proxy;
let server;
let port;

before(async () => {
  proxy = await httpProxy();
  // Answers plain requests with "ok" and accepts WebSocket upgrades.
  server = Http.createServer((_request, response) => response.end("ok"));
  server.on("upgrade", (request, socket) => {
    const accept = createHash("sha1")
      .update(`${request.headers["sec-websocket-key"]}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
      .digest("base64");
    const protocol = request.headers["sec-websocket-protocol"];
    socket.write(
      "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
        `Sec-WebSocket-Accept: ${accept}\r\n` +
        (protocol ? `Sec-WebSocket-Protocol: ${protocol}\r\n` : "") +
        "\r\n",
    );
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  port = server.address().port;
});

after(async () => {
  server.closeAllConnections();
  server.close();
  await proxy.stop();
});

const opens = (socket) =>
  new Promise((resolve, reject) => {
    socket.addEventListener("open", () => {
      socket.close();
      resolve();
    });
    socket.addEventListener("error", (event) => reject(event.error ?? new Error("WebSocket failed")));
  });

test("the proxy option sends the bridge and the API through undici's ProxyAgent", async () => {
  proxy.requests.length = 0;
  const transport = makeTransport(proxy.url.replace("http://", "http://user:p%40ss@"), {});
  await opens(transport.webSocket(new URL(`ws://relay.test:${port}/connect`), ["opentunnel"], { "user-agent": "test" }));
  const response = await transport.fetch(`http://relay.test:${port}/api`);
  assert.equal(await response.text(), "ok");
  assert.deepEqual(
    proxy.requests.map((request) => [request.method, request.target]),
    [
      ["CONNECT", `relay.test:${port}`],
      ["CONNECT", `relay.test:${port}`],
    ],
  );
  const basic = `Basic ${Buffer.from("user:p@ss").toString("base64")}`;
  assert.ok(proxy.requests.every((request) => request.authorization === basic));
});

test("without the option the runtime's fetch and WebSocket are used as they are", () => {
  const transport = makeTransport(undefined, { HTTPS_PROXY: "socks5://127.0.0.1:1" });
  assert.equal(transport.fetch, undefined);
});

test("Node's WebSocket follows HTTP_PROXY and NO_PROXY with NODE_USE_ENV_PROXY=1, like its fetch", async () => {
  const script = `
    const { makeTransport } = await import(${JSON.stringify(new URL("../../dist/effect/proxy.js", import.meta.url).href)});
    const socket = makeTransport().webSocket(new URL(process.argv[1]), ["opentunnel"], {});
    socket.onopen = () => { console.log("open"); process.exit(0); };
    socket.onerror = () => { console.log("error"); process.exit(0); };
  `;
  const run = async (env) => {
    proxy.requests.length = 0;
    const { stdout } = await execFile(
      process.execPath,
      ["--input-type=module", "-e", script, `ws://relay.test:${port}/connect`],
      { env: { ...process.env, HTTPS_PROXY: "", ALL_PROXY: "", HTTP_PROXY: proxy.url, NO_PROXY: "", ...env }, timeout: 10_000 },
    );
    return [stdout.trim(), proxy.requests.map((request) => request.target)];
  };
  assert.deepEqual(await run({ NODE_USE_ENV_PROXY: "1" }), ["open", [`relay.test:${port}`]]);
  assert.deepEqual(await run({ NODE_USE_ENV_PROXY: "1", NO_PROXY: "relay.test" }), ["error", []]);
  assert.deepEqual(await run({ NODE_USE_ENV_PROXY: "" }), ["error", []]);
});
