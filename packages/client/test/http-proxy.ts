import * as Net from "node:net";

export interface ProxyRequest {
  /** `CONNECT` for tunnels, else the method of a forwarded request. */
  readonly method: string;
  /** `host:port` for `CONNECT`, else the absolute URL. */
  readonly target: string;
  readonly authorization: string | undefined;
}

export interface HttpProxy {
  readonly url: string;
  readonly requests: ProxyRequest[];
  readonly connects: () => ProxyRequest[];
  readonly stop: () => Promise<void>;
}

/**
 * An HTTP proxy that tunnels `CONNECT` and forwards absolute-form requests,
 * sending every host to 127.0.0.1 on the requested port, so names that only
 * resolve through it (`relay.test`) prove a connection went through it.
 */
export async function httpProxy(): Promise<HttpProxy> {
  const requests: ProxyRequest[] = [];
  const sockets = new Set<Net.Socket>();
  const server = Net.createServer((client) => {
    sockets.add(client);
    client.on("close", () => sockets.delete(client));
    client.on("error", () => undefined);
    let head = Buffer.alloc(0);
    const onData = (chunk: Buffer) => {
      head = Buffer.concat([head, chunk]);
      const end = head.indexOf("\r\n\r\n");
      if (end === -1) return;
      client.off("data", onData);
      const lines = head.subarray(0, end).toString("latin1").split("\r\n");
      const [method = "", target = ""] = lines[0]!.split(" ");
      const authorization = lines
        .find((line) => line.toLowerCase().startsWith("proxy-authorization:"))
        ?.slice("proxy-authorization:".length)
        .trim();
      requests.push({ method, target, authorization });
      const port =
        method === "CONNECT" ? Number(target.split(":").pop()) : Number(new URL(target).port || 80);
      const upstream = Net.connect(port, "127.0.0.1");
      sockets.add(upstream);
      upstream.on("close", () => sockets.delete(upstream));
      upstream.on("error", () => client.destroy());
      client.on("close", () => upstream.destroy());
      upstream.once("connect", () => {
        if (method === "CONNECT") {
          client.write("HTTP/1.1 200 Connection established\r\n\r\n");
          const rest = head.subarray(end + 4);
          if (rest.length > 0) upstream.write(rest);
        } else {
          upstream.write(head);
        }
        client.pipe(upstream);
        upstream.pipe(client);
      });
    };
    client.on("data", onData);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as Net.AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    requests,
    connects: () => requests.filter((request) => request.method === "CONNECT"),
    stop: () =>
      new Promise((resolve) => {
        for (const socket of sockets) socket.destroy();
        server.close(() => resolve());
      }),
  };
}
