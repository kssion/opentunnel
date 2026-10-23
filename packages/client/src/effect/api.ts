import { Effect, Layer, Context } from "effect";
import {
  FetchHttpClient,
  HttpClient,
  HttpClientError,
  HttpClientRequest,
  type HttpClientResponse,
} from "effect/http";
import { ApiRetry } from "@opentunnel/protocol/api-retry";
import pkg from "../../package.json" with { type: "json" };
import { HttpApiClient } from "effect/http-api";
import { Api } from "@opentunnel/protocol/api/api";
import { Tunnel } from "@opentunnel/protocol/tunnel";

/** How the SDK identifies itself to the server, on API calls and the bridge. */
export const USER_AGENT = `opentunnel-sdk/${pkg.version}`;

type Client = HttpApiClient.ForApi<typeof Api>;

/** Error codes of a fetch that could not connect, so the request never left (Bun's and Node's). */
const CONNECT_ERRORS = new Set([
  "ConnectionRefused",
  "ECONNREFUSED",
  "ENOTFOUND",
  "EAI_AGAIN",
  "FailedToOpenSocket",
  "UND_ERR_CONNECT_TIMEOUT",
]);

const errorCode = (cause: unknown): string | undefined => {
  if (typeof cause !== "object" || cause === null) return undefined;
  const { code, cause: inner } = cause as { code?: unknown; cause?: unknown };
  return typeof code === "string" ? code : errorCode(inner);
};

/** Reads and binding the same CSR (which answers with the current certificate) may be repeated freely. */
const repeatFor = (request: HttpClientRequest.HttpClientRequest): ApiRetry.Repeat =>
  request.method === "GET" || (request.method === "POST" && request.url.endsWith("/certificate"))
    ? "idempotent"
    : "once";

const retryableError = (error: unknown, repeat: ApiRetry.Repeat) =>
  HttpClientError.isHttpClientError(error) &&
  error.reason._tag === "TransportError" &&
  (repeat === "idempotent" || CONNECT_ERRORS.has(errorCode(error.reason.cause) ?? ""));

/**
 * Sends requests again after transient failures (network errors, 429, 5xx
 * including Cloudflare's 52x) as far as the request allows, with capped
 * exponential backoff; the last failure is returned.
 */
export const withRetries = <E, R>(client: HttpClient.HttpClient.With<E, R>): HttpClient.HttpClient.With<E, R> =>
  HttpClient.transform(client, (effect, request) => {
    const repeat = repeatFor(request);
    const wait = (attempt: number, retryAfter?: string) => {
      const [min, max] = ApiRetry.retryDelayMs(attempt, retryAfter);
      return Effect.sleep(min + Math.random() * (max - min));
    };
    const attempt = (n: number): Effect.Effect<HttpClientResponse.HttpClientResponse, E, R> =>
      Effect.matchEffect(effect, {
        onFailure: (error) =>
          n < ApiRetry.RETRIES && retryableError(error, repeat)
            ? Effect.andThen(wait(n), () => attempt(n + 1))
            : Effect.fail(error),
        onSuccess: (response) =>
          n < ApiRetry.RETRIES && ApiRetry.retryableStatus(response.status, repeat)
            ? Effect.andThen(wait(n, response.headers["retry-after"]), () => attempt(n + 1))
            : Effect.succeed(response),
      });
    return attempt(0);
  });

interface OpenTunnelApi {
  readonly client: Client;
  readonly authorized: (token: Tunnel.Token) => Effect.Effect<Client>;
}

export class OpenTunnelApiClient extends Context.Service<OpenTunnelApiClient, OpenTunnelApi>()(
  "@opentunnel/client/OpenTunnelApiClient",
) {
  /** `fetch` replaces the runtime's for API calls, as a proxy needs on some runtimes. */
  static layer(options: { readonly api: URL | string; readonly fetch?: typeof globalThis.fetch }) {
    return Layer.effect(
      OpenTunnelApiClient,
      Effect.gen(function* () {
        const httpClient = (yield* HttpClient.HttpClient).pipe(
          HttpClient.mapRequest(HttpClientRequest.setHeader("user-agent", USER_AGENT)),
          withRetries,
        );
        const client = yield* HttpApiClient.makeWith(Api, {
          baseUrl: options.api,
          httpClient,
        });
        return {
          client,
          authorized: (token) =>
            HttpApiClient.makeWith(Api, {
              baseUrl: options.api,
              httpClient: httpClient.pipe(
                HttpClient.mapRequest(HttpClientRequest.bearerToken(token)),
              ),
            }),
        };
      }),
    ).pipe(
      Layer.provide(
        options.fetch
          ? FetchHttpClient.layer.pipe(Layer.provide(Layer.succeed(FetchHttpClient.Fetch, options.fetch)))
          : FetchHttpClient.layer,
      ),
    );
  }
}
