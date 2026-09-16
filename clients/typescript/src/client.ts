export interface HealthResponse {
  status: "ok";
}

export interface SessionIdentity {
  agent_id: string;
  owner_id: string;
  identity_source: "local_fixture";
  assurance_level: "test_only";
  is_test_fixture: true;
}

export interface TasClientOptions {
  baseUrl: string;
  fetch?: typeof globalThis.fetch;
  token?: string;
  traceId?: string;
}

export class TasClient {
  readonly #baseUrl: URL;
  readonly #fetch: typeof globalThis.fetch;
  readonly #token: string | undefined;
  readonly #traceId: string | undefined;

  constructor(options: TasClientOptions) {
    this.#baseUrl = new URL(options.baseUrl);
    if (this.#baseUrl.username.length > 0 || this.#baseUrl.password.length > 0) {
      throw new Error("TAS base URL must not contain embedded credentials");
    }
    this.#fetch = options.fetch ?? globalThis.fetch;
    this.#token = options.token;
    this.#traceId = options.traceId;
  }

  async health(): Promise<HealthResponse> {
    const response = await this.#fetch(new URL("/health", this.#baseUrl), {
      headers: this.#headers(),
    });

    if (!response.ok) {
      throw new Error(`TAS health check failed with HTTP ${response.status}`);
    }

    const body: unknown = await response.json();
    if (!isHealthResponse(body)) {
      throw new TypeError("TAS health response does not match the expected contract");
    }

    return body;
  }

  async session(): Promise<SessionIdentity> {
    if (this.#token === undefined || this.#token.length === 0) {
      throw new Error("A TAS agent token is required for this request");
    }
    if (!isSecureCredentialUrl(this.#baseUrl)) {
      throw new Error("TAS credentials require HTTPS or a loopback HTTP address");
    }

    const response = await this.#fetch(new URL("/session", this.#baseUrl), {
      headers: this.#headers(this.#token),
    });
    if (!response.ok) {
      throw new Error(`TAS session request failed with HTTP ${response.status}`);
    }

    const body: unknown = await response.json();
    if (!isSessionIdentity(body)) {
      throw new TypeError("TAS session response does not match the expected contract");
    }
    return body;
  }

  #headers(token?: string): Headers {
    const headers = new Headers({ accept: "application/json" });
    if (token !== undefined) {
      headers.set("authorization", `Bearer ${token}`);
    }
    if (this.#traceId !== undefined) {
      headers.set("x-trace-id", this.#traceId);
    }
    return headers;
  }
}

function isSecureCredentialUrl(url: URL): boolean {
  if (url.protocol === "https:") {
    return true;
  }
  return (
    url.protocol === "http:" &&
    (url.hostname === "localhost" ||
      url.hostname === "127.0.0.1" ||
      url.hostname === "[::1]")
  );
}

function isHealthResponse(value: unknown): value is HealthResponse {
  return (
    typeof value === "object" &&
    value !== null &&
    "status" in value &&
    value.status === "ok"
  );
}

function isSessionIdentity(value: unknown): value is SessionIdentity {
  return (
    typeof value === "object" &&
    value !== null &&
    "agent_id" in value &&
    typeof value.agent_id === "string" &&
    "owner_id" in value &&
    typeof value.owner_id === "string" &&
    "identity_source" in value &&
    value.identity_source === "local_fixture" &&
    "assurance_level" in value &&
    value.assurance_level === "test_only" &&
    "is_test_fixture" in value &&
    value.is_test_fixture === true
  );
}
