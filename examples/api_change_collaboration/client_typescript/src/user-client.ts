export interface UserResponseV1 {
  userId: string;
  userName: string;
}

export interface UserApiClientOptions {
  baseUrl: string;
  fetch?: typeof globalThis.fetch;
  timeoutMs?: number;
  maxResponseBytes?: number;
}

export class UserApiClient {
  readonly #baseUrl: URL;
  readonly #fetch: typeof globalThis.fetch;
  readonly #timeoutMs: number;
  readonly #maxResponseBytes: number;

  constructor(options: UserApiClientOptions) {
    this.#baseUrl = validatedBaseUrl(options.baseUrl);
    this.#fetch = options.fetch ?? globalThis.fetch;
    this.#timeoutMs = positiveInteger(options.timeoutMs ?? 5_000, "timeoutMs");
    this.#maxResponseBytes = positiveInteger(
      options.maxResponseBytes ?? 65_536,
      "maxResponseBytes",
    );
  }

  async getUser(userId: string): Promise<UserResponseV1> {
    if (!/^[A-Za-z0-9-]{1,64}$/.test(userId)) {
      throw new TypeError("userId must contain 1..64 ASCII letters, digits, or hyphens");
    }
    const response = await this.#fetch(
      new URL(`/api/users/${encodeURIComponent(userId)}`, this.#baseUrl),
      {
        headers: { accept: "application/json" },
        signal: AbortSignal.timeout(this.#timeoutMs),
      },
    );
    if (!response.ok) {
      throw new Error(`User API request failed with HTTP ${response.status}`);
    }
    const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim();
    if (contentType !== "application/json") {
      throw new TypeError("User API response must use application/json");
    }
    const declaredLength = response.headers.get("content-length");
    if (declaredLength !== null) {
      const parsed = Number(declaredLength);
      if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > this.#maxResponseBytes) {
        throw new RangeError("User API response exceeds the configured size limit");
      }
    }
    const text = await readLimitedUtf8(response, this.#maxResponseBytes);
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch (error) {
      throw new TypeError("User API response is not valid JSON", { cause: error });
    }
    if (!isUserResponseV1(body, userId)) {
      throw new TypeError("User API response does not match the v1 contract");
    }
    return body;
  }
}

function validatedBaseUrl(value: string): URL {
  const url = new URL(value);
  if (url.username || url.password || url.search || url.hash || url.pathname !== "/") {
    throw new TypeError("baseUrl must be an origin without credentials, path, query, or fragment");
  }
  const loopback = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw new TypeError("baseUrl requires HTTPS or a loopback HTTP origin");
  }
  return url;
}

function positiveInteger(value: number, field: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${field} must be a positive safe integer`);
  }
  return value;
}

async function readLimitedUtf8(response: Response, limit: number): Promise<string> {
  if (response.body === null) {
    return "";
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const item = await reader.read();
      if (item.done) {
        break;
      }
      size += item.value.byteLength;
      if (size > limit) {
        await reader.cancel("configured response size exceeded");
        throw new RangeError("User API response exceeds the configured size limit");
      }
      chunks.push(item.value);
    }
  } finally {
    reader.releaseLock();
  }
  const payload = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    payload.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(payload);
  } catch (error) {
    throw new TypeError("User API response is not valid UTF-8", { cause: error });
  }
}

function isUserResponseV1(value: unknown, requestedUserId: string): value is UserResponseV1 {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const record = value as Record<string, unknown>;
  return (
    Object.keys(record).sort().join(",") === "userId,userName" &&
    record.userId === requestedUserId &&
    typeof record.userName === "string" &&
    record.userName.length >= 1 &&
    record.userName.length <= 256
  );
}
