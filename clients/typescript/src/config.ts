import { readFile } from "node:fs/promises";

export interface LocalAgentConfig {
  agent_id: string;
  base_url: string;
  token: string;
  identity_source: "local_fixture";
  assurance_level: "test_only";
  is_test_fixture: true;
}

export async function loadLocalAgentConfig(path: string): Promise<LocalAgentConfig> {
  const parsed: unknown = JSON.parse(await readFile(path, "utf8"));
  if (!isLocalAgentConfig(parsed)) {
    throw new TypeError("Local agent configuration does not match the expected contract");
  }
  return parsed;
}

function isLocalAgentConfig(value: unknown): value is LocalAgentConfig {
  return (
    typeof value === "object" &&
    value !== null &&
    "agent_id" in value &&
    typeof value.agent_id === "string" &&
    value.agent_id.length > 0 &&
    "base_url" in value &&
    typeof value.base_url === "string" &&
    value.base_url.length > 0 &&
    "token" in value &&
    typeof value.token === "string" &&
    value.token.length > 0 &&
    !("simulated" in value) &&
    "identity_source" in value &&
    value.identity_source === "local_fixture" &&
    "assurance_level" in value &&
    value.assurance_level === "test_only" &&
    "is_test_fixture" in value &&
    value.is_test_fixture === true
  );
}
