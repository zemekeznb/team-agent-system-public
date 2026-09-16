import { TasClient } from "./client.js";
import { loadLocalAgentConfig } from "./config.js";

const configPath = process.argv[2];
if (configPath === undefined) {
  throw new Error("Usage: node session-cli.js <agent-config.json>");
}

const config = await loadLocalAgentConfig(configPath);
const identity = await new TasClient({
  baseUrl: config.base_url,
  token: config.token,
}).session();

process.stdout.write(`${JSON.stringify(identity)}\n`);
