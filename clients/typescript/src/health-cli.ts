import { TasClient } from "./client.js";

const baseUrl = process.argv[2] ?? "http://127.0.0.1:8000";
const health = await new TasClient({ baseUrl }).health();

process.stdout.write(`${JSON.stringify(health)}\n`);
