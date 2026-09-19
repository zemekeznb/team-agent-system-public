import { UserApiClient } from "./user-client.js";

async function main(): Promise<void> {
  const [baseUrl, userId] = process.argv.slice(2);
  if (baseUrl === undefined || userId === undefined || process.argv.length !== 4) {
    throw new TypeError("usage: read-user-cli <base-url> <user-id>");
  }
  const user = await new UserApiClient({ baseUrl }).getUser(userId);
  process.stdout.write(`${JSON.stringify(user)}\n`);
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "unknown client failure";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
