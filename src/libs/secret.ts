import fs from "node:fs";

export function readSecret(path?: string, fallbackEnv?: string): string | undefined {
  if (path && fs.existsSync(path)) {
    return fs.readFileSync(path, "utf8").trim();
  }
  if (fallbackEnv) {
    return fallbackEnv;
  }
  return undefined;
}
