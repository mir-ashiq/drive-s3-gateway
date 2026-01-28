import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";

const eslintBin = join(process.cwd(), "node_modules", ".bin", "eslint");

if (!existsSync(eslintBin)) {
  console.warn("eslint binary not found; skipping lint.");
  process.exit(0);
}

const result = spawnSync(eslintBin, ["src"], { stdio: "inherit" });
if (result.status === 0) {
  process.exit(0);
}

console.warn("eslint failed; verify parser configuration and dependencies.");
process.exit(result.status ?? 1);
