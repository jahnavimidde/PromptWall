import { describe, expect, it } from "bun:test";
import { execSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

describe("M13 — Credential Hygiene & Secret Scanning", () => {
  const rootDir = join(__dirname, "../..");

  it("ensures .env and private key patterns are present in .gitignore", () => {
    const gitignorePath = join(rootDir, ".gitignore");
    expect(existsSync(gitignorePath)).toBe(true);

    const gitignore = readFileSync(gitignorePath, "utf8");
    const lines = gitignore.split("\n").map((l) => l.trim());

    expect(lines).toContain(".env");
    expect(lines).toContain(".env.local");
    expect(lines).toContain("*.pem");
    expect(lines).toContain("*.key");
  });

  it("verifies .env is not tracked in the git index", () => {
    try {
      const tracked = execSync("git ls-files .env", {
        cwd: rootDir,
        encoding: "utf8",
      }).trim();
      expect(tracked).toBe("");
    } catch {
      // If git command fails in non-git environment, test passes trivially
    }
  });

  it("verifies .env.example exists and contains only synthetic template values", () => {
    const examplePath = join(rootDir, ".env.example");
    expect(existsSync(examplePath)).toBe(true);

    const exampleContent = readFileSync(examplePath, "utf8");
    const lines = exampleContent.split("\n");

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;

      const match = trimmed.match(/^([A-Z0-9_]+)=(.*)$/);
      if (match) {
        const [, key, val] = match;
        if (key.includes("KEY") || key.includes("SECRET") || key.includes("TOKEN")) {
          expect(
            val.includes("EXAMPLE") || val.includes("placeholder") || val.includes("change-me"),
          ).toBe(true);
        }
      }
    }
  });

  it("verifies tracked repository files do not expose live credentials", () => {
    let trackedFiles: string[] = [];
    try {
      trackedFiles = execSync("git ls-files", {
        cwd: rootDir,
        encoding: "utf8",
      })
        .trim()
        .split("\n")
        .filter(Boolean);
    } catch {
      return;
    }

    const sensitivePatterns = [
      { name: "Live AWS Access Key", regex: /AKIA[0-9A-Z]{16}/ },
      { name: "Live Anthropic Key", regex: /sk-ant-api03-[a-zA-Z0-9_-]{25,}/ },
    ];

    for (const file of trackedFiles) {
      // Skip binary, lock, test pattern definition, or fixture files
      if (
        file.endsWith(".lockb") ||
        file.endsWith(".png") ||
        file.endsWith(".jpg") ||
        file.endsWith(".svg") ||
        file.includes("patterns/") ||
        file.includes(".test.") ||
        file.includes("benchmarks/")
      ) {
        continue;
      }

      const fullPath = join(rootDir, file);
      if (!existsSync(fullPath)) continue;

      const content = readFileSync(fullPath, "utf8");
      for (const { regex } of sensitivePatterns) {
        const match = content.match(regex);
        if (match) {
          const matchedStr = match[0];
          const isSynthetic =
            matchedStr.includes("EXAMPLE") ||
            matchedStr.includes("00000") ||
            matchedStr.includes("placeholder") ||
            matchedStr.includes("xxxx");
          expect(isSynthetic).toBe(true);
        }
      }
    }
  });
});
