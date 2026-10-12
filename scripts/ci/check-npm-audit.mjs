// Runs `npm audit` (all dependencies) and fails unless every advisory is a documented,
// unexpired exception. Usage: check-npm-audit.mjs <app dir> <exceptions.json> <report out>
// Production dependencies are gated separately with no exceptions at all.
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";

const [appDir, exceptionsFile, reportFile] = process.argv.slice(2);

let raw;
try {
  raw = execFileSync("npm", ["audit", "--json"], { cwd: appDir, encoding: "utf8", shell: process.platform === "win32" });
} catch (error) {
  // npm audit exits non-zero when it finds anything; its JSON is still on stdout.
  raw = error.stdout;
}
writeFileSync(reportFile, raw ?? "");

let audit;
try {
  audit = JSON.parse(raw);
} catch {
  console.error("npm audit produced no readable report; refusing to treat that as clean.");
  process.exit(2);
}
if (audit.error || !audit.vulnerabilities || !audit.metadata) {
  console.error("npm audit failed:", JSON.stringify(audit.error ?? audit, null, 2));
  process.exit(2);
}

const exceptions = JSON.parse(readFileSync(exceptionsFile, "utf8")).npm ?? [];
const byAdvisory = new Map(exceptions.map((e) => [e.advisory, e]));
const today = new Date().toISOString().slice(0, 10);
const problems = [];

// Root advisories are the objects in `via`; string entries just point at other packages.
const advisories = new Map();
for (const [name, vulnerability] of Object.entries(audit.vulnerabilities)) {
  for (const via of vulnerability.via) {
    if (typeof via === "object") {
      const id = via.url?.split("/").pop() ?? String(via.source);
      advisories.set(id, { package: name, title: via.title, severity: via.severity, url: via.url });
    }
  }
}

for (const [id, advisory] of advisories) {
  const exception = byAdvisory.get(id);
  if (!exception) {
    problems.push(`${advisory.severity} ${id} in ${advisory.package}: ${advisory.title} (${advisory.url}) is not a documented exception.`);
  } else if (exception.package !== advisory.package) {
    problems.push(`${id} is documented for ${exception.package} but now affects ${advisory.package}.`);
  } else if (exception.reviewBy < today) {
    problems.push(`Exception for ${id} expired on ${exception.reviewBy}; review it (${exception.reviewWhen}).`);
  }
}
for (const exception of exceptions) {
  if (!advisories.has(exception.advisory)) {
    console.log(`Note: ${exception.advisory} no longer reported; remove it from ${exceptionsFile}.`);
  }
}

if (problems.length > 0) {
  console.error(`npm audit:\n  ${problems.join("\n  ")}`);
  process.exit(1);
}
console.log(`npm: ${advisories.size} advisory(ies), all documented exceptions: ${[...advisories.keys()].join(", ") || "none"}.`);
