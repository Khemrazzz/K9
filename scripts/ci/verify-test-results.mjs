// Security regression gate. Reads a test report and fails unless every required security
// test ran and passed, nothing was skipped, and the total did not shrink.
// Usage: verify-test-results.mjs backend <results.trx> | e2e <playwright-results.json>
import { readFileSync } from "node:fs";

const [suite, file] = process.argv.slice(2);
const manifest = JSON.parse(readFileSync(new URL("./security-tests.json", import.meta.url), "utf8"))[suite];
if (!manifest) {
  console.error(`Unknown suite "${suite}". Use backend or e2e.`);
  process.exit(2);
}

let content;
try {
  content = readFileSync(file, "utf8");
} catch (error) {
  console.error(`No test report at ${file}: ${error.message}`);
  process.exit(2);
}

/** @type {{ name: string, outcome: string }[]} */
const results = suite === "backend" ? fromTrx(content) : fromPlaywright(JSON.parse(content));

const failures = [];
const total = results.length;
const notPassed = results.filter((r) => r.outcome !== "passed");
if (total < manifest.minimumTotal) {
  failures.push(`Only ${total} tests ran; at least ${manifest.minimumTotal} are expected.`);
}
for (const result of notPassed) {
  failures.push(`${result.outcome}: ${result.name}`);
}
for (const [guarantee, prefix] of Object.entries(manifest.required)) {
  const matching = results.filter((r) => r.name.startsWith(prefix));
  if (matching.length === 0) {
    failures.push(`Missing security test for "${guarantee}" (${prefix}).`);
  } else if (matching.some((r) => r.outcome !== "passed")) {
    failures.push(`Security test for "${guarantee}" did not pass.`);
  }
}

if (failures.length > 0) {
  console.error(`Security regression gate failed (${suite}):\n  ${failures.join("\n  ")}`);
  process.exit(1);
}
console.log(`Security regression gate (${suite}): ${total} tests passed, ${Object.keys(manifest.required).length} required security guarantees covered.`);

function fromTrx(xml) {
  const results = [];
  for (const match of xml.matchAll(/<UnitTestResult\b([^>]*)>/g)) {
    const attributes = Object.fromEntries([...match[1].matchAll(/(\w+)="([^"]*)"/g)].map((m) => [m[1], decode(m[2])]));
    results.push({ name: attributes.testName, outcome: attributes.outcome === "Passed" ? "passed" : attributes.outcome.toLowerCase() });
  }
  return results;
}

function decode(value) {
  return value.replaceAll("&quot;", '"').replaceAll("&apos;", "'").replaceAll("&lt;", "<").replaceAll("&gt;", ">").replaceAll("&amp;", "&");
}

function fromPlaywright(report) {
  const results = [];
  const walk = (suiteNode, titles) => {
    for (const spec of suiteNode.specs ?? []) {
      for (const test of spec.tests ?? []) {
        // "expected" = passed; "skipped", "unexpected" and "flaky" all fail the gate.
        const outcome = test.status === "expected" ? "passed" : test.status;
        results.push({ name: [...titles, spec.title].join(" > "), outcome });
      }
    }
    for (const child of suiteNode.suites ?? []) {
      walk(child, child.title && !child.title.endsWith(".ts") ? [...titles, child.title] : titles);
    }
  };
  for (const root of report.suites ?? []) {
    walk(root, []);
  }
  return results;
}
