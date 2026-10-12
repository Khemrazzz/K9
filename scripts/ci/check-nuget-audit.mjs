// Fails if `dotnet list package --vulnerable --format json` reports any vulnerable
// package, or if its output is missing or unreadable (a scanner failure is a failure).
import { readFileSync } from "node:fs";

const [file] = process.argv.slice(2);
let report;
try {
  report = JSON.parse(readFileSync(file, "utf8"));
} catch (error) {
  console.error(`NuGet audit report unreadable (${file}): ${error.message}`);
  process.exit(2);
}

if (!Array.isArray(report.projects) || report.projects.length === 0) {
  console.error("NuGet audit report lists no projects; refusing to treat that as clean.");
  process.exit(2);
}
if (Array.isArray(report.problems) && report.problems.length > 0) {
  console.error("NuGet audit could not complete:", JSON.stringify(report.problems, null, 2));
  process.exit(2);
}

const findings = [];
for (const project of report.projects) {
  for (const framework of project.frameworks ?? []) {
    for (const kind of ["topLevelPackages", "transitivePackages"]) {
      for (const pkg of framework[kind] ?? []) {
        for (const vulnerability of pkg.vulnerabilities ?? []) {
          findings.push(`${project.path}: ${pkg.id} ${pkg.resolvedVersion} (${vulnerability.severity}) ${vulnerability.advisoryurl}`);
        }
      }
    }
  }
}

if (findings.length > 0) {
  console.error(`Vulnerable NuGet packages:\n  ${findings.join("\n  ")}`);
  process.exit(1);
}
console.log(`NuGet: no known vulnerabilities in ${report.projects.length} project(s).`);
