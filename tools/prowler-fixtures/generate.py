"""Generates the Prowler OCSF fixtures used by K9's import contract tests.

Synthetic check results are passed through Prowler's own code: Finding.generate_output
builds each finding (including Prowler's finding UID) and the OCSF output class writes the
file exactly as `prowler --output-formats json-ocsf` does. No cloud account or credentials
are involved.

Usage (from the repository root, with the pinned requirements installed):

    python tools/prowler-fixtures/generate.py          # rewrite the fixtures
    python tools/prowler-fixtures/generate.py --check  # fail if they are out of date

The output is byte-for-byte reproducible: the fixtures use fixed UTC timestamps, and the
random part of Prowler's scan ID is seeded per file.
"""

from __future__ import annotations

import argparse
import filecmp
import importlib.metadata
import json
import random
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

PROWLER_VERSION = "5.44.0"

REPO_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_DIR = REPO_ROOT / "apps" / "api" / "K9.Api.Tests" / "Fixtures" / "Prowler" / PROWLER_VERSION

ACCOUNT_A = "111111111111"
ACCOUNT_B = "222222222222"
AZURE_SUBSCRIPTION = "00000000-0000-4000-8000-000000000001"

T1 = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)
T2 = datetime(2026, 9, 8, 10, 0, 0, tzinfo=timezone.utc)
T3 = datetime(2026, 9, 15, 10, 0, 0, tzinfo=timezone.utc)

# Real Prowler checks whose metadata (title, severity, resource type, ...) the fixtures use.
CHECKS = {
    "bucket_pab": "aws/services/s3/s3_bucket_level_public_access_block",
    "sg_all_ports": "aws/services/ec2/ec2_securitygroup_allow_ingress_from_internet_to_all_ports",
    "root_mfa": "aws/services/iam/iam_root_mfa_enabled",
    "key_rotation": "aws/services/iam/iam_rotate_access_key_90_days",
    "ami_block": "aws/services/ec2/ec2_ami_account_block_public_access",
    "contacts": "aws/services/account/account_maintain_current_contact_details",
    "azure_storage_keys": "azure/services/storage/storage_account_key_access_disabled",
}


@dataclass(frozen=True)
class Result:
    """One synthetic check result, shaped like what a Prowler check reports."""

    check: str
    status: str
    detail: str
    resource_id: str
    resource_arn: str
    region: str
    account: str = ACCOUNT_A
    muted: bool = False
    resource: dict = field(default_factory=dict, hash=False)


@dataclass(frozen=True)
class Fixture:
    name: str
    description: str
    scans: tuple[tuple[datetime, tuple[Result, ...]], ...]
    seed: int
    shuffle: bool = False


# ---- Resources --------------------------------------------------------------------------

def bucket(name: str, status: str, detail: str, account: str = ACCOUNT_A, **kw) -> Result:
    return Result("bucket_pab", status, detail, name, f"arn:aws:s3:::{name}", "eu-west-1", account,
                  resource={"name": name, "region": "eu-west-1"}, **kw)


def security_group(sg_id: str, status: str, detail: str, account: str = ACCOUNT_A, **kw) -> Result:
    arn = f"arn:aws:ec2:eu-west-1:{account}:security-group/{sg_id}"
    return Result("sg_all_ports", status, detail, sg_id, arn, "eu-west-1", account,
                  resource={"id": sg_id, "region": "eu-west-1", "vpc_id": "vpc-0k9"}, **kw)


def root_mfa(status: str, detail: str, account: str = ACCOUNT_A) -> Result:
    # IAM is global; Prowler reports it in the IAM client's region.
    return Result("root_mfa", status, detail, "<root_account>", f"arn:aws:iam::{account}:root", "us-east-1", account)


def access_key(user: str, key: int, status: str, detail: str) -> Result:
    # As in iam_rotate_access_key_90_days: both keys of a user share the user's ARN and
    # differ only in the resource ID (which becomes the finding's resource name).
    return Result("key_rotation", status, detail, f"{user}-access-key-{key}",
                  f"arn:aws:iam::{ACCOUNT_A}:user/{user}", "us-east-1",
                  resource={"user": user, "arn": f"arn:aws:iam::{ACCOUNT_A}:user/{user}"})


def ami_block(region: str, status: str, detail: str) -> Result:
    # As in ec2_ami_account_block_public_access: one finding per region, all with the same
    # account-level ARN (built from the EC2 client's default region).
    return Result("ami_block", status, detail, ACCOUNT_A, f"arn:aws:ec2:us-east-1:{ACCOUNT_A}:account", region,
                  resource={"region": region, "status": "unblocked" if status == "FAIL" else "block-new-sharing"})


def contacts(detail: str = "Login to the AWS Console. Choose your account name on the top right of the window -> My Account -> Contact Information.") -> Result:
    return Result("contacts", "MANUAL", detail, ACCOUNT_A, f"arn:aws:iam::{ACCOUNT_A}:root", "us-east-1")


# ---- Scenarios --------------------------------------------------------------------------

BASELINE_A = (
    bucket("k9-logs", "FAIL", "Block Public Access is not configured for the S3 Bucket k9-logs."),
    bucket("k9-assets", "PASS", "Block Public Access is configured for the S3 Bucket k9-assets."),
    security_group("sg-0a1", "FAIL", "Security group default (sg-0a1) has all ports open to the Internet."),
    security_group("sg-0b2", "FAIL", "Security group legacy (sg-0b2) has all ports open to the Internet.", muted=True),
    root_mfa("FAIL", "MFA is not enabled for root account."),
    access_key("alice", 1, "FAIL", "User alice has not rotated access key 1 in over 90 days (120 days)."),
    access_key("alice", 2, "PASS", "User alice has rotated access key 2 in the last 90 days."),
    ami_block("eu-west-1", "FAIL", "AMI Block Public Access is disabled in eu-west-1."),
    ami_block("us-east-1", "PASS", "AMI Block Public Access is enabled in us-east-1."),
    contacts(),
)

FOLLOWUP_A = (
    bucket("k9-logs", "PASS", "Block Public Access is configured for the S3 Bucket k9-logs."),
    bucket("k9-assets", "FAIL", "Block Public Access is not configured for the S3 Bucket k9-assets."),
    # sg-0a1 is not in this scan: it was not reassessed, which is not evidence of a fix.
    security_group("sg-0b2", "PASS", "Security group legacy (sg-0b2) does not have all ports open to the Internet.", muted=True),
    root_mfa("FAIL", "MFA is not enabled for root account (checked again)."),
    access_key("alice", 1, "PASS", "User alice has rotated access key 1 in the last 90 days."),
    access_key("alice", 2, "PASS", "User alice has rotated access key 2 in the last 90 days."),
    ami_block("eu-west-1", "PASS", "AMI Block Public Access is enabled in eu-west-1."),
    ami_block("us-east-1", "FAIL", "AMI Block Public Access is disabled in us-east-1."),
    contacts(),
)

THIRD_A = (
    bucket("k9-logs", "FAIL", "Block Public Access is not configured for the S3 Bucket k9-logs."),
    security_group("sg-0a1", "MANUAL", "Security group default (sg-0a1) could not be evaluated automatically."),
    root_mfa("PASS", "MFA is enabled for root account."),
)

BASELINE_B = (
    bucket("k9-logs-b", "FAIL", "Block Public Access is not configured for the S3 Bucket k9-logs-b.", account=ACCOUNT_B),
    security_group("sg-0a1", "FAIL", "Security group default (sg-0a1) has all ports open to the Internet.", account=ACCOUNT_B),
    root_mfa("PASS", "MFA is enabled for root account.", account=ACCOUNT_B),
)

FIXTURES = (
    Fixture("aws-a-t1-baseline", "Account A, first scan: PASS, FAIL, MANUAL and muted results; global (IAM) and regional resources; "
            "two access keys sharing one ARN; one ARN reported in two regions.", ((T1, BASELINE_A),), seed=1),
    Fixture("aws-a-t2-followup", "Account A, a week later: fixes, a PASS-to-FAIL regression, a missing resource (sg-0a1), "
            "a muted PASS, and the two regions of one ARN moving in opposite directions.", ((T2, FOLLOWUP_A),), seed=2),
    Fixture("aws-a-t2-reexport", "The T2 scan exported again: the same observations in a different order with a different "
            "random scan ID. Semantically identical to aws-a-t2-followup, but not byte-identical.", ((T2, FOLLOWUP_A),), seed=3, shuffle=True),
    Fixture("aws-a-t3-third", "Account A, third scan: k9-logs fails again after being fixed, sg-0a1 comes back as MANUAL, "
            "root MFA passes.", ((T3, THIRD_A),), seed=4),
    Fixture("aws-a-t2-conflict", "Claims the same scan time as aws-a-t2-followup but reports k9-logs as FAIL: a conflict.",
            ((T2, (bucket("k9-logs", "FAIL", "Block Public Access is not configured for the S3 Bucket k9-logs."),)),), seed=5),
    Fixture("aws-b-t1-baseline", "Account B, first scan, with a security group ID that also exists in account A.",
            ((T1, BASELINE_B),), seed=6),
    Fixture("aws-multi-account", "Accounts A and B in one file, each with its own scan time.",
            ((T1, BASELINE_B), (T3, THIRD_A)), seed=7),
    Fixture("aws-prowler-uid-collision", "Two different resources (different ARNs) with the same check, account, region and "
            "resource name. Prowler gives both the same finding UID; K9 must keep them apart.",
            ((T1, (
                Result("sg_all_ports", "FAIL", "Security group shared (sg-0c3) has all ports open to the Internet.", "shared",
                       f"arn:aws:ec2:eu-west-1:{ACCOUNT_A}:security-group/sg-0c3", "eu-west-1"),
                Result("sg_all_ports", "PASS", "Security group shared (sg-0d4) does not have all ports open to the Internet.", "shared",
                       f"arn:aws:ec2:eu-west-1:{ACCOUNT_A}:security-group/sg-0d4", "eu-west-1"),
            )),), seed=8),
    Fixture("aws-in-file-duplicate", "The same observation twice in one file (identical content).",
            ((T1, (BASELINE_A[0], BASELINE_A[0])),), seed=9),
    Fixture("aws-in-file-contradiction", "The same resource and check twice in one scan with different results.",
            ((T1, (BASELINE_A[0], bucket("k9-logs", "PASS", "Block Public Access is configured for the S3 Bucket k9-logs."))),), seed=10),
    Fixture("azure-unsupported", "An Azure finding. K9 V1 supports AWS only and must reject it.",
            ((T1, (Result("azure_storage_keys", "FAIL", "Storage account k9storage allows shared key access.", "k9storage",
                          f"/subscriptions/{AZURE_SUBSCRIPTION}/resourceGroups/k9/providers/Microsoft.Storage/storageAccounts/k9storage",
                          "westeurope", AZURE_SUBSCRIPTION),)),), seed=11),
)


# ---- Prowler plumbing -------------------------------------------------------------------

def generate(output_dir: Path) -> list[dict]:
    installed = importlib.metadata.version("prowler")
    if installed != PROWLER_VERSION:
        sys.exit(f"Prowler {PROWLER_VERSION} is required, found {installed}. Install tools/prowler-fixtures/requirements.txt.")

    import prowler
    from prowler.config.config import timestamp
    from prowler.lib.check.models import Check_Report_AWS, Check_Report_Azure
    from prowler.lib.outputs.finding import Finding
    from prowler.lib.outputs.ocsf.ocsf import OCSF

    checks_root = Path(prowler.__file__).parent / "providers"
    metadata = {key: next((checks_root / path).glob("*.metadata.json")).read_text(encoding="utf-8") for key, path in CHECKS.items()}
    options = SimpleNamespace(unix_timestamp=False, bulk_checks_metadata={})

    def aws_provider(account: str) -> SimpleNamespace:
        return SimpleNamespace(
            type="aws",
            identity=SimpleNamespace(account=account, partition="aws", profile="k9-fixtures"),
            organizations_metadata=SimpleNamespace(
                account_name=f"k9-sandbox-{account[-1]}", account_email="", organization_arn="", organization_id="",
                account_tags={}, account_ou_id="", account_ou_name=""),
        )

    def azure_provider(subscription: str) -> SimpleNamespace:
        return SimpleNamespace(
            type="azure",
            identity=SimpleNamespace(identity_type="Service Principal", identity_id="k9-fixtures", tenant_ids=["k9-tenant"],
                                     tenant_domain="k9.test", subscriptions={subscription: "k9-sandbox"}),
        )

    def finding(result: Result) -> Finding:
        if result.check.startswith("azure_"):
            report = Check_Report_Azure(metadata=metadata[result.check], resource=result.resource)
            report.resource_name = result.resource_id
            report.resource_id = result.resource_arn
            report.subscription = result.account
            report.location = result.region
            provider = azure_provider(result.account)
        else:
            report = Check_Report_AWS(metadata=metadata[result.check], resource=result.resource)
            report.resource_id = result.resource_id
            report.resource_arn = result.resource_arn
            report.region = result.region
            provider = aws_provider(result.account)
        report.status = result.status
        report.status_extended = result.detail
        report.muted = result.muted
        return Finding.generate_output(provider, report, options)

    output_dir.mkdir(parents=True, exist_ok=True)
    manifest = []
    for fixture in FIXTURES:
        random.seed(fixture.seed)  # Prowler's scan ID takes its random bits from the global RNG.
        findings = []
        for scan_time, results in fixture.scans:
            timestamp.set(scan_time)  # Prowler stamps every finding of a run with one process-wide time.
            findings.extend(finding(r) for r in results)
        if fixture.shuffle:
            random.Random(fixture.seed).shuffle(findings)
        path = output_dir / f"{fixture.name}.ocsf.json"
        writer = OCSF(findings=findings, file_path=str(path), from_cli=True)
        writer.batch_write_data_to_file()
        written = json.loads(path.read_text(encoding="utf-8"))
        if len(written) != len(findings):
            sys.exit(f"{path.name}: Prowler wrote {len(written)} of {len(findings)} findings.")
        manifest.append({"file": path.name, "description": fixture.description, "findings": len(written)})

    (output_dir / "manifest.json").write_text(json.dumps({
        "generator": "tools/prowler-fixtures/generate.py",
        "prowler": PROWLER_VERSION,
        "py-ocsf-models": importlib.metadata.version("py-ocsf-models"),
        "note": "Synthetic results passed through Prowler's real finding and OCSF output code. Real CLI exports carry "
                "time_dt in the scanning machine's local time without an offset; these carry UTC with an offset.",
        "fixtures": manifest,
    }, indent=2) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="verify the committed fixtures instead of rewriting them")
    args = parser.parse_args()

    if not args.check:
        for fixture in generate(OUTPUT_DIR):
            print(f"{fixture['file']}: {fixture['findings']} findings")
        return

    with tempfile.TemporaryDirectory() as scratch:
        generate(Path(scratch))
        expected = sorted(p.name for p in Path(scratch).iterdir())
        actual = sorted(p.name for p in OUTPUT_DIR.iterdir()) if OUTPUT_DIR.exists() else []
        _, mismatch, errors = filecmp.cmpfiles(scratch, OUTPUT_DIR, expected, shallow=False)
        if expected != actual or mismatch or errors:
            sys.exit(f"Fixtures are out of date (differs: {mismatch + errors}, files: {actual} vs {expected}). Re-run the generator.")
    print("Fixtures are up to date.")


if __name__ == "__main__":
    main()
