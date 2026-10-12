# Prowler OCSF import contract (V1)

What K9 accepts when an organization uploads a Prowler scan, and how it turns uploads into
findings. Status: **contract agreed, implementation pending** (PR f). The contract tests
in `apps/api/K9.Api.Tests/Assessments/` encode every rule below. The fixtures they use
are generated from Prowler's own output code by `tools/prowler-fixtures/`.

## Supported input

| | Accepted |
|---|---|
| Producer | Prowler `5.44.0` (`metadata.product.version`). Other versions are rejected. |
| Schema | OCSF `1.5.0` (`metadata.version`), class Detection Finding (`class_uid` 2004) |
| Provider | `aws` only. Azure, GCP, Kubernetes and others are rejected until they have an adapter. |
| File | One JSON array of findings, UTF-8, as written by `prowler --output-formats json-ocsf` |
| Size | `Assessments:Import:MaxFileBytes` (default 64 MiB) and `Assessments:Import:MaxObservations` (default 20,000) |

A file is accepted or rejected as a whole. Validation reports at most 20 problems, each
a code plus the finding's index and field, never the finding's content.

## Fields K9 reads

| K9 meaning | OCSF field | Rule |
|---|---|---|
| Check | `metadata.event_code` | Must equal `finding_info.analytic.uid`; `^[a-z0-9_]{1,128}$` |
| Result | `status_code` | `PASS`, `FAIL`, `MANUAL` or `MUTED`. Anything else is rejected. |
| Muted in Prowler | `status_id` | `3` (Suppressed) means muted. This is not the result. |
| Account | `cloud.account.uid` | AWS: 12 digits |
| Provider | `cloud.provider` | Must equal `unmapped.provider` |
| Location | `resources[0].region` | Must equal `cloud.region`. AWS: a region code or `global`. |
| Resource | `resources[0].uid` and `resources[0].name` | Exactly one resource per finding; uid ≤ 2048 and name ≤ 1024 characters |
| Scan time | `time` (epoch seconds) | Every finding of one account in one file must share it |
| Evidence | `status_detail`, `severity_id`, `resources[0].type` | `status_detail` longer than 4,000 characters is truncated |
| Display only | `finding_info.title`, `remediation.desc` | Stored, not compared |
| Traceability only | `finding_info.uid`, `unmapped.scan_id` | Stored, never used as identity |

Ignored on purpose:
- `time_dt`: Prowler writes the scanning machine's local time without an offset.
- `resources[0].data`: a dump of the resource that changes between runs and can hold
  sensitive configuration.
- Compliance mappings and `unmapped.*`, apart from the provider and scan ID.

## Identity

A K9 observation identity is:

```
(organization, provider, account, check, location, resource uid, resource name)
```

It is encoded as a JSON array, so the encoding is unambiguous, and hashed with SHA-256.
Every component is needed. Each of these was verified against Prowler 5.44.0:

- **Resource uid alone is not unique.** `iam_rotate_access_key_90_days` reports each access
  key separately (`alice-access-key-1`, `alice-access-key-2`), but both carry the user's
  ARN. The name tells them apart.
- **Location is needed.** `ec2_ami_account_block_public_access` reports every region with
  the same account-level ARN.
- **Prowler's `finding_info.uid` is not unique either.** It is
  `prowler-{provider}-{check}-{account}-{region}-{resource name}` and omits the resource
  uid, so different resources with the same name collide.

If a resource is renamed, its identity changes. The old finding then stays open as "not
reassessed", and a new one opens. That errs on the safe side: the old finding is never
closed because of the rename.

## Observations

- An observation is one finding of one scan: identity plus scan time. Observations are
  append-only. Neither the runtime role nor the owner can update, delete or truncate them.
- **Fingerprint (version 1)** = SHA-256 of the UTF-8 bytes of `k9-observation-fingerprint:v1\n`
  followed by a canonical JSON object (sorted keys, no whitespace) with exactly these fields:
  `muted`, `resource_type`, `result` (Prowler's code, e.g. `FAIL`), `severity_id`,
  `status_detail` (after truncation). Fields added in later Prowler versions stay outside the
  fingerprint until a new fingerprint version adds them. Each observation stores its
  canonical content and `fingerprint_version`. Fingerprints are compared only at the same
  version; a newer version is recomputed from the stored content.
- **File fingerprint** = SHA-256 of the uploaded bytes, unique per organization.

| Upload | Outcome |
|---|---|
| Same bytes as an earlier import in this organization | `200`, the original import; nothing written |
| Same identity and scan time, same fingerprint | Already known; no new row |
| Same identity and scan time, different fingerprint | `409`; the whole file is rejected |
| Same identity twice in one file, identical | Collapsed into one observation |
| Same identity twice in one file, different | `400` `in_file_conflict` |

## Finding lifecycle

A finding exists once an identity has failed at least once. Its state is a pure function
of its whole observation history. The order and concurrency of imports never change it.

- **Conclusive** observations: `FAIL` (muted or not) and an unmuted `PASS`. `MANUAL`,
  `MUTED` and a muted `PASS` are kept in history but decide nothing.
- The **latest conclusive observation by scan time** decides. `FAIL` → **open**.
  `PASS` → **fixed**, labelled `scanner_reported`: Prowler says so, and K9 has not verified it.
- Closing therefore takes a strictly newer, unmuted PASS for the same identity. A
  missing observation, a MANUAL or muted result, or a failed import never closes anything.
- **Reopened**: open again after having been fixed. **Needs review**: the newest observation
  is non-conclusive. **Not reassessed**: the account has a newer scan that does not contain
  this identity.

## Import transaction

1. Validate the whole file before touching the database.
2. Begin a transaction. Take `pg_advisory_xact_lock(k9_assessment_lock_key(org, provider, account))`
   for each account in the file, in ascending key order. A lock-key collision only makes
   imports wait; row-level security still confines every read and write to the organization.
3. Insert observations with `ON CONFLICT DO NOTHING`, then compare fingerprints with the
   stored rows. Any mismatch rolls the whole import back (`409`).
4. Recompute the affected findings from their full history and write them.
5. Record `assessment.import` in the audit log, inside the transaction.
6. Commit. Any failure before this point leaves no import, observation, finding or success
   audit event behind. A rejected upload is recorded as a failure audit event after the rollback.

## API

| Method and path | Role | |
|---|---|---|
| `POST /api/organizations/{id}/assessments/prowler/imports` | Analyst | Body: the OCSF file, `application/json` |
| `GET /api/organizations/{id}/assessments/imports` | Viewer | Import history |
| `GET /api/organizations/{id}/findings?status=open\|fixed` | Viewer | Current findings |
| `GET /api/organizations/{id}/findings/{findingId}` | Viewer | A finding with every observation and the import it came from |

Responses: `201` imported, `200` duplicate file (not audited: nothing changed), `400`
invalid file (`problems`, at most one per finding), `409` conflict with stored history
(`problems`, naming only the incoming observation's check, resource and location), `413`
too large, `415` not JSON, `403` below Analyst, `503` audit log unavailable. Import history
is newest first; a finding's observations are oldest first.

An import reports what it did to current state: `opened` (a new open finding), `reopened`
(fixed → open) and `fixed` (open → fixed). A finding that first appears already fixed (an
older failure imported after a newer pass) is in none of the three.

## Not in V1

Cloud credentials, running Prowler, scheduled scans, providers other than AWS, manual
finding states (risk acceptance), and proof that an uploaded file came from a real scan.
