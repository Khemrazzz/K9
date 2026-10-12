# Prowler OCSF fixtures

`generate.py` writes the Prowler scans that K9's import contract tests read
(`apps/api/K9.Api.Tests/Fixtures/Prowler/5.44.0/`). It needs no cloud account: synthetic
check results go through Prowler's own `Finding.generate_output` and OCSF writer. The
finding UIDs, region handling and file layout are therefore exactly what Prowler 5.44.0
produces. `manifest.json` lists what each fixture covers.

CI only reads the committed JSON, so it needs neither Python nor Prowler. Regenerate only
when the scenarios or the pinned Prowler version change:

```sh
uv venv --python 3.12 .venv-prowler       # or: python -m venv .venv-prowler
uv pip install --python .venv-prowler --require-hashes -r tools/prowler-fixtures/requirements.txt
.venv-prowler/Scripts/python -I tools/prowler-fixtures/generate.py           # bin/python on Linux/macOS
.venv-prowler/Scripts/python -I tools/prowler-fixtures/generate.py --check   # verify, change nothing
```

The output is byte-for-byte reproducible: the timestamps are fixed, and the random part of
each scan ID is seeded. `requirements.txt` pins every package by hash. It is compiled from
`requirements.in` with `uv pip compile requirements.in --universal --python-version 3.12 --generate-hashes`.

The fixtures differ from a real CLI export in one way: a real export writes `time_dt` in the
scanning machine's local time with no offset, while these write UTC. K9 ignores `time_dt`
and uses `time`, so this does not affect the tests (one of them checks it).

To support a new Prowler version, add a new output directory and a matching entry in
`ProwlerOcsfContract`, and keep the old fixtures. Don't overwrite them in place.
