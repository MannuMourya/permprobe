# permprobe

Non-destructive permission matrix for cloud storage and HTTP resources.

Point it at an S3 bucket, a GCS bucket, an Azure container, or any HTTPS object and it tells you **which actions are allowed**, the **status code** each action returned, and the **vendor error code** (`AccessDenied` vs `NoSuchBucket` vs `NoSuchKey`). Existing data is never overwritten or deleted.

```text
permprobe s3://target-bucket
permprobe gs://target-bucket --token %GCP_TOKEN%
permprobe https://api.example.com/v1/invoices/4412 --compare-anon
```

```text
ACTION                               METH    ST   CODE                         VERDICT
s3:HeadBucket                        HEAD    200                               ALLOWED
s3:ListBucket                        GET     200                               ALLOWED
s3:GetBucketAcl                      GET     200                               ALLOWED
s3:GetBucketPolicy                   GET     403  AccessDenied                 EXISTS_DENIED
s3:PutObject                         PUT     412                               INFERRED
s3:DeleteObject                      DELETE  403  AccessDenied                 EXISTS_DENIED

FINDINGS
  ! PUBLIC LIST — unauthenticated listing succeeded. Object keys are exposed.
  ! WRITE PATH REACHABLE — PUT returned 412 rather than 403.
```

---

## Why this exists

Most bucket scanners answer one boolean: public or not. That is not enough.

| Status + code | What it actually means |
|---|---|
| `200` / `204` / `206` | Action is allowed |
| `403 AccessDenied` | Resource **exists**, this action is denied |
| `404 NoSuchBucket` | Name is free (or hidden) |
| `404 NoSuchKey` | Bucket exists, object does not |
| `401` | Identity required — retry with keys / token |
| `405 MethodNotAllowed` | Verb is not implemented on this resource |
| `411` / `412` | Write path reached the API without creating a live object |
| `301` + `x-amz-bucket-region` | Bucket exists, wrong region |

`permprobe` records all of that in one table so you can decide the next probe instead of guessing.

---

## Install

Python **3.9+** on Linux, macOS, or Windows. Only runtime dependency: `requests`.

### Linux / macOS

```bash
# from a clone
python3 -m pip install --user .

# or isolated (recommended)
python3 -m pip install --user pipx
pipx install .

# from GitHub
pipx install git+https://github.com/mannumourya/permprobe.git
```

Make sure the scripts directory is on `PATH`:

```bash
# Linux
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# macOS (zsh)
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

Then:

```bash
permprobe --version
permprobe --help
permprobe s3://my-bucket -v
```

### Windows (PowerShell)

```powershell
py -m pip install --user .
```

If `permprobe` is not recognized, add the user Scripts folder to PATH (one-time):

```powershell
$scripts = py -c "import site; print(site.USER_BASE + r'\Python' if False else '')"
# Usually one of:
#   $env:APPDATA\Python\Python312\Scripts
#   $env:LOCALAPPDATA\Programs\Python\Python312\Scripts

[Environment]::SetEnvironmentVariable(
  "Path",
  $env:Path + ";$env:APPDATA\Python\Python312\Scripts",
  "User"
)
```

Close and reopen the terminal, then:

```powershell
permprobe --version
permprobe s3://my-bucket -v
```

`pipx` on Windows works the same way and keeps the tool isolated:

```powershell
py -m pip install --user pipx
py -m pipx ensurepath
pipx install .
```

### Editable install (development)

```bash
python3 -m pip install -e .      # Linux / macOS
py -m pip install -e .           # Windows
```

### Run without installing

```bash
python3 -m permprobe s3://my-bucket
py -m permprobe s3://my-bucket
```

---

## Usage

```text
permprobe [options] TARGET [TARGET ...]
permprobe -f targets.txt [options]
```

| Target | Treated as |
|---|---|
| `s3://bucket` / `s3://bucket/key` | Amazon S3 |
| `https://bucket.s3.amazonaws.com/...` | Amazon S3 |
| `gs://bucket` / `*.storage.googleapis.com` | Google Cloud Storage |
| `https://account.blob.core.windows.net/container` | Azure Blob |
| any other `http(s)://...` | Generic HTTP resource |
| `--s3-endpoint https://...` | S3-compatible (R2, MinIO, Spaces, Wasabi, B2) |

### Common commands

```bash
# public bucket recon (read-only, default)
permprobe s3://target-bucket -v

# known object — GetObject / ACL / tagging
permprobe s3://target-bucket/backups/db.dump

# anonymous vs your AWS keys
permprobe s3://target-bucket --compare-anon

# GCS with access token (uses official testIamPermissions)
permprobe gs://target-bucket --token "$(gcloud auth print-access-token)"

# generic API object — mutating verbs never hit the live URL
permprobe https://api.example.com/v2/users/42 --compare-anon

# opt-in canary write (creates + deletes .__permprobe_<uuid> only)
permprobe s3://target-bucket --mode write-probe

# batch + JSON
permprobe -f buckets.txt --json > matrix.json
```

### Flags

| Flag | Purpose |
|---|---|
| `--mode readonly` | Default. No existing object is written or deleted |
| `--mode write-probe` | Create a unique canary, then delete **only** that canary |
| `--header "Name: value"` | Extra request header (repeatable) |
| `--token TOKEN` | GCP OAuth access token |
| `--profile NAME` | AWS shared-credentials profile (`~/.aws/credentials`) |
| `--region REGION` | AWS region hint (also auto-detected from `x-amz-bucket-region`) |
| `--s3-endpoint URL` | Custom S3-compatible endpoint |
| `--compare-anon` | Run once with auth and once anonymous |
| `--timeout 20` | Per-request timeout in seconds |
| `--insecure` | Skip TLS verify |
| `--json` | Machine-readable output |
| `-v` / `--verbose` | Print evidence + interesting headers |
| `--no-color` | Disable ANSI color (also auto-disabled when not a TTY) |

### Authentication

| Source | Used for |
|---|---|
| none | Anonymous / public checks |
| `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` | SigV4-signed S3 (no boto3) |
| `--profile` | Same, from `~/.aws/credentials` (also works on Windows as `%USERPROFILE%\.aws\credentials`) |
| `--token` / `CLOUDSDK_AUTH_ACCESS_TOKEN` | GCS Bearer + `testIamPermissions` |
| `--header "Authorization: Bearer …"` | Attached to every request |
| `--header "x-ms-..."` or a SAS query on the URL | Azure |

---

## Safety contract

This is the point of the tool.

| Mode | What is sent | Mutates existing data? |
|---|---|---|
| `readonly` (default) | `OPTIONS`, `HEAD`, `GET` (Range `0-0`), list/ACL/policy GETs, `DELETE` of a **non-existent** canary key, `PUT` with `If-Match` on that canary | **No** |
| `write-probe` | Also `PUT`s `.__permprobe_<uuid>`, then `DELETE`s **only that object** | Only the canary it created |

It will never:

- overwrite an existing object key
- send an unconditional `DELETE` to a live object
- change bucket ACL, policy, CORS, versioning, or public-access-block
- run list-delete, complete a multipart upload, or copy over existing keys

Write inference in readonly mode uses `If-Match` against a key that does not exist. On real S3/GCS a `412` means “write is authorized” and the object is **not** created. If a compatible store ignores the precondition and returns `200`, permprobe deletes that canary immediately.

Delete inference (when listing works) sends `DELETE` to **one listed object** with a condition that cannot succeed:

- GCS: `ifGenerationMatch=1` (real generations are large timestamps)
- S3: `If-Match: "permprobe-never-matches"`

`412` = delete is allowed, object kept. `401`/`403` = delete denied. A canary `404 NoSuchKey` is **not** treated as delete-allowed.

---

## Output

Every probe row:

- action name (`s3:ListBucket`, `gcs:objects.get`, `http:OPTIONS`, …)
- HTTP method + URL
- status code
- cloud error code
- verdict
- evidence (with `-v`)

Rolled-up capabilities: `EXISTS`, `LIST`, `READ`, `WRITE`, `DELETE`, `ACL_READ`, `POLICY_READ`, `CORS`, `METADATA`, `TAGS`, `MULTIPART`.

Verdicts:

| Verdict | Meaning |
|---|---|
| `ALLOWED` | Action succeeded |
| `DENIED` | Explicit deny |
| `EXISTS_DENIED` | `403` / `AccessDenied` — resource is allocated |
| `AUTH_REQUIRED` | `401` / missing identity |
| `NOT_FOUND` | Name or key does not exist |
| `METHOD_BLOCKED` | `405` / verb not implemented |
| `INFERRED` | Side-channel (e.g. `412` on `If-Match`) |
| `REDIRECT` | Region / endpoint redirect |
| `SKIPPED` | Probe not conclusive without extra identity |
| `ERROR` | Network / TLS / 5xx |

`--json` emits the same structure for scripts.

---

## How probes are chosen

**S3** — `HeadBucket`, `ListBucket`, `GetBucketAcl`, `GetBucketPolicy`, CORS, versioning, encryption, public-access-block, object lock, lifecycle, logging, multipart list, plus object-level `GetObject` (byte 0 only) when a key is given. Region is taken from `x-amz-bucket-region` / `?location`.

**GCS** — JSON + XML APIs. With `--token`, also `storage.buckets.getIamPolicy` and official `testIamPermissions` (zero side effects).

**Azure Blob** — container properties, list, ACL, metadata. Auth via `--header` or SAS on the URL.

**HTTP** — `OPTIONS` / `HEAD` / `GET` against the live URL. `PUT` / `POST` / `PATCH` / `DELETE` only against a sibling canary path so an existing invoice/user/object cannot be overwritten. `Allow` and CORS headers are surfaced as warnings.

---

## Project layout

```text
permprobe/
├── permprobe/            # library + CLI
│   ├── cli.py
│   ├── detect.py         # s3:// gs:// azure http auto-detect
│   ├── probes_s3.py
│   ├── probes_gcs.py
│   ├── probes_azure.py
│   ├── probes_http.py
│   ├── sigv4.py          # AWS SigV4, no boto3
│   └── report.py
├── pyproject.toml        # pip/pipx install + `permprobe` console script
├── requirements.txt
└── README.md
```

---

## Legal

Authorized testing only. Scanning assets you do not own or do not have written permission to test is illegal. Default mode is non-destructive, but you are responsible for scope.

---

## License

MIT. See [LICENSE](LICENSE).
