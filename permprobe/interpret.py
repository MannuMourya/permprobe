"""Turn status + vendor error code into a verdict a hunter can act on."""

from __future__ import annotations

import re
from typing import Optional

from .models import ProbeResult, Verdict


INTERESTING_HEADER_NAMES = {
    "allow",
    "accept-ranges",
    "access-control-allow-origin",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-allow-credentials",
    "access-control-expose-headers",
    "access-control-max-age",
    "www-authenticate",
    "x-amz-bucket-region",
    "x-amz-request-id",
    "x-amz-id-2",
    "x-amz-version-id",
    "x-amz-delete-marker",
    "x-amz-server-side-encryption",
    "x-amz-replication-status",
    "x-amz-mp-parts-count",
    "x-amz-object-lock-mode",
    "x-amzn-requestid",
    "x-guploader-uploadid",
    "x-goog-generation",
    "x-goog-metageneration",
    "x-goog-storage-class",
    "x-goog-hash",
    "x-goog-stored-content-length",
    "cf-ray",
    "x-amz-cf-id",
    "x-amz-cf-pop",
    "x-ms-request-id",
    "x-ms-version",
    "x-ms-blob-type",
    "x-ms-lease-status",
    "x-ms-error-code",
    "x-cache",
    "server",
    "content-type",
    "content-range",
    "etag",
    "location",
}


S3_EXISTS_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "AllAccessDisabled",
    "InvalidAccessKeyId",
    "SignatureDoesNotMatch",
    "InvalidRequest",
    "AccessControlListNotSupported",
    "MethodNotAllowed",
    "PermanentRedirect",
    "TemporaryRedirect",
    "AuthorizationHeaderMalformed",
    "InvalidBucketName",
    "InvalidArgument",
    "InlineDataTooLarge",
    "MissingContentLength",
    "IncompleteBody",
    "RequestTimeout",
    "SlowDown",
}

S3_NOT_FOUND_CODES = {"NoSuchBucket", "NoSuchKey", "NoSuchWebsiteConfiguration", "NoSuchCORSConfiguration", "NoSuchLifecycleConfiguration", "NoSuchTagSet", "ReplicationConfigurationNotFoundError", "ServerSideEncryptionConfigurationNotFoundError", "ObjectLockConfigurationNotFoundError"}


def pick_headers(headers: dict) -> dict:
    out = {}
    for k, v in headers.items():
        if k.lower() in INTERESTING_HEADER_NAMES:
            out[k] = v
    return out


def extract_error_code(body: str, headers: dict) -> tuple[Optional[str], Optional[str]]:
    if not body:
        hdr = headers.get("x-ms-error-code") or headers.get("X-Ms-Error-Code")
        return (hdr, None) if hdr else (None, None)
    text = body[:4000]
    m = re.search(r"<Code>([^<]+)</Code>", text)
    if m:
        msg = None
        mm = re.search(r"<Message>([^<]+)</Message>", text)
        if mm:
            msg = mm.group(1).strip()
        return m.group(1).strip(), msg
    m = re.search(r'"error"\s*:\s*\{\s*"code"\s*:\s*"([^"]+)"', text)
    if m:
        mm = re.search(r'"message"\s*:\s*"([^"]+)"', text)
        return m.group(1), mm.group(1) if mm else None
    m = re.search(r'"code"\s*:\s*"([^"]+)"', text)
    if m:
        mm = re.search(r'"message"\s*:\s*"([^"]+)"', text)
        return m.group(1), mm.group(1) if mm else None
    m = re.search(r"<Error>\s*<Code>([^<]+)</Code>", text, re.I)
    if m:
        return m.group(1), None
    return None, None


def classify(status: Optional[int], error_code: Optional[str], method: str, action: str) -> Verdict:
    if status is None:
        return Verdict.ERROR

    code = error_code or ""

    if status in (301, 302, 307, 308):
        return Verdict.REDIRECT

    if status in (200, 204, 206, 304):
        return Verdict.ALLOWED

    if status == 401 or code in {"AuthenticationRequired", "ExpiredToken", "InvalidToken", "AuthFailure"}:
        return Verdict.AUTH_REQUIRED

    if status == 405 or code in {"MethodNotAllowed", "UnsupportedMethod"}:
        return Verdict.METHOD_BLOCKED

    if status == 404 or code in S3_NOT_FOUND_CODES:
        # Probers upgrade specific 404s (e.g. S3 NoSuchKey on DELETE) themselves.
        return Verdict.NOT_FOUND

    if status == 411 or code in {"MissingContentLength", "IncompleteBody"}:
        # PUT reached the API; length missing. Strong write-path signal.
        return Verdict.INFERRED

    if status == 412:
        return Verdict.INFERRED

    if status == 409:
        return Verdict.INFERRED

    if status in (400, 411, 413, 416):
        if code in {"AccessControlListNotSupported"}:
            return Verdict.DENIED
        return Verdict.INFERRED

    if status == 403:
        if code in {"NoSuchBucket"}:
            return Verdict.NOT_FOUND
        return Verdict.EXISTS_DENIED if code in S3_EXISTS_CODES or not code else Verdict.DENIED

    if status == 501:
        return Verdict.METHOD_BLOCKED

    if status >= 500:
        return Verdict.ERROR

    return Verdict.DENIED


def summarize_capabilities(probes: list[ProbeResult]) -> dict[str, str]:
    """Roll probe verdicts up to coarse capabilities. First strong signal wins,
    later probes can upgrade INFERRED -> ALLOWED."""
    rank = {
        Verdict.ALLOWED.value: 6,
        Verdict.INFERRED.value: 5,
        Verdict.EXISTS_DENIED.value: 4,
        Verdict.AUTH_REQUIRED.value: 3,
        Verdict.DENIED.value: 2,
        Verdict.METHOD_BLOCKED.value: 2,
        Verdict.NOT_FOUND.value: 1,
        Verdict.REDIRECT.value: 1,
        Verdict.ERROR.value: 0,
        Verdict.SKIPPED.value: 0,
    }
    cap: dict[str, tuple[int, str, str]] = {}
    for p in probes:
        key = p.capability
        label = f"{p.verdict.value} ({p.status if p.status is not None else 'err'} {p.error_code or p.action})"
        score = rank.get(p.verdict.value, 0)
        # A successful ALLOWED on the same cap should dominate.
        if key not in cap or score > cap[key][0]:
            cap[key] = (score, p.verdict.value, label)
        elif score == cap[key][0] and p.verdict == Verdict.ALLOWED:
            cap[key] = (score, p.verdict.value, label)
    return {k: v[2] for k, v in cap.items()}


def findings_from(probes: list[ProbeResult], kind: str) -> list[str]:
    out: list[str] = []
    by_action = {p.action: p for p in probes}

    def allowed(action: str) -> bool:
        p = by_action.get(action)
        return bool(p and p.verdict == Verdict.ALLOWED)

    def inferred(action: str) -> bool:
        p = by_action.get(action)
        return bool(p and p.verdict in (Verdict.ALLOWED, Verdict.INFERRED))

    if allowed("s3:ListBucket") or allowed("gcs:objects.list") or allowed("azure:ListBlobs"):
        out.append("PUBLIC LIST — unauthenticated listing succeeded. Object keys are exposed.")
    if allowed("s3:GetObject") or allowed("gcs:objects.get") or allowed("azure:GetBlob"):
        out.append("PUBLIC READ — object bytes are retrievable without credentials.")
    if allowed("s3:GetBucketAcl") or allowed("s3:GetObjectAcl") or allowed("gcs:buckets.getIamPolicy"):
        out.append("ACL/POLICY READ — access-control document is readable. Useful for priv-esc mapping.")
    if allowed("s3:GetBucketPolicy"):
        out.append("BUCKET POLICY READ — policy document leaked.")
    if any(p.action == "s3:PutObject" and p.verdict in (Verdict.ALLOWED, Verdict.INFERRED) and p.mutated for p in probes):
        out.append("PUBLIC WRITE — canary object was created. Bucket accepts unauthenticated PUT.")
    elif any(
        p.action == "s3:PutObject" and p.verdict == Verdict.INFERRED and p.status in (411, 412, 409)
        for p in probes
    ):
        out.append("WRITE PATH REACHABLE — PUT returned 411/412 rather than 403. Confirm with --mode write-probe.")
    if any(
        p.action in {"gcs:objects.delete.precondition", "s3:DeleteObject.precondition", "azure:DeleteBlob.precondition"}
        and p.verdict == Verdict.INFERRED
        and p.status == 412
        for p in probes
    ):
        out.append("PUBLIC DELETE — conditional DELETE on a live object returned 412. IAM allows delete; the object was not removed.")
    elif any(
        p.action in {"gcs:objects.delete.precondition", "s3:DeleteObject.precondition"}
        and p.verdict in (Verdict.AUTH_REQUIRED, Verdict.EXISTS_DENIED, Verdict.DENIED)
        for p in probes
    ):
        out.append("DELETE DENIED for this identity — conditional DELETE on a live object returned 401/403. A canary 404 is not proof of delete.")
    if any(p.action in {"s3:DeleteObject", "http:DELETE-canary"} and p.verdict == Verdict.ALLOWED for p in probes):
        out.append("DELETE ALLOWED on canary key — delete permission is granted (existing keys were not touched).")
    if allowed("http:OPTIONS") and any("PUT" in (p.interesting_headers.get("Allow") or p.interesting_headers.get("Access-Control-Allow-Methods") or "") for p in probes if p.action == "http:OPTIONS"):
        out.append("OPTIONS advertises PUT — server claims write is allowed. Verify with a canary, never against the live object.")
    if any(p.verdict == Verdict.EXISTS_DENIED for p in probes):
        out.append("RESOURCE EXISTS — 403/AccessDenied (not 404). Name is allocated; try authenticated identity or sibling keys.")
    return out


_CDN_SERVER_HINTS = (
    "cloudflare",
    "cloudfront",
    "akamai",
    "fastly",
    "varnish",
    "sucuri",
    "incapsula",
    "imperva",
    "awselb",
)

_EDGE_HEADER_MARKERS = ("cf-ray", "x-amz-cf-id", "x-amz-cf-pop")

_ORIGIN_HEADER_MARKERS = (
    "x-amz-request-id",
    "x-amz-id-2",
    "x-amz-bucket-region",
    "x-guploader-uploadid",
    "x-goog-generation",
    "x-goog-hash",
    "x-goog-stored-content-length",
    "x-ms-request-id",
    "x-ms-version",
    "x-ms-error-code",
)


def classify_origin(headers: dict) -> str:
    """Per-response origin confidence: origin | edge | mixed | unknown."""
    if not headers:
        return "unknown"
    h = {str(k).lower(): str(v) for k, v in headers.items()}
    server = (h.get("server") or "").lower()
    hit_origin = any(m in h for m in _ORIGIN_HEADER_MARKERS)
    if "amazons3" in server or "uploadserver" in server:
        hit_origin = True
    hit_edge = any(m in h for m in _EDGE_HEADER_MARKERS)
    if any(hint in server for hint in _CDN_SERVER_HINTS):
        hit_edge = True
    if hit_origin and hit_edge:
        return "mixed"
    if hit_origin:
        return "origin"
    if hit_edge:
        return "edge"
    return "unknown"


def origin_warnings(kind: str, probes: list[ProbeResult]) -> list[str]:
    """Roll per-probe origin tags into run-level warnings.

    GET/HEAD/OPTIONS are often CDN-cached while PUT/DELETE go to origin.
    A single aggregate check would hide that split.
    """
    answered = [p for p in probes if p.status is not None]
    if not answered:
        return []

    by = {}
    for p in answered:
        tag = p.origin or "unknown"
        by.setdefault(tag, []).append(p)

    warnings: list[str] = []
    edge_like = by.get("edge", []) + by.get("mixed", [])
    origin_like = by.get("origin", [])
    unknown = by.get("unknown", [])

    if edge_like and origin_like:
        edge_methods = sorted({p.method for p in edge_like})
        origin_methods = sorted({p.method for p in origin_like})
        warnings.append(
            "MIXED ROUTING — some verbs hit a CDN/WAF, others hit storage origin. "
            f"edge/mixed: {', '.join(edge_methods)}; origin: {', '.join(origin_methods)}. "
            "Do not treat edge status codes as IAM."
        )
    elif edge_like and not origin_like:
        warnings.append(
            "CDN/WAF fingerprint on every answered probe. Status codes may reflect the edge, not bucket IAM. "
            f"Re-run against the canonical origin "
            f"({'*.s3.amazonaws.com' if kind == 's3' else 'storage.googleapis.com' if kind == 'gcs' else '*.blob.core.windows.net' if kind == 'azure' else 'the storage API host'})."
        )
    elif kind in {"s3", "gcs", "azure"} and unknown and not origin_like and not edge_like:
        warnings.append(
            f"No native {kind.upper()} origin headers on any response. "
            "This target may be a custom domain, CDN, or reverse proxy. "
            "Treat the matrix as the edge's behavior until you hit the storage API directly."
        )

    tainted = [p for p in answered if p.origin in {"edge", "unknown"} and p.capability in {"LIST", "READ", "EXISTS", "CORS"}]
    clean_mut = [p for p in answered if p.origin == "origin" and p.capability in {"WRITE", "DELETE"}]
    if tainted and clean_mut:
        warnings.append(
            "LIST/READ/OPTIONS look edge-or-unknown while WRITE/DELETE look like origin. "
            "A cached 200 list is not the same signal as an origin 403 delete."
        )
    return warnings
