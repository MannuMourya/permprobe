"""Figure out what a target string actually is."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse


@dataclass
class Target:
    raw: str
    kind: str  # s3 gcs azure http
    bucket: Optional[str] = None
    key: Optional[str] = None
    account: Optional[str] = None  # azure
    container: Optional[str] = None
    region: Optional[str] = None
    url: Optional[str] = None
    endpoint: Optional[str] = None


_S3_VIRTUAL = re.compile(
    r"^https?://([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3(?:[.-]([a-z0-9-]+))?\.amazonaws\.com(?:\.cn)?(/.*)?$",
    re.I,
)
_S3_WEBSITE = re.compile(
    r"^https?://([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3-website[.-]([a-z0-9-]+)\.amazonaws\.com(?:\.cn)?(/.*)?$",
    re.I,
)
_S3_PATH = re.compile(
    r"^https?://s3(?:[.-]([a-z0-9-]+))?\.amazonaws\.com(?:\.cn)?/([^/]+)(/.*)?$",
    re.I,
)
_GCS_VIRTUAL = re.compile(
    r"^https?://([a-z0-9][a-z0-9._\-]{1,220}[a-z0-9])\.storage\.googleapis\.com(/.*)?$",
    re.I,
)
_GCS_PATH = re.compile(
    r"^https?://storage\.googleapis\.com/([^/]+)(/.*)?$",
    re.I,
)
_AZURE = re.compile(
    r"^https?://([a-z0-9]{3,24})\.blob\.core\.windows\.net/([^/?]+)(/.*)?$",
    re.I,
)


def parse_target(raw: str, s3_endpoint: Optional[str] = None) -> Target:
    s = raw.strip()
    if s.startswith("s3://"):
        rest = s[5:]
        bucket, _, key = rest.partition("/")
        return Target(raw=s, kind="s3", bucket=bucket, key=key or None, endpoint=s3_endpoint)
    if s.startswith("gs://"):
        rest = s[5:]
        bucket, _, key = rest.partition("/")
        return Target(raw=s, kind="gcs", bucket=bucket, key=key or None)

    m = _S3_VIRTUAL.match(s)
    if m:
        key = (m.group(3) or "").lstrip("/") or None
        return Target(raw=s, kind="s3", bucket=m.group(1), key=key, region=m.group(2), url=s)
    m = _S3_WEBSITE.match(s)
    if m:
        key = (m.group(3) or "").lstrip("/") or None
        return Target(raw=s, kind="s3", bucket=m.group(1), key=key, region=m.group(2), url=s)
    m = _S3_PATH.match(s)
    if m:
        key = (m.group(3) or "").lstrip("/") or None
        return Target(raw=s, kind="s3", bucket=m.group(2), key=key, region=m.group(1), url=s)
    m = _GCS_VIRTUAL.match(s)
    if m:
        key = (m.group(2) or "").lstrip("/") or None
        return Target(raw=s, kind="gcs", bucket=m.group(1), key=key, url=s)
    m = _GCS_PATH.match(s)
    if m:
        key = (m.group(2) or "").lstrip("/") or None
        return Target(raw=s, kind="gcs", bucket=m.group(1), key=key, url=s)
    m = _AZURE.match(s)
    if m:
        key = (m.group(3) or "").lstrip("/") or None
        return Target(
            raw=s,
            kind="azure",
            account=m.group(1),
            container=m.group(2),
            bucket=m.group(2),
            key=key,
            url=s,
        )

    # Custom S3-compatible endpoint + s3:// already handled. If user passed
    # https://custom-endpoint/bucket/key with --s3-endpoint, treat as S3.
    if s3_endpoint:
        p = urlparse(s)
        path = (p.path or "/").lstrip("/")
        bucket, _, key = path.partition("/")
        return Target(raw=s, kind="s3", bucket=bucket or None, key=key or None, url=s, endpoint=s3_endpoint)

    p = urlparse(s)
    if p.scheme in {"http", "https"} and p.netloc:
        return Target(raw=s, kind="http", url=s)
    raise ValueError(f"Cannot parse target: {raw!r}. Use s3://, gs://, a cloud URL, or https://...")
