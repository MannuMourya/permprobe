"""Minimal AWS SigV4 signer. No boto3. Enough for S3 REST probes."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
from urllib.parse import urlsplit, parse_qsl, quote


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret: str, datestamp: str, region: str, service: str) -> bytes:
    k_date = _sign(("AWS4" + secret).encode("utf-8"), datestamp)
    k_region = hmac.new(k_date, region.encode(), hashlib.sha256).digest()
    k_service = hmac.new(k_region, service.encode(), hashlib.sha256).digest()
    return hmac.new(k_service, b"aws4_request", hashlib.sha256).digest()


def sign_headers(
    method: str,
    url: str,
    *,
    access_key: str,
    secret_key: str,
    region: str,
    service: str = "s3",
    session_token: str | None = None,
    extra_headers: dict | None = None,
    payload_hash: str = "UNSIGNED-PAYLOAD",
) -> dict:
    parts = urlsplit(url)
    host = parts.netloc
    canonical_uri = parts.path or "/"
    # S3 requires URI encoding but keeps slashes
    canonical_uri = quote(canonical_uri, safe="/-_.~")

    qs = parse_qsl(parts.query, keep_blank_values=True)
    qs_sorted = sorted((quote(k, safe="-_.~"), quote(v, safe="-_.~")) for k, v in qs)
    canonical_query = "&".join(f"{k}={v}" for k, v in qs_sorted)

    now = dt.datetime.utcnow()
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")

    headers = {"host": host, "x-amz-date": amz_date, "x-amz-content-sha256": payload_hash}
    if session_token:
        headers["x-amz-security-token"] = session_token
    if extra_headers:
        for k, v in extra_headers.items():
            headers[k.lower()] = v

    signed_header_keys = sorted(headers.keys())
    canonical_headers = "".join(f"{k}:{headers[k].strip()}\n" for k in signed_header_keys)
    signed_headers = ";".join(signed_header_keys)

    canonical_request = "\n".join(
        [
            method.upper(),
            canonical_uri,
            canonical_query,
            canonical_headers,
            signed_headers,
            payload_hash,
        ]
    )
    scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )
    key = _signing_key(secret_key, datestamp, region, service)
    signature = hmac.new(key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    headers["Authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    return headers
