"""Amazon S3 + S3-compatible permission probes.

Safety:
  * Never PUT/DELETE an existing key.
  * PUT without body is used to infer write (expects 411/403).
  * write-probe mode PUTs a unique canary and deletes only that canary.
"""

from __future__ import annotations

import re
import uuid
from typing import Optional
from urllib.parse import quote

from .http import Client
from .models import ProbeResult, ResourceReport, Verdict
from .interpret import summarize_capabilities, findings_from
from .sigv4 import sign_headers
from .detect import Target


# Bucket subresources we can GET without mutating anything.
BUCKET_GETS = [
    ("", "s3:ListBucket", "LIST"),
    ("location", "s3:GetBucketLocation", "METADATA"),
    ("acl", "s3:GetBucketAcl", "ACL_READ"),
    ("policy", "s3:GetBucketPolicy", "POLICY_READ"),
    ("policyStatus", "s3:GetBucketPolicyStatus", "POLICY_READ"),
    ("cors", "s3:GetBucketCORS", "CORS"),
    ("versioning", "s3:GetBucketVersioning", "METADATA"),
    ("website", "s3:GetBucketWebsite", "METADATA"),
    ("tagging", "s3:GetBucketTagging", "TAGS"),
    ("logging", "s3:GetBucketLogging", "METADATA"),
    ("lifecycle", "s3:GetLifecycleConfiguration", "METADATA"),
    ("encryption", "s3:GetEncryptionConfiguration", "METADATA"),
    ("publicAccessBlock", "s3:GetBucketPublicAccessBlock", "METADATA"),
    ("object-lock", "s3:GetBucketObjectLockConfiguration", "METADATA"),
    ("notification", "s3:GetBucketNotification", "METADATA"),
    ("replication", "s3:GetReplicationConfiguration", "METADATA"),
    ("requestPayment", "s3:GetBucketRequestPayment", "METADATA"),
    ("accelerate", "s3:GetAccelerateConfiguration", "METADATA"),
    ("uploads", "s3:ListBucketMultipartUploads", "MULTIPART"),
]

OBJECT_GETS = [
    ("", "s3:GetObject", "READ"),
    ("acl", "s3:GetObjectAcl", "ACL_READ"),
    ("tagging", "s3:GetObjectTagging", "TAGS"),
    ("legal-hold", "s3:GetObjectLegalHold", "METADATA"),
    ("retention", "s3:GetObjectRetention", "METADATA"),
    ("attributes", "s3:GetObjectAttributes", "METADATA"),
]


def _virtual_url(bucket: str, region: Optional[str], key: Optional[str] = None, endpoint: Optional[str] = None) -> str:
    if endpoint:
        base = endpoint.rstrip("/")
        url = f"{base}/{bucket}"
    elif region and region not in {"us-east-1", "US"}:
        url = f"https://{bucket}.s3.{region}.amazonaws.com"
    else:
        url = f"https://{bucket}.s3.amazonaws.com"
    if key:
        url += "/" + quote(key, safe="/-_.~")
    return url


def _with_sub(url: str, sub: str) -> str:
    if not sub:
        return url
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}{sub}"


class S3Prober:
    def __init__(
        self,
        client: Client,
        creds: Optional[dict] = None,
        region: str = "us-east-1",
        mode: str = "readonly",
        identity: str = "anonymous",
    ):
        self.client = client
        self.creds = creds
        self.region = region
        self.mode = mode
        self.identity = identity

    def _call(
        self,
        method: str,
        url: str,
        action: str,
        capability: str,
        extra_headers: Optional[dict] = None,
        data=None,
        mutated: bool = False,
    ) -> ProbeResult:
        hdrs = dict(extra_headers or {})
        signed = False
        if self.creds:
            signed_hdrs = sign_headers(
                method,
                url,
                access_key=self.creds["access_key"],
                secret_key=self.creds["secret_key"],
                region=self.region,
                session_token=self.creds.get("session_token"),
                extra_headers=hdrs,
            )
            hdrs.update(signed_hdrs)
            signed = True
        return self.client.request(
            method,
            url,
            action=action,
            capability=capability,
            headers=hdrs,
            data=data,
            signed=signed,
            mutated=mutated,
        )

    def _first_listed_key(self, base: str) -> Optional[str]:
        url = _with_sub(base, "list-type=2&max-keys=5")
        try:
            resp = self.client.session.get(
                url,
                timeout=self.client.timeout,
                allow_redirects=False,
                verify=self.client.verify_tls,
            )
            if resp.status_code != 200:
                return None
            keys = re.findall(r"<Key>([^<]+)</Key>", resp.text or "")
            return keys[0] if keys else None
        except Exception:
            return None

    def _precondition_delete(self, bucket: str, region: str, key: str, endpoint: Optional[str]) -> ProbeResult:
        obj_url = _virtual_url(bucket, None if region == "us-east-1" else region, key=key, endpoint=endpoint)
        p = self._call(
            "DELETE",
            obj_url,
            "s3:DeleteObject.precondition",
            "DELETE",
            extra_headers={"If-Match": '"permprobe-never-matches"'},
        )
        if p.status == 412:
            p.verdict = Verdict.INFERRED
            p.evidence = f"412 If-Match miss on {key} — DeleteObject allowed, object not removed"
        elif p.status == 400 and "conditional" in (p.evidence or "").lower():
            p.verdict = Verdict.SKIPPED
            p.evidence = "If-Match DELETE requires SigV4 on AWS. Pass keys or treat canary 204 as the signal."
        elif p.status == 403:
            p.verdict = Verdict.EXISTS_DENIED
            p.evidence = p.evidence or f"DeleteObject denied on {key}"
        elif p.status == 401:
            p.verdict = Verdict.AUTH_REQUIRED
        elif p.status in (200, 204):
            p.verdict = Verdict.ALLOWED
            p.mutated = True
            p.evidence = f"WARNING: {key} may have been deleted (If-Match was ignored)"
        p.note = f"If-Match never-matches on live object {key}"
        return p

    def _discover_region(self, bucket: str, endpoint: Optional[str]) -> tuple[str, list[ProbeResult]]:
        probes: list[ProbeResult] = []
        url = _virtual_url(bucket, None, endpoint=endpoint)
        p = self._call("HEAD", url, "s3:HeadBucket", "EXISTS")
        probes.append(p)
        region = self.region
        hdr_region = (
            p.interesting_headers.get("x-amz-bucket-region")
            or p.interesting_headers.get("X-Amz-Bucket-Region")
        )
        if hdr_region:
            region = hdr_region
        if p.status in (301, 307) or p.verdict == Verdict.REDIRECT:
            loc = p.interesting_headers.get("Location") or p.interesting_headers.get("location")
            if loc and ".s3." in loc:
                # https://bucket.s3.eu-west-1.amazonaws.com/
                try:
                    host = loc.split("//", 1)[1].split("/", 1)[0]
                    parts = host.split(".s3.")
                    if len(parts) == 2:
                        region = parts[1].split(".amazonaws")[0]
                except Exception:
                    pass
        # location subresource is the authoritative read
        loc_url = _with_sub(_virtual_url(bucket, region if region != "us-east-1" else None, endpoint=endpoint), "location")
        lp = self._call("GET", loc_url, "s3:GetBucketLocation", "METADATA")
        probes.append(lp)
        if lp.status == 200 and lp.evidence:
            import re

            m = re.search(r"<LocationConstraint>([^<]*)</LocationConstraint>", lp.evidence)
            if m and m.group(1):
                region = m.group(1)
            elif lp.status == 200:
                # empty constraint = us-east-1
                region = region or "us-east-1"
        self.region = region or "us-east-1"
        return self.region, probes

    def run(self, target: Target) -> ResourceReport:
        bucket = target.bucket
        if not bucket:
            raise ValueError("S3 target is missing a bucket name")
        key = target.key
        endpoint = target.endpoint
        region, bootstrap = self._discover_region(bucket, endpoint)
        if target.region:
            region = target.region
            self.region = region

        base = _virtual_url(bucket, None if region == "us-east-1" else region, endpoint=endpoint)
        report = ResourceReport(
            target=target.raw,
            kind="s3",
            resolved_url=base,
            region=region,
            identity=self.identity,
        )
        report.probes.extend(bootstrap)

        # OPTIONS for CORS
        report.probes.append(
            self._call(
                "OPTIONS",
                base,
                "s3:OPTIONS",
                "CORS",
                extra_headers={
                    "Origin": "https://permprobe.example",
                    "Access-Control-Request-Method": "GET",
                    "Access-Control-Request-Headers": "x-amz-date",
                },
            )
        )

        for sub, action, cap in BUCKET_GETS:
            # already issued location + head
            if action in {"s3:GetBucketLocation", "s3:HeadBucket"}:
                continue
            url = _with_sub(base, sub) if sub else base
            method = "GET"
            extra = {}
            if action == "s3:ListBucket":
                url = _with_sub(base, "list-type=2&max-keys=2")
            report.probes.append(self._call(method, url, action, cap, extra_headers=extra))

        # Object-level if a key was given
        if key:
            obj_url = _virtual_url(bucket, None if region == "us-east-1" else region, key=key, endpoint=endpoint)
            report.probes.append(self._call("HEAD", obj_url, "s3:HeadObject", "EXISTS"))
            for sub, action, cap in OBJECT_GETS:
                url = _with_sub(obj_url, sub) if sub else obj_url
                extra = {}
                if action == "s3:GetObject":
                    extra = {"Range": "bytes=0-0"}
                if action == "s3:GetObjectAttributes":
                    extra = {"x-amz-object-attributes": "ETag,ObjectSize"}
                    url = _with_sub(obj_url, "attributes")
                report.probes.append(self._call("GET", url, action, cap, extra_headers=extra))

        live_key = key or self._first_listed_key(base)
        if live_key:
            report.probes.append(self._precondition_delete(bucket, region, live_key, endpoint))
        else:
            report.probes.append(
                ProbeResult(
                    action="s3:DeleteObject.precondition",
                    capability="DELETE",
                    method="DELETE",
                    url=base,
                    verdict=Verdict.SKIPPED,
                    evidence="no live object key available to run If-Match DELETE",
                )
            )

        # Non-destructive write/delete inference against a canary key that
        # we have never created (unless write-probe).
        canary = f".__permprobe_{uuid.uuid4().hex}"
        canary_url = _virtual_url(bucket, None if region == "us-east-1" else region, key=canary, endpoint=endpoint)

        # Non-destructive write inference:
        # If-Match on a key that does not exist fails with 412 *after* auth,
        # so a 412 means PutObject is allowed without creating the object.
        # 403 = no write. 200 would be a store that ignored If-Match — we
        # immediately delete that canary.
        put_infer = self._call(
            "PUT",
            canary_url,
            "s3:PutObject",
            "WRITE",
            extra_headers={"If-Match": '"permprobe-never-matches"', "Content-Type": "application/octet-stream"},
        )
        if put_infer.status == 404:
            put_infer.verdict = Verdict.NOT_FOUND
            put_infer.note = "PUT 404 — bucket may not exist"
        elif put_infer.status == 412:
            put_infer.verdict = Verdict.INFERRED
            put_infer.evidence = "412 Precondition Failed on If-Match — PutObject authorized, object not created"
        elif put_infer.status == 400 and "conditional writes" in (put_infer.evidence or "").lower():
            put_infer.verdict = Verdict.SKIPPED
            put_infer.evidence = "If-Match requires SigV4 on AWS. Pass keys or use --mode write-probe."
        elif put_infer.status in (200, 204):
            put_infer.verdict = Verdict.ALLOWED
            put_infer.mutated = True
            put_infer.note = "store ignored If-Match and created the canary; deleting it"
            self._call("DELETE", canary_url, "s3:DeleteObject", "DELETE", mutated=True)
        report.probes.append(put_infer)

        # DELETE of a key we never created. 204 = delete allowed (idempotent
        # success). 404 NoSuchKey = delete permission + key missing. 403 = deny.
        del_infer = self._call("DELETE", canary_url, "s3:DeleteObject", "DELETE")
        if del_infer.status == 204:
            del_infer.verdict = Verdict.ALLOWED
            del_infer.evidence = "204 on never-created key (S3 delete is idempotent when permitted)"
        elif del_infer.status == 404 and (del_infer.error_code or "") == "NoSuchKey":
            del_infer.verdict = Verdict.ALLOWED
            del_infer.evidence = "NoSuchKey — delete was authorized, object did not exist"
        report.probes.append(del_infer)

        if self.mode == "write-probe":
            body = b"permprobe-canary-ok"
            put = self._call(
                "PUT",
                canary_url,
                "s3:PutObject",
                "WRITE",
                extra_headers={"Content-Type": "text/plain"},
                data=body,
                mutated=True,
            )
            if put.status in (200, 204):
                put.verdict = Verdict.ALLOWED
                put.evidence = f"created canary {canary}"
            report.probes.append(put)
            # always try to clean up our own canary
            cleanup = self._call("DELETE", canary_url, "s3:DeleteObject", "DELETE", mutated=True)
            cleanup.note = f"cleanup of {canary}"
            report.probes.append(cleanup)

        report.capabilities = summarize_capabilities(report.probes)
        report.findings = findings_from(report.probes, "s3")
        if any(p.status in (301, 307) for p in report.probes) and region:
            report.warnings.append(f"Followed/detected region {region}. Re-run against the regional endpoint if probes look thin.")
        return report
