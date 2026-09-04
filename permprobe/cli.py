"""CLI entrypoint."""

from __future__ import annotations

import argparse
import configparser
import os
import sys
from pathlib import Path
from typing import Optional

from . import __version__
from .detect import parse_target
from .http import Client
from .models import ResourceReport
from .probes_s3 import S3Prober
from .probes_gcs import GCSProber
from .probes_azure import AzureProber
from .probes_http import HTTPProber
from .report import print_report


def _load_aws_profile(name: str) -> dict:
    path = Path.home() / ".aws" / "credentials"
    if not path.exists():
        raise SystemExit(f"AWS profile {name!r} requested but {path} does not exist")
    cfg = configparser.ConfigParser()
    cfg.read(path)
    if name not in cfg:
        raise SystemExit(f"AWS profile {name!r} not in {path}")
    section = cfg[name]
    if "aws_access_key_id" not in section:
        raise SystemExit(f"profile {name!r} has no aws_access_key_id")
    return {
        "access_key": section["aws_access_key_id"],
        "secret_key": section["aws_secret_access_key"],
        "session_token": section.get("aws_session_token"),
    }


def _aws_creds_from_env() -> Optional[dict]:
    key = os.environ.get("AWS_ACCESS_KEY_ID")
    secret = os.environ.get("AWS_SECRET_ACCESS_KEY")
    if key and secret:
        return {
            "access_key": key,
            "secret_key": secret,
            "session_token": os.environ.get("AWS_SESSION_TOKEN"),
        }
    return None


def _parse_headers(items: list[str]) -> dict:
    out = {}
    for raw in items or []:
        if ":" not in raw:
            raise SystemExit(f"--header must be 'Name: value', got {raw!r}")
        k, v = raw.split(":", 1)
        out[k.strip()] = v.strip()
    return out


def _read_targets(args) -> list[str]:
    items = list(args.targets or [])
    if args.file:
        text = Path(args.file).read_text(encoding="utf-8")
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                items.append(line)
    if not items:
        raise SystemExit("no targets. pass URLs or -f file")
    return items


def _probe_one(raw: str, args, extra_headers: dict, creds: Optional[dict], token: Optional[str], identity: str) -> ResourceReport:
    target = parse_target(raw, s3_endpoint=args.s3_endpoint)
    client = Client(
        extra_headers=extra_headers,
        timeout=args.timeout,
        follow_redirects=False,
        verify_tls=not args.insecure,
    )
    mode = args.mode
    if target.kind == "s3":
        region = args.region or target.region or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
        return S3Prober(client, creds=creds, region=region, mode=mode, identity=identity).run(target)
    if target.kind == "gcs":
        return GCSProber(client, token=token, mode=mode, identity=identity).run(target)
    if target.kind == "azure":
        return AzureProber(client, mode=mode, identity=identity).run(target)
    return HTTPProber(client, mode=mode, identity=identity).run(target)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="permprobe",
        description="Non-destructive permission matrix for S3 / GCS / Azure / HTTP resources.",
        epilog="Default mode never writes or deletes existing objects. Use --mode write-probe to create+delete a unique canary only.",
    )
    p.add_argument("targets", nargs="*", help="s3://bucket[/key] | gs://bucket | https://...")
    p.add_argument("-f", "--file", help="file with one target per line")
    p.add_argument("--mode", choices=["readonly", "write-probe"], default="readonly")
    p.add_argument("--header", action="append", default=[], help="extra request header. Repeatable. 'Name: value'")
    p.add_argument("--token", help="GCP OAuth access token (or set CLOUDSDK_AUTH_ACCESS_TOKEN)")
    p.add_argument("--profile", help="AWS shared-credentials profile name")
    p.add_argument("--region", help="AWS region hint (also read from x-amz-bucket-region)")
    p.add_argument("--s3-endpoint", help="S3-compatible endpoint, e.g. https://xxx.r2.cloudflarestorage.com")
    p.add_argument("--compare-anon", action="store_true", help="run once with auth and once anonymous, print both")
    p.add_argument("--timeout", type=float, default=20.0)
    p.add_argument("--insecure", action="store_true", help="skip TLS verify")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.add_argument("-v", "--verbose", action="store_true", help="print evidence + interesting headers")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--version", action="version", version=f"permprobe {__version__}")
    return p


def _configure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def main(argv: Optional[list[str]] = None) -> int:
    _configure_stdio()
    args = build_parser().parse_args(argv)
    extra = _parse_headers(args.header)
    creds = None
    if args.profile:
        creds = _load_aws_profile(args.profile)
    else:
        creds = _aws_creds_from_env()
    token = args.token or os.environ.get("CLOUDSDK_AUTH_ACCESS_TOKEN") or os.environ.get("GOOGLE_OAUTH_ACCESS_TOKEN")

    identity = "anonymous"
    if creds:
        identity = f"aws:{creds['access_key'][:4]}...{creds['access_key'][-2:]}"
    if token:
        identity = "gcs:bearer"
    if extra.get("Authorization") or extra.get("authorization"):
        identity = "header-auth"

    reports: list[ResourceReport] = []
    for raw in _read_targets(args):
        try:
            reports.append(_probe_one(raw, args, extra, creds, token, identity))
            if args.compare_anon and identity != "anonymous":
                anon_headers = {k: v for k, v in extra.items() if k.lower() != "authorization"}
                reports.append(_probe_one(raw, args, anon_headers, None, None, "anonymous"))
        except ValueError as e:
            print(f"skip {raw}: {e}", file=sys.stderr)
        except KeyboardInterrupt:
            print("interrupted", file=sys.stderr)
            return 130

    print_report(reports, as_json=args.json, verbose=args.verbose, use_color=not args.no_color)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
