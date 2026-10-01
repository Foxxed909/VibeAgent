#!/usr/bin/env python3
"""CLI entry: python -m agent.cli …"""
from __future__ import annotations

import argparse
import json

from .job_store import save_job
from .orchestrator import run_job
from .product import resolve_depth, resolve_stress
from .scope import Authorization, CONFIRM_PHRASE


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="VibeAgent / BreakAgent authorized security assessment runner")
    parser.add_argument("--agent", choices=["vibe", "break"], default="vibe", help="Agent mode")
    parser.add_argument("--tier", choices=["hobby", "enterprise"], default="hobby")
    parser.add_argument("--target", action="append", required=True, help="Exact authorized target; repeat for multiple")
    parser.add_argument("--confirm", required=True, help=f"Must equal: {CONFIRM_PHRASE}")
    parser.add_argument("--app-name")
    parser.add_argument("--company-name")
    parser.add_argument("--contact-email")
    parser.add_argument("--emergency-contact")
    parser.add_argument("--access-code")
    parser.add_argument("--model")
    parser.add_argument("--depth", choices=["quick", "standard", "deep"], default="standard")
    parser.add_argument("--stress", type=int)
    parser.add_argument("--stress-mode", choices=["capped", "org"], default="capped")
    parser.add_argument("--cookie")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--save", action="store_true", help="Persist report using the configured job store")
    args = parser.parse_args(argv)

    auth = Authorization(
        tier=args.tier,
        targets=args.target,
        confirmation=args.confirm,
        app_name=args.app_name,
        company_name=args.company_name,
        contact_email=args.contact_email,
        emergency_contact=args.emergency_contact,
        access_code=args.access_code,
    )
    depth = resolve_depth(args.tier, args.depth, args.access_code)
    stress_m, stress_mode = resolve_stress(args.tier, args.access_code, args.stress, args.stress_mode)

    report = run_job(
        auth,
        dry_run=args.dry_run,
        model=args.model,
        depth=depth,
        stress_multiplier=stress_m,
        stress_mode=stress_mode,
        cookie=args.cookie,
        agent_mode=args.agent,
    )
    if args.save:
        save_job(report)
    print(json.dumps(report, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
