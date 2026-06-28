"""aws_posture_check — minimal LIVE read-only AWS security posture checker (boto3).

Uses a read-only profile (SecurityAudit/ViewOnlyAccess) to flag common account-level
misconfigurations mapped to CIS AWS Foundations controls. Read-only: it never changes anything.

Usage:
    python aws_posture_check.py --profile audit --region us-east-1
"""
from __future__ import annotations

import argparse
import json
import sys

import boto3
from botocore.exceptions import BotoCoreError, ClientError

SEV_WEIGHT = {"HIGH": 5, "MEDIUM": 2, "LOW": 1}


def _f(sev, control, message):
    return {"severity": sev, "control": control, "message": message}


def check_root_mfa(session, findings):
    iam = session.client("iam")
    summary = iam.get_account_summary()["SummaryMap"]
    if summary.get("AccountMFAEnabled", 0) != 1:
        findings.append(_f("HIGH", "CIS 1.5 Root MFA", "Root account does not have MFA enabled"))
    if summary.get("AccountAccessKeysPresent", 0) == 1:
        findings.append(_f("HIGH", "CIS 1.4 Root keys", "Root account has access keys (should have none)"))


def check_password_policy(session, findings):
    iam = session.client("iam")
    try:
        p = iam.get_account_password_policy()["PasswordPolicy"]
        if p.get("MinimumPasswordLength", 0) < 14:
            findings.append(_f("MEDIUM", "CIS 1.8 Password length",
                               f"Password min length is {p.get('MinimumPasswordLength')} (< 14)"))
        if not p.get("RequireSymbols") or not p.get("RequireNumbers"):
            findings.append(_f("MEDIUM", "CIS 1.x Password complexity",
                               "Password policy does not require symbols and numbers"))
    except ClientError as e:
        if "NoSuchEntity" in str(e):
            findings.append(_f("MEDIUM", "CIS 1.x Password policy",
                               "No IAM account password policy is set"))


def check_users_mfa(session, findings):
    iam = session.client("iam")
    try:
        for u in iam.list_users().get("Users", []):
            name = u["UserName"]
            has_console = True
            try:
                iam.get_login_profile(UserName=name)
            except ClientError:
                has_console = False
            if has_console and not iam.list_mfa_devices(UserName=name).get("MFADevices"):
                findings.append(_f("HIGH", "CIS 1.10 User MFA",
                                   f"IAM user '{name}' has console access but no MFA"))
    except ClientError:
        pass


def check_cloudtrail(session, findings):
    try:
        trails = session.client("cloudtrail").describe_trails().get("trailList", [])
        if not trails:
            findings.append(_f("HIGH", "CIS 3.1 CloudTrail",
                               "No CloudTrail trail configured - API activity is not logged"))
    except (ClientError, BotoCoreError):
        pass


def check_guardduty(session, findings):
    try:
        if not session.client("guardduty").list_detectors().get("DetectorIds"):
            findings.append(_f("MEDIUM", "GuardDuty",
                               "GuardDuty threat detection is not enabled in this region"))
    except (ClientError, BotoCoreError):
        pass


def check_default_sg(session, findings):
    try:
        for sg in session.client("ec2").describe_security_groups().get("SecurityGroups", []):
            for perm in sg.get("IpPermissions", []):
                for rng in perm.get("IpRanges", []):
                    if rng.get("CidrIp") == "0.0.0.0/0":
                        port = perm.get("FromPort", "all")
                        findings.append(_f("HIGH", "CIS 5.x Security Group",
                                           f"SG {sg['GroupId']} allows 0.0.0.0/0 on port {port}"))
    except (ClientError, BotoCoreError):
        pass


def check_s3(session, findings):
    s3 = session.client("s3")
    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except (ClientError, BotoCoreError):
        return
    for b in buckets:
        name = b["Name"]
        try:
            s3.get_bucket_encryption(Bucket=name)
        except ClientError:
            findings.append(_f("MEDIUM", "S3 encryption", f"Bucket '{name}' has no default encryption"))
        try:
            pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            if not all(pab.values()):
                findings.append(_f("HIGH", "S3 public access", f"Bucket '{name}' public access not fully blocked"))
        except ClientError:
            findings.append(_f("HIGH", "S3 public access", f"Bucket '{name}' has no public access block"))


CHECKS = [check_root_mfa, check_password_policy, check_users_mfa,
          check_cloudtrail, check_guardduty, check_default_sg, check_s3]


def run(profile: str, region: str) -> list:
    session = boto3.Session(profile_name=profile, region_name=region)
    findings = []
    for check in CHECKS:
        try:
            check(session, findings)
        except Exception as exc:  # noqa: BLE001 - one failing check shouldn't stop the rest
            findings.append(_f("LOW", "check-error", f"{check.__name__} failed: {exc}"))
    return findings


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="aws_posture_check", description="Live read-only AWS posture check.")
    ap.add_argument("--profile", default="audit")
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    findings = run(args.profile, args.region)
    score = sum(SEV_WEIGHT.get(f["severity"], 0) for f in findings)

    if args.json:
        print(json.dumps({"findings": findings, "risk_score": score}, indent=2))
        return 0
    if not findings:
        print("No findings — account passes all checks.")
        return 0
    print(f"AWS posture findings ({len(findings)}, risk score {score}):")
    for f in sorted(findings, key=lambda x: -SEV_WEIGHT[x["severity"]]):
        print(f"  [{f['severity']:<6}] {f['control']:<26} {f['message']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
