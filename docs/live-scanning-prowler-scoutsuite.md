# Live Cloud Scanning — Prowler & ScoutSuite (when an AWS/Azure account is ready)

This project scans **Infrastructure-as-Code** statically with Checkov (no account needed).
To scan a *live* account, use Prowler and/or ScoutSuite with **read-only** credentials.

## Safety
- Create a dedicated IAM user/role with AWS-managed **`SecurityAudit`** + **`ViewOnlyAccess`** —
  read-only, no changes possible.
- Use the **Free** AWS account plan (auto-closes, no surprise billing).
- Never commit credentials. Prefer SSO / temporary creds.

## Prowler (CIS / multi-framework)
```bash
pip install prowler
prowler aws --profile audit -M html csv          # full assessment, html+csv reports
prowler aws --list-checks                         # offline: see all checks
prowler aws -c s3_bucket_public_access            # run one check
```

## ScoutSuite (multi-cloud posture)
```bash
pip install scoutsuite
scout aws --profile audit                          # generates an HTML report
scout azure --cli                                  # uses az login session
```

## Lab loop (matches this repo's IaC demo)
1. Apply the **insecure** Terraform into the sandbox account.
2. Run Prowler/ScoutSuite → screenshot the failed findings.
3. Apply the **secure** Terraform (or remediate in-console).
4. Re-scan → screenshot the now-passing controls (the before/after is the deliverable).

> Until the account exists, the Checkov IaC scan in this repo already proves the same
> detect-and-remediate workflow against the same misconfigurations.
