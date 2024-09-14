# IAM Security Tools

Working security tools for analyzing IAM policies and configurations.

## Tools

### policy-analyzer.py

**What it does**: Scans IAM policies for security issues like wildcards, dangerous permissions, and overly broad access.

**Quick start**:
```bash
# Analyze a single policy
python policy-analyzer.py my-policy.json

# Scan a directory of policies
python policy-analyzer.py ./policies/

# Example policy to test with
echo '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
  }]
}' > test-policy.json

python policy-analyzer.py test-policy.json
```

**What it checks**:
- Admin wildcards (`Action: *`, `Resource: *`)
- Privilege escalation permissions without conditions
- iam:PassRole without restrictions
- Trust policies that are too permissive
- Dangerous actions on all resources

**Exit codes**:
- 0: No issues
- 1: High severity issues found
- 2: Critical issues found

Use in CI/CD to automatically reject bad policies.

---

## Requirements

```bash
# No external dependencies - uses Python standard library only
# Tested with Python 3.8+
```

---

## Examples

### Example 1: Catch Admin Wildcards

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
  }]
}
```

**Output**:
```
🔴 CRITICAL
Issue: Statement 0: Grants admin access (Action: *, Resource: *)
Fix: Narrow this down. Specify actual actions and resources needed.
```

### Example 2: Catch Privilege Escalation

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "iam:PutUserPolicy",
    "Resource": "*"
  }]
}
```

**Output**:
```
🟠 HIGH
Issue: Allows privilege escalation without conditions
Fix: Add conditions (like MFA requirement, IP restrictions, or permission boundaries).
```

---

## Integration with CI/CD

```yaml
# GitHub Actions example
- name: Check IAM Policies
  run: |
    python tools/policy-analyzer.py terraform/iam-policies/
    # Script exits with non-zero if issues found
```

---

Built because I got tired of reviewing IAM policies manually and missing stuff.
