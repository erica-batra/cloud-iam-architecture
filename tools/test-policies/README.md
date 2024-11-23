# IAM Policy Test Cases

Test policies to demonstrate the IAM Policy Analyzer tool.

## Quick Start

```bash
# Run all tests (bash)
cd cloud-iam-architecture/tools/test-policies
chmod +x run-tests.sh
./run-tests.sh

# Run all tests (PowerShell)
cd cloud-iam-architecture\tools\test-policies
.\run-tests.ps1

# Test individual policy
cd ..
python policy-analyzer.py test-policies/1-admin-wildcard.json
```

---

## Test Policies Overview

### Bad Policies (Should Trigger Findings)

#### 1. Admin Wildcard (`1-admin-wildcard.json`)
**What it is**: The worst IAM policy possible  
**Issue**: `Action: *` on `Resource: *` = admin access to everything  
**Expected Finding**: CRITICAL - Grants admin access

```json
{
  "Action": "*",
  "Resource": "*"
}
```

**Why this is bad**: One compromised credential = full account access

---

#### 2. Privilege Escalation (`2-privilege-escalation.json`)
**What it is**: Multiple privilege escalation techniques  
**Issues**: 
- `iam:PutUserPolicy` = can attach policy to self
- `iam:AttachUserPolicy` = can attach AdministratorAccess  
- `iam:CreateAccessKey` = can create keys for other users

**Expected Finding**: HIGH - Allows privilege escalation without conditions

**Why this is bad**: User can grant themselves any permissions

---

#### 3. PassRole Unrestricted (`3-passrole-unrestricted.json`)
**What it is**: PassRole with Lambda permissions  
**Issue**: Can pass admin roles to Lambda functions they create

**Expected Finding**: HIGH - PassRole allowed on all roles

**Attack scenario**:
```bash
# Create Lambda with admin role
aws lambda create-function \
  --function-name backdoor \
  --role arn:aws:iam::123456789012:role/AdminRole \
  --runtime python3.9 \
  --handler index.handler \
  --zip-file fileb://malicious.zip

# Execute with admin permissions
aws lambda invoke --function-name backdoor output.txt
```

---

#### 4. Loose Trust Policy (`4-loose-trust-policy.json`)
**What it is**: Trust policy allowing entire AWS account  
**Issue**: Principal is `:root` instead of specific role ARN

**Expected Finding**: MEDIUM - Trust policy allows entire AWS account

**Why this is bad**: ANY principal in that account can assume this role

---

#### 5. Public Trust Policy (`5-public-trust-policy.json`)
**What it is**: Trust policy with wildcard principal  
**Issue**: Principal is `*` = anyone with an AWS account

**Expected Finding**: CRITICAL - Trust policy allows ANY AWS principal

**Why this is bad**: Literally anyone can assume this role

---

#### 6. Dangerous S3 Permissions (`6-dangerous-s3-permissions.json`)
**What it is**: S3 admin on all buckets  
**Issue**: `s3:*` on all resources

**Expected Finding**: HIGH - Broad permissions on all resources

**Why this is bad**: Can delete any S3 bucket, exfiltrate any data

---

### Good Policies (Should Pass or Minimal Issues)

#### 7. S3 Read-Only (`good-1-s3-read-only.json`)
**What it is**: Properly scoped S3 read access  
**Why it's good**:
- Specific actions (GetObject, ListBucket)
- Specific resource (one bucket)
- Read-only (can't modify or delete)

**Expected**: ✅ No issues found

---

#### 8. EC2 Read-Only (`good-2-ec2-read-only.json`)
**What it is**: EC2 describe/get permissions  
**Why it's good**:
- Read-only actions only
- Useful for monitoring/dashboards
- Can't launch instances or modify config

**Expected**: ✅ No issues found

**Note**: Resource wildcard is acceptable for read-only Describe actions

---

#### 9. PassRole with Restrictions (`good-3-passrole-restricted.json`)
**What it is**: PassRole properly scoped  
**Why it's good**:
- Specific role ARN (not wildcard)
- Condition: only pass to Lambda service
- Lambda actions scoped to specific function prefix

**Expected**: ✅ No issues found

**This is how PassRole should be done**

---

#### 10. MFA-Protected (`good-4-mfa-protected.json`)
**What it is**: Sensitive action requiring MFA  
**Why it's good**:
- CreateAccessKey gated by MFA
- Self-service (users can only create keys for themselves)
- Reduces impact of compromised passwords

**Expected**: ✅ No issues found

---

#### 11. Trust Policy with ExternalId (`good-5-trust-with-externalid.json`)
**What it is**: Cross-account trust with external ID  
**Why it's good**:
- Specific principal (not :root or wildcard)
- ExternalId prevents confused deputy attack
- Standard pattern for third-party integrations

**Expected**: ✅ No issues found

---

## Test Results Summary

| Policy | Expected Severity | Key Finding |
|--------|------------------|-------------|
| 1-admin-wildcard | CRITICAL | Admin wildcard |
| 2-privilege-escalation | HIGH | Multiple escalation techniques |
| 3-passrole-unrestricted | HIGH | PassRole on all roles |
| 4-loose-trust-policy | MEDIUM | Trust :root without conditions |
| 5-public-trust-policy | CRITICAL | Trust wildcard principal |
| 6-dangerous-s3-permissions | HIGH | s3:* on all resources |
| good-1-s3-read-only | PASS | ✅ Well-scoped |
| good-2-ec2-read-only | PASS | ✅ Read-only |
| good-3-passrole-restricted | PASS | ✅ Properly restricted |
| good-4-mfa-protected | PASS | ✅ MFA required |
| good-5-trust-with-externalid | PASS | ✅ ExternalId present |

---

## Running Tests

### Individual Test
```bash
python policy-analyzer.py test-policies/1-admin-wildcard.json
```

### Scan All Policies
```bash
python policy-analyzer.py test-policies/
```

### Use in CI/CD
```yaml
# GitHub Actions
- name: Check IAM Policies
  run: |
    python tools/policy-analyzer.py terraform/policies/
    # Exits non-zero if critical/high findings
```

---

## Creating Your Own Test Policies

### Template for Bad Policy
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "dangerous:Action",
    "Resource": "*"
  }]
}
```

### Template for Good Policy
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "safe:Action",
    "Resource": "arn:aws:service:region:account:resource/specific",
    "Condition": {
      "StringEquals": {
        "key": "value"
      }
    }
  }]
}
```

---

## What These Tests Demonstrate

1. **Tool Accuracy**: Catches real security issues
2. **False Positive Rate**: Minimal - good policies pass
3. **Actionable Output**: Clear findings with remediation steps
4. **Edge Cases**: Handles conditions, trust policies, combinations
5. **Production Ready**: Can be used in actual security reviews

---

Built to show the tool actually works, not just in theory.
