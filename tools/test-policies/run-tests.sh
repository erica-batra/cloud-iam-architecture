#!/bin/bash
# Test runner for IAM Policy Analyzer
# Runs the analyzer against all test policies to demonstrate it works

echo "=========================================="
echo "IAM Policy Analyzer - Test Suite"
echo "=========================================="
echo ""

# Navigate to parent directory
cd "$(dirname "$0")/.."

echo "📋 Testing Bad Policies (Should Find Issues)"
echo "=========================================="
echo ""

echo "🔴 Test 1: Admin Wildcard Policy"
python3 policy-analyzer.py test-policies/1-admin-wildcard.json
echo ""

echo "🔴 Test 2: Privilege Escalation"
python3 policy-analyzer.py test-policies/2-privilege-escalation.json
echo ""

echo "🔴 Test 3: PassRole Unrestricted"
python3 policy-analyzer.py test-policies/3-passrole-unrestricted.json
echo ""

echo "🔴 Test 4: Loose Trust Policy"
python3 policy-analyzer.py test-policies/4-loose-trust-policy.json
echo ""

echo "🔴 Test 5: Public Trust Policy"
python3 policy-analyzer.py test-policies/5-public-trust-policy.json
echo ""

echo "🔴 Test 6: Dangerous S3 Permissions"
python3 policy-analyzer.py test-policies/6-dangerous-s3-permissions.json
echo ""

echo "=========================================="
echo "📋 Testing Good Policies (Should Pass)"
echo "=========================================="
echo ""

echo "✅ Test 7: S3 Read-Only (Well-Scoped)"
python3 policy-analyzer.py test-policies/good-1-s3-read-only.json
echo ""

echo "✅ Test 8: EC2 Read-Only"
python3 policy-analyzer.py test-policies/good-2-ec2-read-only.json
echo ""

echo "✅ Test 9: PassRole with Restrictions"
python3 policy-analyzer.py test-policies/good-3-passrole-restricted.json
echo ""

echo "✅ Test 10: MFA-Protected Policy"
python3 policy-analyzer.py test-policies/good-4-mfa-protected.json
echo ""

echo "✅ Test 11: Trust Policy with ExternalId"
python3 policy-analyzer.py test-policies/good-5-trust-with-externalid.json
echo ""

echo "=========================================="
echo "📊 Batch Test: Scan All Policies"
echo "=========================================="
echo ""
python3 policy-analyzer.py test-policies/
echo ""

echo "=========================================="
echo "✅ All tests complete!"
echo "=========================================="
