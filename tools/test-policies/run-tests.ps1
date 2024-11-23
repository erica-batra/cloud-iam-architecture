# PowerShell Test Runner for IAM Policy Analyzer
# Windows version of run-tests.sh

Write-Host "=========================================="
Write-Host "IAM Policy Analyzer - Test Suite"
Write-Host "=========================================="
Write-Host ""

# Navigate to parent directory
Set-Location "$PSScriptRoot\.."

Write-Host "📋 Testing Bad Policies (Should Find Issues)" -ForegroundColor Yellow
Write-Host "=========================================="
Write-Host ""

Write-Host "🔴 Test 1: Admin Wildcard Policy" -ForegroundColor Red
python policy-analyzer.py test-policies\1-admin-wildcard.json
Write-Host ""

Write-Host "🔴 Test 2: Privilege Escalation" -ForegroundColor Red
python policy-analyzer.py test-policies\2-privilege-escalation.json
Write-Host ""

Write-Host "🔴 Test 3: PassRole Unrestricted" -ForegroundColor Red
python policy-analyzer.py test-policies\3-passrole-unrestricted.json
Write-Host ""

Write-Host "🔴 Test 4: Loose Trust Policy" -ForegroundColor Red
python policy-analyzer.py test-policies\4-loose-trust-policy.json
Write-Host ""

Write-Host "🔴 Test 5: Public Trust Policy" -ForegroundColor Red
python policy-analyzer.py test-policies\5-public-trust-policy.json
Write-Host ""

Write-Host "🔴 Test 6: Dangerous S3 Permissions" -ForegroundColor Red
python policy-analyzer.py test-policies\6-dangerous-s3-permissions.json
Write-Host ""

Write-Host "==========================================" -ForegroundColor Yellow
Write-Host "📋 Testing Good Policies (Should Pass)" -ForegroundColor Yellow
Write-Host "=========================================="
Write-Host ""

Write-Host "✅ Test 7: S3 Read-Only (Well-Scoped)" -ForegroundColor Green
python policy-analyzer.py test-policies\good-1-s3-read-only.json
Write-Host ""

Write-Host "✅ Test 8: EC2 Read-Only" -ForegroundColor Green
python policy-analyzer.py test-policies\good-2-ec2-read-only.json
Write-Host ""

Write-Host "✅ Test 9: PassRole with Restrictions" -ForegroundColor Green
python policy-analyzer.py test-policies\good-3-passrole-restricted.json
Write-Host ""

Write-Host "✅ Test 10: MFA-Protected Policy" -ForegroundColor Green
python policy-analyzer.py test-policies\good-4-mfa-protected.json
Write-Host ""

Write-Host "✅ Test 11: Trust Policy with ExternalId" -ForegroundColor Green
python policy-analyzer.py test-policies\good-5-trust-with-externalid.json
Write-Host ""

Write-Host "=========================================="
Write-Host "📊 Batch Test: Scan All Policies"
Write-Host "=========================================="
Write-Host ""
python policy-analyzer.py test-policies\
Write-Host ""

Write-Host "=========================================="
Write-Host "✅ All tests complete!" -ForegroundColor Green
Write-Host "=========================================="
