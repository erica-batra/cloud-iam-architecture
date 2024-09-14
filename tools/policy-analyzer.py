#!/usr/bin/env python3
"""
IAM Policy Analyzer - Find overly permissive policies before they become a problem

This tool parses IAM policies and flags potential security issues like:
- Wildcard permissions that are way too broad
- Missing conditions on sensitive actions
- Trust policies that trust basically everyone
- Policies that allow privilege escalation

I built this after seeing too many policies with "Action": "*" on "Resource": "*"
and wondering "how did this even get approved?"
"""

import json
import sys
from typing import Dict, List, Tuple
from pathlib import Path


class PolicyAnalyzer:
    """
    Analyzes IAM policies for security issues.
    
    Started simple (just check for wildcards) but grew as I found more issues
    in production policies that should've been caught earlier.
    """
    
    # These actions are powerful - if you see them with wildcards, that's usually bad
    PRIVILEGE_ESCALATION_ACTIONS = [
        'iam:PutUserPolicy',
        'iam:PutRolePolicy',
        'iam:AttachUserPolicy',
        'iam:AttachRolePolicy',
        'iam:CreateAccessKey',
        'iam:CreateLoginProfile',
        'iam:UpdateAssumeRolePolicy',
        'iam:PassRole',
        'sts:AssumeRole',
        'lambda:CreateFunction',
        'lambda:UpdateFunctionCode',
        'ec2:RunInstances',
        'cloudformation:CreateStack',
    ]
    
    # If these are allowed on all resources without conditions, you're gonna have a bad time
    DANGEROUS_ACTIONS = [
        'iam:*',
        's3:*',
        'ec2:*',
        '*:*',
        'lambda:InvokeFunction',
        'dynamodb:*',
        'rds:*',
    ]
    
    def __init__(self):
        self.findings = []
        self.policy_name = ""
    
    def analyze_policy(self, policy: Dict, policy_name: str = "Unknown") -> List[Dict]:
        """
        Main analysis entry point. Feed it an IAM policy document, get back findings.
        
        Args:
            policy: IAM policy document (the JSON parsed into a dict)
            policy_name: What to call this policy in the results
            
        Returns:
            List of findings (dicts with severity, issue, and recommendation)
        """
        self.policy_name = policy_name
        self.findings = []
        
        # Check if it's even a valid policy structure
        if 'Statement' not in policy:
            self.findings.append({
                'severity': 'ERROR',
                'issue': 'Not a valid IAM policy - missing Statement element',
                'recommendation': 'Check the policy format. Should have "Version" and "Statement".'
            })
            return self.findings
        
        statements = policy.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]  # Sometimes it's just one statement, not a list
        
        for idx, statement in enumerate(statements):
            self._analyze_statement(statement, idx)
        
        return self.findings
    
    def _analyze_statement(self, statement: Dict, statement_idx: int):
        """
        Analyze a single policy statement.
        
        Each statement can have different issues, so we check them all:
        - Is Effect "Allow" with wildcards? (common problem)
        - Are there dangerous actions without conditions?
        - Is the resource wildcard when it shouldn't be?
        """
        effect = statement.get('Effect', 'Deny')
        
        # Only care about Allow statements for now (Deny wildcards are actually fine)
        if effect != 'Allow':
            return
        
        actions = self._get_actions(statement)
        resources = self._get_resources(statement)
        conditions = statement.get('Condition', {})
        principal = statement.get('Principal', {})
        
        # Check 1: The dreaded "Action": "*" on "Resource": "*"
        if '*' in actions and '*' in resources:
            self.findings.append({
                'severity': 'CRITICAL',
                'issue': f'Statement {statement_idx}: Grants admin access (Action: *, Resource: *)',
                'recommendation': 'Narrow this down. Specify actual actions and resources needed. '
                                'This is essentially giving away the keys to everything.'
            })
            return  # No point checking more, this is already terrible
        
        # Check 2: Privilege escalation actions without restrictions
        escalation_actions = [a for a in actions if a in self.PRIVILEGE_ESCALATION_ACTIONS or a == '*']
        if escalation_actions and not conditions:
            self.findings.append({
                'severity': 'HIGH',
                'issue': f'Statement {statement_idx}: Allows privilege escalation without conditions',
                'actions': escalation_actions,
                'recommendation': 'Add conditions (like MFA requirement, IP restrictions, or permission boundaries). '
                                'These actions let users give themselves more permissions.'
            })
        
        # Check 3: Dangerous actions on all resources
        dangerous = [a for a in actions if a in self.DANGEROUS_ACTIONS]
        if dangerous and ('*' in resources or not resources):
            self.findings.append({
                'severity': 'HIGH',
                'issue': f'Statement {statement_idx}: Broad permissions on all resources',
                'actions': dangerous,
                'recommendation': f'Limit to specific resources. For example, if this is for S3, '
                                f'specify the bucket ARN instead of using "*".'
            })
        
        # Check 4: PassRole without restrictions (confused deputy attack vector)
        if 'iam:PassRole' in actions or '*' in actions:
            if '*' in resources:
                self.findings.append({
                    'severity': 'HIGH',
                    'issue': f'Statement {statement_idx}: iam:PassRole allowed on all roles',
                    'recommendation': 'Restrict PassRole to specific roles. Attackers can use this to '
                                    'escalate privileges by passing admin roles to services they control.'
                })
        
        # Check 5: Trust policies that trust too much
        if principal:
            self._check_trust_policy(principal, statement_idx, conditions)
    
    def _check_trust_policy(self, principal: Dict, statement_idx: int, conditions: Dict):
        """
        Check if trust policy is too permissive.
        
        Common issue: Trusting the entire AWS account (:root) instead of specific roles.
        """
        aws_principals = principal.get('AWS', [])
        if isinstance(aws_principals, str):
            aws_principals = [aws_principals]
        
        for p in aws_principals:
            # Trusting :root means ANY principal in that account can assume this role
            if ':root' in p and not conditions:
                self.findings.append({
                    'severity': 'MEDIUM',
                    'issue': f'Statement {statement_idx}: Trust policy allows entire AWS account',
                    'principal': p,
                    'recommendation': 'Specify exact role/user ARNs instead of :root. '
                                    'Or add conditions like ExternalId or MFA requirement.'
                })
            
            # Wildcard principals are usually a mistake
            if p == '*' and not conditions:
                self.findings.append({
                    'severity': 'CRITICAL',
                    'issue': f'Statement {statement_idx}: Trust policy allows ANY AWS principal',
                    'recommendation': 'This allows anyone with an AWS account to assume this role. '
                                    'Almost certainly not what you want. Specify actual principals.'
                })
    
    def _get_actions(self, statement: Dict) -> List[str]:
        """Extract actions from statement (handle both single string and list)."""
        actions = statement.get('Action', statement.get('NotAction', []))
        if isinstance(actions, str):
            return [actions]
        return list(actions)
    
    def _get_resources(self, statement: Dict) -> List[str]:
        """Extract resources from statement (handle both single string and list)."""
        resources = statement.get('Resource', statement.get('NotResource', []))
        if isinstance(resources, str):
            return [resources]
        return list(resources)
    
    def print_findings(self):
        """
        Print findings in a human-readable format.
        
        Color-coded by severity (if terminal supports it) because it's easier to scan.
        """
        if not self.findings:
            print(f"✅ {self.policy_name}: No issues found!")
            return
        
        # Count by severity for summary
        severity_counts = {}
        for finding in self.findings:
            sev = finding['severity']
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        print(f"\n📋 Policy: {self.policy_name}")
        print(f"🔍 Found {len(self.findings)} issue(s)")
        
        for sev, count in severity_counts.items():
            print(f"   {sev}: {count}")
        
        print("\n" + "="*80)
        
        for finding in self.findings:
            severity = finding['severity']
            
            # Simple color coding (works on most terminals)
            if severity == 'CRITICAL':
                prefix = '🔴 CRITICAL'
            elif severity == 'HIGH':
                prefix = '🟠 HIGH'
            elif severity == 'MEDIUM':
                prefix = '🟡 MEDIUM'
            else:
                prefix = '⚪ LOW'
            
            print(f"\n{prefix}")
            print(f"Issue: {finding['issue']}")
            
            if 'actions' in finding:
                print(f"Actions: {', '.join(finding['actions'])}")
            
            if 'principal' in finding:
                print(f"Principal: {finding['principal']}")
            
            print(f"Fix: {finding['recommendation']}")
            print("-" * 80)


def analyze_file(file_path: str) -> Tuple[bool, List[Dict]]:
    """
    Analyze a policy from a JSON file.
    
    Returns:
        (success: bool, findings: List[Dict])
    """
    try:
        with open(file_path, 'r') as f:
            policy = json.load(f)
        
        analyzer = PolicyAnalyzer()
        findings = analyzer.analyze_policy(policy, Path(file_path).name)
        analyzer.print_findings()
        
        return True, findings
    
    except json.JSONDecodeError as e:
        print(f"❌ Error: Invalid JSON in {file_path}")
        print(f"   {str(e)}")
        return False, []
    
    except FileNotFoundError:
        print(f"❌ Error: File not found: {file_path}")
        return False, []
    
    except Exception as e:
        print(f"❌ Error analyzing {file_path}: {str(e)}")
        return False, []


def main():
    """
    Main entry point. Can analyze one policy or scan a directory.
    
    Usage:
        python policy-analyzer.py policy.json
        python policy-analyzer.py /path/to/policies/
    """
    if len(sys.argv) < 2:
        print("IAM Policy Analyzer")
        print("\nUsage:")
        print("  python policy-analyzer.py <policy-file.json>")
        print("  python policy-analyzer.py <directory>")
        print("\nExamples:")
        print("  python policy-analyzer.py my-policy.json")
        print("  python policy-analyzer.py ./policies/")
        sys.exit(1)
    
    target = sys.argv[1]
    path = Path(target)
    
    if path.is_file():
        # Single file
        success, findings = analyze_file(str(path))
        
        # Exit code based on findings
        if not success:
            sys.exit(2)
        
        critical = sum(1 for f in findings if f['severity'] == 'CRITICAL')
        high = sum(1 for f in findings if f['severity'] == 'HIGH')
        
        if critical > 0:
            sys.exit(2)  # Critical findings
        elif high > 0:
            sys.exit(1)  # High findings
        else:
            sys.exit(0)  # All good
    
    elif path.is_dir():
        # Directory - scan all JSON files
        print(f"🔍 Scanning directory: {path}\n")
        
        json_files = list(path.glob("**/*.json"))
        
        if not json_files:
            print(f"No JSON files found in {path}")
            sys.exit(1)
        
        print(f"Found {len(json_files)} JSON file(s)\n")
        
        total_findings = []
        for json_file in json_files:
            success, findings = analyze_file(str(json_file))
            total_findings.extend(findings)
        
        # Summary
        print(f"\n{'='*80}")
        print(f"📊 Summary: Analyzed {len(json_files)} policy file(s)")
        print(f"   Total findings: {len(total_findings)}")
        
        if total_findings:
            severity_counts = {}
            for finding in total_findings:
                sev = finding['severity']
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                if sev in severity_counts:
                    print(f"   {sev}: {severity_counts[sev]}")
        
        # Exit based on severity
        critical = sum(1 for f in total_findings if f['severity'] == 'CRITICAL')
        high = sum(1 for f in total_findings if f['severity'] == 'HIGH')
        
        if critical > 0:
            sys.exit(2)
        elif high > 0:
            sys.exit(1)
    
    else:
        print(f"❌ Error: {target} is not a file or directory")
        sys.exit(1)


if __name__ == '__main__':
    main()
