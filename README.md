# Cloud IAM Architecture

**Identity & Access Management** • Design Patterns • Security Implications

## What This Is

This is me trying to make sense of cloud IAM—how it works, how it breaks, and how to design it so you're not giving everyone admin access "just in case." I've spent way too much time debugging IAM issues and realized there are patterns that keep showing up. This repo is those patterns, along with what can go wrong and how to actually detect it.

### DevOps → Security Perspective

When I was doing DevOps, IAM was this annoying thing you had to deal with to make services talk to each other. Now that I'm focused on security, I realize it's actually the foundation of everything—if you get IAM wrong, all your other security controls don't matter much.

This repo is basically: here's what I learned about IAM after years of fighting with it, now with a security focus instead of just "make it work."

## What I'm Trying to Do Here

1. Document IAM patterns that actually work in production (not just in blog posts)
2. Figure out how attackers abuse IAM—privilege escalation paths, credential theft, the usual
3. Design IAM setups that don't make lateral movement easy
4. Build policies that give services what they need and nothing more (harder than it sounds)
5. Translate "we need to deploy things quickly" into "here's how to do that securely"

## 📚 Contents

### Core IAM Concepts
- [`01-iam-fundamentals/`](./01-iam-fundamentals/) - IAM building blocks and security implications
- [`02-identity-types/`](./02-identity-types/) - Human vs service identities and separation patterns
- [`03-permission-boundaries/`](./03-permission-boundaries/) - Using boundaries to limit blast radius

### Architecture Patterns
- [`04-cross-account-access/`](./04-cross-account-access/) - Secure patterns for multi-account access
- [`05-identity-federation/`](./05-identity-federation/) - SAML, OIDC, AWS SSO patterns and risks
- [`06-service-roles/`](./06-service-roles/) - Service identity design and trust relationships
- [`07-least-privilege-design/`](./07-least-privilege-design/) - Building minimal permission policies

### Security Analysis
- [`08-privilege-escalation/`](./08-privilege-escalation/) - IAM privilege escalation paths and mitigations
- [`09-attack-scenarios/`](./09-attack-scenarios/) - Real-world IAM attack patterns
- [`10-detection-strategies/`](./10-detection-strategies/) - Monitoring and detecting IAM abuse

### Practical Implementation
- [`11-policy-examples/`](./11-policy-examples/) - Production-ready IAM policy templates
- [`12-terraform-modules/`](./12-terraform-modules/) - IaC for secure IAM deployment
- [`13-audit-tools/`](./13-audit-tools/) - Scripts for IAM security auditing

## Core Principles (That Actually Matter)

### 1. Least Privilege (For Real Though)
**The Idea**: Only give the permissions actually needed. Not "probably needed" or "might need someday."

**How**:
- Start by denying everything, then explicitly allow specific things
- Use permission boundaries so even admins can't grant themselves everything
- Actually review permissions regularly (put it on your calendar or it won't happen)
- Use temporary elevated access when you need more (not permanent "just in case" permissions)

**Why**: When (not if) credentials get stolen, you want the attacker to have as few options as possible

### 2. Separation of Duties
**The Idea**: One person/service shouldn't be able to do everything. Split up powerful capabilities.

**How**:
- Split read/write/delete permissions—being able to read doesn't mean you should delete
- Separate access to data from access to the control plane
- Make sensitive stuff require approval from multiple people
- Have a break-glass process for emergencies (that you hopefully never use)

**Why**: Limits damage from compromised accounts or malicious insiders. Also makes it harder to accidentally destroy everything.

### 3. Assume You're Already Hacked
**The Idea**: Design like someone's already got your credentials. Because eventually, someone will.

**How**:
- Use short-lived credentials (15min - 1hr max). Makes stolen creds expire quickly
- MFA for humans, even for internal stuff. Yes, it's annoying. Do it anyway
- Use PrivateLink and VPC endpoints so services don't talk over the public internet
- Log everything in CloudTrail. You'll need those logs when (not if) something goes wrong

**Why**: Limits how long attackers can use stolen credentials and how far they can spread

### 4. Defense in Depth
**Principle**: Multiple layers of access controls.

**Implementation**:
- IAM policies (identity-based + resource-based)
- Service Control Policies (SCPs) at organization level
- Permission boundaries for delegated admin
- VPC security groups and NACLs as network layer

**Security Benefit**: If one control fails, others still protect resources

### 5. Explicit Trust Boundaries
**Principle**: Clearly define and enforce trust boundaries.

**Implementation**:
- Explicit trust relationships in assume role policies
- External ID for third-party access
- Condition keys to restrict access context
- Regular audit of cross-account trust relationships

**Security Benefit**: Prevents unauthorized cross-account or cross-service access

## 🔑 Key IAM Patterns Documented

### Pattern 1: Hub-and-Spoke IAM Federation
Centralized identity provider federating to multiple AWS accounts.

**Use Case**: Organization with 50+ AWS accounts, single identity source  
**Security Focus**: Minimizing credential sprawl, centralizing MFA enforcement  
**Trade-offs**: Single point of failure vs credential complexity  

See: [`05-identity-federation/hub-spoke-pattern.md`](./05-identity-federation/hub-spoke-pattern.md)

### Pattern 2: Service Role Chaining
Services assuming roles to access other services without long-lived credentials.

**Use Case**: Lambda → DynamoDB → S3, each with minimal permissions  
**Security Focus**: No embedded credentials, audit trail of each hop  
**Trade-offs**: Complexity vs security  

See: [`06-service-roles/role-chaining.md`](./06-service-roles/role-chaining.md)

### Pattern 3: Break-Glass Emergency Access
Emergency access pattern with automated alerting and time limits.

**Use Case**: Production incident requires elevated permissions  
**Security Focus**: Temporary access, full audit, automatic revocation  
**Trade-offs**: Security vs operational agility  

See: [`07-least-privilege-design/break-glass-pattern.md`](./07-least-privilege-design/break-glass-pattern.md)

### Pattern 4: Cross-Account Access with Conditions
Secure pattern for multi-account resource access with strong restrictions.

**Use Case**: CI/CD account deploying to production accounts  
**Security Focus**: MFA required, IP restrictions, time-based access  
**Trade-offs**: Operational complexity vs security controls  

See: [`04-cross-account-access/conditional-access.md`](./04-cross-account-access/conditional-access.md)

## Threats & How to Deal With Them

### Threat: Privilege Escalation
**What happens**: Someone with basic permissions figures out how to give themselves admin

**Common ways this happens**:
- They have `iam:PutUserPolicy` and attach an admin policy to themselves (classic)
- They use `iam:PassRole` + `lambda:CreateFunction` to run code as a more privileged role
- They find a role with a loose trust policy and use `sts:AssumeRole` to jump into it

**How to prevent it**:
- Use permission boundaries - they set a ceiling even admins can't break through
- SCPs at the org level to block really dangerous API calls
- Actually monitor CloudTrail for sketchy `iam:*` and `sts:AssumeRole` calls (alerts, not just logs)
- Don't let the same people manage IAM and everything else

More details: [`08-privilege-escalation/escalation-paths.md`](./08-privilege-escalation/escalation-paths.md)

### Threat: Stolen Credentials
**What happens**: Someone gets your AWS access keys and uses them to do bad things

**Common ways this happens**:
- Committed to GitHub (happens more than you'd think)
- Accidentally logged by applications
- Hardcoded in Docker images or Lambda environment variables (please don't do this)

**How to prevent it**:
- Just use IAM roles. Seriously, stop creating access keys if you don't have to
- If you absolutely need keys: short TTL, rotate them often, alert on weird usage patterns
- MFA for anything sensitive
- Use VPC endpoints so traffic stays internal

More details: [`09-attack-scenarios/credential-theft.md`](./09-attack-scenarios/credential-theft.md)

### Threat: Resource-Based Policy Backdoor
**Attack**: Attacker modifies resource policy to grant themselves access  
**Example**: S3 bucket policy allowing `Principal: "*"` with no conditions

**Mitigations**:
- Use SCPs to prevent `s3:PutBucketPolicy` without approval
- Block public access at bucket and account level
- Automated scanning for overly permissive policies
- Least privilege on policy modification permissions

See: [`09-attack-scenarios/resource-policy-abuse.md`](./09-attack-scenarios/resource-policy-abuse.md)

## 🛠️ Practical Tools

### IAM Policy Analyzer (Python)
Analyzes IAM policies for overly broad permissions, missing conditions, and security gaps.

```bash
cd 13-audit-tools
python3 policy-analyzer.py --policy-file policy.json
```

**Output**: Risk score, specific recommendations, policy diff for remediation

### Privilege Escalation Detector
Scans IAM policies for known privilege escalation paths.

```bash
cd 08-privilege-escalation
python3 detect-escalation.py --account-id 123456789012
```

**Output**: List of identities with escalation-capable permissions, remediation steps

### Least Privilege Policy Generator
Generates minimal IAM policies based on CloudTrail access logs.

```bash
cd 07-least-privilege-design
python3 generate-policy.py --cloudtrail-logs logs/ --role-name MyAppRole
```

**Output**: Least privilege policy JSON, comparison with current policy

## 📊 IAM Maturity Model

### Level 1: Basic (Ad-hoc IAM)
- ❌ Shared credentials and root account usage
- ❌ Overly broad policies (`*` permissions)
- ❌ No MFA enforcement
- ❌ Manual access management

### Level 2: Managed (Structured IAM)
- ✅ Individual user accounts with MFA
- ✅ Role-based access control (RBAC)
- ✅ Some policy restrictions
- ⚠️ Still using long-lived credentials for services

### Level 3: Defined (Secure IAM)
- ✅ Federated identity (SSO)
- ✅ Service roles instead of access keys
- ✅ Permission boundaries in use
- ✅ Regular access reviews
- ⚠️ Limited automation and monitoring

### Level 4: Optimized (Security-First IAM)
- ✅ Least privilege enforced automatically
- ✅ Short-lived credentials everywhere
- ✅ Comprehensive CloudTrail monitoring
- ✅ Automated anomaly detection
- ✅ Policy-as-code with CI/CD validation
- ⚠️ May still have some manual processes

### Level 5: Adaptive (Zero Trust IAM)
- ✅ Continuous authentication and authorization
- ✅ Context-aware access decisions
- ✅ Automated response to threats
- ✅ Real-time least privilege adjustment
- ✅ Full visibility and automated compliance

**Current Focus**: Helping teams move from Level 2-3 to Level 4-5

## 🎓 Learning Path

### For DevOps Engineers Transitioning to Security:
1. Start with [`01-iam-fundamentals/`](./01-iam-fundamentals/) - understand IAM building blocks
2. Review [`08-privilege-escalation/`](./08-privilege-escalation/) - see how IAM can be abused
3. Study [`04-cross-account-access/`](./04-cross-account-access/) - you're probably already using this
4. Implement [`07-least-privilege-design/`](./07-least-privilege-design/) - start tightening existing policies
5. Build [`10-detection-strategies/`](./10-detection-strategies/) - monitor what you've built

### For Security Engineers New to Cloud:
1. Start with [`01-iam-fundamentals/`](./01-iam-fundamentals/) - cloud IAM is different
2. Review [`05-identity-federation/`](./05-identity-federation/) - map on-prem identity concepts
3. Study [`09-attack-scenarios/`](./09-attack-scenarios/) - understand cloud-specific threats
4. Implement [`13-audit-tools/`](./13-audit-tools/) - assess current posture
5. Design using [`04-cross-account-access/`](./04-cross-account-access/) - secure multi-account patterns

## Where This Stuff Comes From

I'm pulling from:
- AWS docs (obviously)
- Actual production IAM setups I've worked with
- MITRE ATT&CK Cloud Matrix (great for understanding attack patterns)
- Research from Rhino Security Labs, Datadog Security Labs, others
- Trial and error—lots of "oh, THAT'S how that breaks"

Specific references are in the individual docs.

## Quick Disclaimer

This is security research and documentation. Everything here is:
- Based on real situations but anonymized (not doxxing anyone)
- For learning how to secure things, not break into them
- Should be adapted to your situation—what works for me might not work for you

Don't just copy-paste IAM policies without understanding what they do. That's how you either lock yourself out or give everyone too much access (both bad).

## 🚀 Future Additions

- [ ] Azure AD and GCP IAM comparison
- [ ] Kubernetes RBAC integration with cloud IAM
- [ ] Automated IAM remediation workflows
- [ ] IAM security dashboards and metrics
- [ ] Advanced SCP patterns for org-wide controls
- [ ] Identity threat intelligence integration

## 📬 Contributing

This is a personal research repository, but I welcome:
- Corrections and clarifications
- Additional attack scenarios
- Real-world pattern suggestions
- Tool improvements

Open an issue or reach out: erica.batra@gmail.com

---

**Status**: Active Development  
**Focus**: AWS IAM (primary), Azure AD, GCP IAM  
**Last Updated**: January 2026
