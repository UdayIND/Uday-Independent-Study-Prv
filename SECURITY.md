# Security Policy

## Defensive-Only Policy

This project is designed for **defensive cybersecurity operations only**. All detection capabilities and recommendations are intended to help security teams identify and respond to threats in their own networks.

### Permitted Uses

- Analyzing network traffic from your own organization
- Detecting threats in authorized security research environments
- Training security analysts on threat detection techniques
- Improving SOC capabilities and incident response workflows

### Prohibited Uses

- Using this tool to attack or probe networks without authorization
- Any offensive security operations or penetration testing without explicit authorization
- Using detection techniques for malicious purposes

## Defensive Recommendations Only

All recommendations in case reports are defensive:
- Network monitoring and log review
- Endpoint investigation
- DNS analysis and domain blocking
- Documentation and escalation

**No offensive actions** are recommended by this tool.

## Data Handling

- **PCAP files**: Never commit to version control (gitignored). Store securely.
- **Log files**: Stored locally in `data/derived/` (gitignored). Clean up per policy.
- **Reports**: May contain IP addresses. Review before sharing externally.

## Responsible Disclosure

If you discover a security vulnerability:
1. Do not create a public GitHub issue
2. Contact the project maintainer directly
3. Allow reasonable time for remediation

## Compliance

Ensure your use complies with:
- Your organization's security policies
- Applicable laws and regulations
- Network monitoring authorizations
- Data privacy requirements (GDPR, CCPA, etc.)

---

**Remember**: This tool is for defenders, not attackers. Use responsibly and ethically.
