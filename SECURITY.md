# Security Policy

## 🔒 Security Guidelines

This project is designed for **defensive cybersecurity operations only**. All detection capabilities, recommendations, and outputs are intended to help security teams identify and respond to threats in their own networks.

## ⚠️ Defensive-Only Policy

### Permitted Uses

- ✅ Analyzing network traffic from your own organization
- ✅ Detecting threats in authorized security research environments
- ✅ Training security analysts on threat detection techniques
- ✅ Improving SOC capabilities and incident response workflows

### Prohibited Uses

- ❌ Using this tool to attack or probe networks without authorization
- ❌ Reverse engineering or bypassing security controls
- ❌ Any offensive security operations or penetration testing without explicit authorization
- ❌ Using detection techniques for malicious purposes

## 🛡️ Defensive Recommendations Only

All recommendations in case reports are **defensive in nature**:

1. **Network Monitoring**: Monitor traffic patterns, review firewall logs
2. **Endpoint Investigation**: Check endpoint logs, review system activity
3. **DNS Analysis**: Review DNS query patterns, consider domain blocking
4. **Documentation**: Document findings, escalate to senior analysts

**No offensive actions** (e.g., active countermeasures, network disruption) are recommended by this tool.

## 🔐 Data Handling

### PCAP Files

- PCAP files contain sensitive network data
- **Never commit PCAP files to version control** (they are gitignored)
- Store PCAP files securely with appropriate access controls
- Follow your organization's data retention policies

### Log Files

- Zeek and Suricata logs may contain sensitive information
- Log files are stored locally in `data/derived/` (gitignored)
- Clean up log files after analysis if required by policy

### Reports

- Case reports may contain IP addresses and network metadata
- Review reports before sharing externally
- Redact sensitive information if needed

## 🔍 Responsible Disclosure

If you discover a security vulnerability in this project:

1. **Do not** create a public GitHub issue
2. Contact the project maintainer directly
3. Provide details of the vulnerability
4. Allow reasonable time for remediation before public disclosure

## 📋 Compliance

This tool is designed to support:

- **SOC Operations**: Security operations center workflows
- **Incident Response**: Threat detection and investigation
- **Compliance**: Logging and audit requirements

Ensure your use of this tool complies with:

- Your organization's security policies
- Applicable laws and regulations
- Network monitoring authorizations
- Data privacy requirements (GDPR, CCPA, etc.)

## 🚨 Incident Response

If you detect a security incident using this tool:

1. **Document**: Record all findings in your incident tracking system
2. **Isolate**: Follow your organization's containment procedures
3. **Escalate**: Notify appropriate security personnel
4. **Preserve**: Maintain evidence for forensic analysis
5. **Remediate**: Follow your organization's remediation procedures

## 📚 Security Best Practices

### For Analysts

- Always verify detections with additional evidence
- Review false positive rates and tune thresholds accordingly
- Keep detection rules and configurations up to date
- Document investigation steps and findings

### For Administrators

- Restrict access to PCAP files and analysis results
- Monitor tool usage and audit logs
- Keep dependencies updated (check `pyproject.toml`)
- Review and approve configuration changes

### For Developers

- Follow secure coding practices
- Validate all inputs (PCAP files, configurations)
- Use parameterized queries if adding database support
- Keep dependencies updated and scan for vulnerabilities

## 🔗 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Controls](https://www.cisecurity.org/controls/)

## 📞 Contact

For security concerns, contact the project maintainer.

---

**Remember**: This tool is a force multiplier for defenders, not attackers. Use responsibly and ethically.
