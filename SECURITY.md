# Security Policy

## Responsible Disclosure

If you discover a security vulnerability in ThreatFade, please report it **privately** to:

📧 **security@tinlance.com** (placeholder – adjust as needed)

**Please do not** open public GitHub issues for security vulnerabilities.

Include:
- Description of vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if applicable)

We will acknowledge receipt within 24 hours and provide updates on our investigation.

## Security Best Practices

### For Users

1. **Keep Updated:** Always run the latest version
   ```bash
   git pull origin main
   pip install -r requirements.txt
   ```

2. **Protect Secrets:**
   - Use `.env` file for Telegram tokens (never commit)
   - Rotate bot tokens regularly
   - Never share chat IDs publicly

3. **Safe Configuration:**
   - Review `config.yaml` before running
   - Restrict file permissions: `chmod 600 config.yaml`
   - Use environment variables for sensitive data

4. **Validate Data:**
   - Only analyze data from trusted sources
   - Verify file integrity before processing
   - Monitor resource usage on large datasets

### For Developers

1. **Code Review:**
   - All PRs require review before merge
   - Security tests run in CI/CD
   - Use `bandit` for vulnerability scanning

2. **Dependencies:**
   - Pin versions in `requirements.txt`
   - Regular `pip-audit` checks
   - Monitor CVE databases

3. **Secrets Management:**
   - Never hardcode tokens or keys
   - Use environment variables (`os.getenv()`)
   - Add to `.gitignore` before committing

4. **Input Validation:**
   - Validate file paths and inputs
   - Sanitize external data
   - Handle errors gracefully

## Known Security Considerations

### Current MVP (1.0.0-beta)

- ✅ No hardcoded secrets
- ✅ No external cloud dependencies
- ✅ Offline-first design
- ⚠️ Telegram bot token must be protected by user
- ⚠️ File system access required (local reports)
- ⚠️ No authentication (intended for research/solo use)

### Future (Q2+)

- Multi-user authentication
- Encrypted data at rest
- TLS for network communication
- Rate limiting for API
- Audit logging

## Vulnerability Tracking

We track security issues in private until resolution, then publish:
- Post-mortem in security advisory
- CVE request (if applicable)
- Patch release with fix

## Security Update Schedule

- **Critical:** Patched within 24-48 hours
- **High:** Patched within 1 week
- **Medium:** Patched with next release
- **Low:** Monitored for next major version

## Contact

- **Security:** security@tinlance.com
- **GitHub Issues:** For non-security bugs only
- **PGP Key:** (if applicable, add signing key)

---

**Built with security in mind by Tinlance Limited**  
© 2026 Tinlance Limited
