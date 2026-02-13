# openclaw-skillscan

Static security analysis for [ClawHub](https://clawhub.com) skills before you install them into [OpenClaw](https://docs.openclaw.ai).

## Why this exists

ClawHub is a growing marketplace, but supply-chain attacks are already happening. Malicious skills have been caught doing credential theft, config tampering, and social engineering through documentation. [CVE-2026-25253](https://nvd.nist.gov/) (1-click RCE, patched in v2026.1.29) showed that OpenClaw's attack surface is real.

This scanner catches the most common attack patterns before a skill ever touches your agent.

## What it scans

**Code files** (`.js`, `.ts`, `.py`, `.sh`, `.mjs`, `.cjs`, `.jsx`, `.tsx`):
- Dynamic execution (`eval`, `exec`, `Function()`, `subprocess.call`)
- Destructive operations (`rm -rf`, `rimraf`, `rmtree`)
- Obfuscation & encoding (`atob`, `b64decode`, `Buffer.from`)
- Credential theft (`ssh-keygen`, `id_rsa`, `authorized_keys`)
- Config tampering (writes to `SOUL.md`, `MEMORY.md`, `openclaw.json`, etc.)
- Undeclared network calls (domain enforcement against `SKILL.md` declarations)

**Documentation files** (`.md`, `.txt`, `README`):
- Social engineering vectors (`curl | bash`, `wget | sh`, PowerShell encoded commands)
- Obfuscated one-liners (`eval $(`, `base64 -d`)

## Scoring

| Tier | Score | Action |
|------|-------|--------|
| A | 90-140 | Safe to install |
| B | 60-89 | Manual review recommended |
| C | 1-59 | Deep review required |
| D | 0 | Do NOT install (blocker found) |

**Base score**: 100 points, with deductions for warnings (-20 each, max -60) and instant zero for blockers.

**Bonus points** (up to +40): Official OpenClaw org (+10), VirusTotal clean (+10), GitHub stars (+5/+10), recent commits (+5).

## Quick start

```bash
# Clone this repo
git clone https://github.com/Jibberdaffle12/openclaw-skillscan.git
cd openclaw-skillscan

# Make executable
chmod +x skill_scan.sh

# Scan a skill directory
./skill_scan.sh /path/to/quarantined/skill-name

# With optional trust signals
VT_CLEAN=true STAR_COUNT=250 ./skill_scan.sh /path/to/skill
```

## Output

```
===============================
SKILL:    example-skill
SCORE:    85 / 100
TIER:     B (pending-review)
HASH:     a3f2b1c
FINDINGS: WARNING: 'puppeteer'
===============================

Audit log: ./skill_audit_log.csv
[REVIEW] Skill has minor warnings. Manual review recommended before install.
```

Results are appended to a CSV audit log for tracking.

## Domain enforcement

If a skill's `SKILL.md` declares domains it connects to, the scanner verifies that code only contacts those domains. Undeclared outbound connections are an automatic blocker. Localhost/loopback addresses are always exempt.

Subdomain matching: declaring `example.com` permits `api.example.com`.

## Integration ideas

- Run as a pre-install hook in your OpenClaw workspace
- Add to CI/CD for skill repos
- Feed audit CSV into a dashboard for fleet-wide visibility
- Pair with a Watcher agent for runtime monitoring

## Known limitations

- Static analysis only (runtime behavior may differ)
- GitHub API integration for star counts is via env var (not automated)
- VirusTotal check is manual (set `VT_CLEAN=true` after verifying)
- Pattern list needs periodic updates as attack vectors evolve

## Contributing

PRs welcome. If you find a pattern that should be added to the blocker or warning lists, open an issue with evidence.

## License

MIT - see [LICENSE](LICENSE)
