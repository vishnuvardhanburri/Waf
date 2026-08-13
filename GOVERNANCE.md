# Project Governance & Maintainership

PyWAF operates under an **Open Governance model** adhering to OpenSSF Gold Level criteria. We prioritize security, performance, vendor neutrality, and community stewardship.

---

## Governance Roles

### 1. Contributors
Anyone who submits code, documentation, threat rules, or issue reports to PyWAF.
- **Requirements**: DCO sign-off (`git commit -s`), follow Code of Conduct.

### 2. Maintainers
Maintainers manage code reviews, security triage, release management, and core architectural direction.
- **Responsibilities**:
  - Review PRs (minimum 1 approval required).
  - Enforce test suite pass (>90% coverage) and security scanning.
  - Maintain security vulnerability response SLAs (24h).
- **Current Maintainers**:
  - Vishnu Vardhan Burri (`@vishnuvardhanburri`) - Lead Architect & Maintainer

---

## Decision-Making Process

1. **Lazy Consensus**: Routine bug fixes, rule additions, performance optimizations, and documentation updates operate on lazy consensus after passing automated CI.
2. **Consensus & Voting**: Major architectural changes or security breaking changes require consensus among Maintainers. Voting operates on a simple majority rule (>50%).

---

## License

PyWAF is open-source software licensed under the **MIT License**.
