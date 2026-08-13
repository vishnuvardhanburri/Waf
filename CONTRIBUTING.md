# Contributing to PyWAF

Thank you for your interest in contributing to PyWAF! As an open-source Web Application Firewall, we maintain strict code quality, performance, and security standards to comply with **OpenSSF Gold Level Certification**.

---

## Code of Conduct

All contributors must follow our [Code of Conduct](CODE_OF_CONDUCT.md). Please report any violations to `security@pywaf.org`.

---

## Developer Certificate of Origin (DCO)

All contributions to PyWAF must include a **Developer Certificate of Origin (DCO)** sign-off in every git commit:

```text
Signed-off-by: Jane Doe <jane.doe@example.com>
```

You can automatically sign off commits using `git commit -s`.

---

## Development Setup

### Prerequisites
- Python 3.10+ (Python 3.10, 3.11, 3.12, 3.14 supported)
- `pytest` for test execution

### Setup Instructions

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/vishnuvardhanburri/Waf.git
   cd Waf
   ```

2. **Set up Virtual Environment**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Run Unit & Hardening Tests**:
   ```bash
   pytest tests/ -v
   ```

---

## Coding & Security Standards

1. **Zero External Dependencies**: Core PyWAF engine (`waf/`) must remain lightweight with standard library imports only.
2. **Test Coverage**: All new WAF rules or features must include unit tests in `tests/` with >90% code coverage.
3. **Double URL Decoding**: All input payload processors must support double-URL-decoded payload inspection.
4. **MIT License**: All contributions are made under the project's [MIT License](LICENSE).

---

## Pull Request Workflow

1. **Branch Naming**: `feat/short-description`, `fix/short-description`, or `sec/short-description`.
2. **Commit Sign-off**: Always run `git commit -s`.
3. **CI Status**: All GitHub Action matrix tests (Ubuntu, macOS, Windows across Python versions) must pass cleanly.
4. **Review Requirement**: Minimum **1 Maintainer approval** required before merge.
