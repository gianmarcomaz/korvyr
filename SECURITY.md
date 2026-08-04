# Security policy

## Scope

Korvyr is a **research prototype**, not a supported security product. It is
provided as-is under the MIT license, with no guarantee of a fix or a response
time. That said, security reports are welcome and will be taken seriously.

**In scope** — vulnerabilities in Korvyr itself:

- Code execution or file writes outside the scratch directory when scanning a
  crafted package (path traversal on extraction, symlink escapes, zip-slip).
- Denial of service in the scanner or proxy triggered by a crafted package
  (unbounded memory, unbounded CPU, parser hangs).
- Server-side request forgery or credential leakage through the proxy or the
  `/scan/package` endpoint.
- Anything that causes Korvyr to *execute* code from a package under analysis.
  Korvyr must never run untrusted package code; a way to make it do so is the
  most serious class of bug in this repository.

**Out of scope**

- **Detection misses and false positives.** A malicious package Korvyr does not
  flag, or a benign one it does, is expected behaviour for a prototype with the
  limitations documented in the README. Please open a normal issue instead — a
  reproducible sample of a missed pattern is genuinely useful.
- Evasion techniques against the published rules. The rules are public and
  pattern-based; evasion is assumed to be practical and is documented as a
  limitation, not treated as a vulnerability.
- The absence of authentication on the scanner API and the proxy. Both are
  documented as localhost/trusted-network services.
- The proxy's fail-open default. This is a documented deployment limitation with
  an opt-out (`KORVYR_FAIL_MODE=closed`).
- Vulnerabilities in third-party dependencies without a demonstrated impact on
  Korvyr. Please report those upstream.

## Reporting

Report privately through **GitHub Security Advisories**:
<https://github.com/gianmarcomaz/Korvyr/security/advisories/new>

Please do not open a public issue for an in-scope vulnerability before it is
resolved.

Helpful contents for a report:

- What an attacker achieves, and what access they need to achieve it.
- Reproduction steps, ideally with a **synthetic** package that demonstrates the
  issue. Do not attach real malware — a minimal harmless fixture in the style of
  `tests/fixtures/` is enough and much easier to work with.
- The affected commit or release.

You can expect an acknowledgement within roughly two weeks. Because this is a
research project maintained by one person, fixes are best-effort.

## Reporting malicious packages

Korvyr's verdicts are **not** authoritative findings. If Korvyr flags a package
on the public registry and you believe it really is malicious, report it to
[npm](https://docs.npmjs.com/reporting-malware-in-an-npm-package), not here.

Do not use a Korvyr verdict as the sole basis for a public accusation against a
package or its maintainer. The measured false-positive rate on a balanced
benchmark was non-zero, and the real-world rate is unknown.

## Handling malicious samples

If you work on Korvyr's detection quality you will handle real malicious
packages. Keep them out of this repository — `data/`, `checkpoints/`, `models/`,
and `results/` are git-ignored precisely so that a corpus cannot be committed by
accident. Never install, execute, or unpack a sample outside an isolated
environment; Korvyr's own analysis is entirely static and never executes package
code.
