# Test fixtures

Minimal **synthetic** npm packages used by the test suite. None of them contain
real malware, and nothing in the test suite executes them — Korvyr's analysis is
entirely static.

| Fixture | What it exercises |
|---|---|
| `clean-package/` | A well-formed package with no suspicious behaviour: the negative case for every rule. |
| `malicious-install-hook/` | A `postinstall` hook whose script reads two credential environment variables and references a remote URL. Triggers the install-hook and credential-exfiltration rules. |
| `manifest-curl-pipe/` | A `postinstall` command that pipes `curl` output into `bash`. Triggers the manifest scanner without any JavaScript file. |

## These fixtures are not model test cases

The tests exercise the rules engine and manifest scanner, which run without a
checkpoint. Do not use these fixtures to judge the GNN: they are a handful of
lines each and sit far outside the distribution of real npm packages the model
was trained on. Scored with a checkpoint loaded, `clean-package` has been
observed above the 0.80 block threshold — a false positive, and an accurate
illustration of the model's compressed score distribution documented in
[`docs/results/production-eval-2026-05-22.md`](../../docs/results/production-eval-2026-05-22.md).

## Conventions for new fixtures

- **Never commit real malware.** Reproduce the *pattern* a rule matches, not an
  actual payload.
- Use `*.example` hostnames (reserved by RFC 2606, they never resolve) rather
  than any real domain.
- Use obviously fake credential values. Never a real token, even an expired one.
- Keep fixtures to the few files a rule needs; the point is that a reviewer can
  read the whole thing in seconds and see exactly why a rule fires.
- Name the directory after the behaviour being tested.

Tests that need a package shaped differently from these three should build a
temporary package inline with `tmp_path` rather than adding a near-duplicate
fixture.
