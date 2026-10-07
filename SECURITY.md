# Security Policy

## Scope

This repository is a static-analysis tool for identifying cryptographic primitives that are vulnerable to known classical or quantum attacks. Security reports should cover the scanner itself, its rule-loading/reporting paths, or issues that could cause unsafe analysis behavior.

## Reporting a vulnerability

Please do not disclose potentially exploitable details in a public issue. Use GitHub's private security reporting mechanism for this repository when available, or contact the maintainer privately through the contact information associated with the repository.

Include:
- affected commit/version
- reproduction steps or a minimal proof of concept
- expected versus actual behavior
- impact and any relevant logs

## Scanner trust model

pqc-scanner is static analysis, not a cryptographic proof or a complete program verifier.

- A finding means a supported detector matched source text or an AST pattern; it does not prove that the matched primitive is actually used in a security-sensitive path.
- No finding does not prove that a codebase is quantum-safe. Dynamic construction, unsupported libraries, generated code, native code, obfuscation, incomplete rules, and unsupported file formats can produce false negatives.
- Regex-based detectors can produce false positives from comments, strings, examples, configuration, or unrelated text.
- Python AST detection is more structured than regex matching, but it is still intentionally conservative and does not perform whole-program data-flow or reachability analysis.
- Recommendations are migration guidance, not drop-in substitutions. Algorithm choice depends on protocol role, interoperability, key management, performance, and deployment constraints.
- NIST standards referenced by the scanner should be checked against current NIST publications before making deployment decisions.

## Development security invariants

Changes to detector logic should preserve:
- no execution of scanned source code
- no requirement to import the target application's dependencies during analysis
- deterministic findings for the same input and rule set
- tests covering both vulnerable examples and known-clean cryptographic primitives

The scanner should treat untrusted source files as data. Do not add functionality that executes, imports, or evaluates scanned project code.

## Responsible use

Use this project for defensive code review, migration planning, research, education, and authorized security assessments. Do not use scan output as a certification of compliance or as proof that a system is secure.
