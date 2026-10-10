# Detection scope and review contract

PQC Scanner is a static-analysis aid for locating supported cryptographic API patterns. A result is a lead for human review, not a certification that a codebase is vulnerable or quantum-safe.

## Detector boundaries

- **Python AST detector:** recognizes supported import and call patterns in parsed Python source. It is not whole-program data-flow analysis and does not establish that a matched call is reachable.
- **Generic detector:** applies lexical rules to supported non-Python file types. It can match comments, strings, generated files, or configuration that is not executed; formatting and unsupported APIs can also cause misses.
- **Taxonomy:** keep quantum-broken public-key primitives distinct from algorithms that are already considered weak classically. Do not classify AES-256 or SHA-256 as broken merely because a quantum algorithm provides a speedup against some cryptographic tasks.
- **Recommendations:** migration suggestions require protocol, interoperability, key-management, implementation, and deployment review. They are not drop-in substitutions or compliance attestations.

## Rule-change checklist

For each detector or rule change:

1. Add a focused vulnerable fixture that demonstrates the supported syntax.
2. Add a clean or near-miss fixture for likely false positives.
3. Assert the expected bucket and severity, not only that some finding exists.
4. Preserve source path and line information where the detector supports it.
5. Explain whether the rule is structural (AST) or lexical (pattern matching), and list important unsupported forms.
6. Run the complete test suite and package build before release.
7. Never describe fixture results as a measured false-positive or false-negative rate for arbitrary repositories.

Fixtures are curated regression examples. Their pass rate describes only those examples; it is not a population-level accuracy estimate.

## Interpreting results

A finding means a supported pattern matched. It does not by itself prove:

- the matched code executes in production;
- the algorithm is used for a security-sensitive purpose;
- a complete protocol can be attacked;
- the suggested replacement is compatible with the application.

Likewise, a clean scan cannot prove that a repository is quantum-safe. Dynamic imports, reflection, native extensions, generated code, custom wrappers, unsupported libraries, and incomplete rules may be outside the detector's coverage.

## Primary standards references

Use the published standards as the source of truth for algorithm names and requirements:

- [NIST FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205 (SLH-DSA)](https://csrc.nist.gov/pubs/fips/205/final)

A standard's existence does not imply that a particular detector rule is complete or that a migration is suitable for every protocol.
