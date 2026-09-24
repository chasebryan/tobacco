# Rule coverage

All rules report candidates for human review. A location match does not establish attacker control, reachability, credential validity, or an exploitable application.

| ID | Trigger and review guidance |
| --- | --- |
| SEC001 | A private-key header appears in a text file. Check whether actual key material follows and whether it is a fixture. The scanner does not parse or decrypt keys. |
| SEC002 | A value matches selected GitHub, Slack, or Stripe token formats. The scanner does not contact the provider or check whether the credential works. |
| SEC003 | A credential-like name has a literal value in selected source/configuration formats. Common placeholders, environment references, and values shorter than eight characters are excluded to reduce noise. This is not an entropy-based detector and misses other names, encodings, concatenations, and weak placeholder-like real passwords. |
| PY001 | Nonliteral input reaches Python's `eval` or `exec`. Static literals and known shadowed names are excluded. Trace whether untrusted data can reach the operation. |
| PY002 | A dynamic command reaches common shell operations or `subprocess` with `shell=True`. Argument lists with shell mode disabled are excluded; argument injection into individual programs is not assessed. |
| PY003 | SQL-like literals are assembled dynamically and reach `execute`, `executemany`, or `executescript`. Parameter binding is excluded. Receiver types and identifier allowlists need review. |
| PY004 | Nonliteral data reaches selected pickle/dill deserialization functions. Check input integrity and trust; trusted local caches may be intentional. |
| PY005 | Nonliteral input reaches unsafe YAML loaders or `yaml.load` without a loader. Behavior for an omitted loader depends on the installed PyYAML version. Explicit safe loaders are excluded. |
| PY006 | Recognized HTTP/TLS APIs explicitly disable certificate verification. Review whether the setting is used for real network communication. |
| PY007 | Flask debug settings or Django-like settings explicitly enable debugging. Review deployment configuration; local development may be intentional. |
| PY008 | `tempfile.mktemp` produces a path without reserving it. Prefer atomic file creation. |
| JS001 | A nonliteral expression reaches `eval` or `Function`. Full lexical scopes and aliases are not resolved. |
| JS002 | Dynamic input reaches `exec`/`execSync` imported from Node's `child_process`. Common CommonJS and ES module imports are recognized. `spawn` shell options and cross-file aliases are not currently checked. |
| JS003 | SQL text is directly interpolated or concatenated in a `query`/`execute` call. Queries stored in variables, tagged-template query builders, and receiver types are not analyzed. |
| PHP001 | A request superglobal appears directly in a selected execution/deserialization call. Assignments and cross-function propagation are not tracked. Sanitization and the PHP API/version need review. |
| CFG001 | Selected Node/cURL settings explicitly disable TLS verification. This is not a general network configuration parser. |
| CFG002 | A recognized Compose YAML file contains `privileged: true`. YAML anchors, arbitrary filenames, Kubernetes configurations, and inherited values are not covered. |
| CFG003 | A recognized GitHub Actions workflow uses `pull_request_target` and checks out a pull-request head. Subsequent execution, workflow permissions, checkout version protections, and secret access determine exploitability. |
| DEP001 | With `--dependencies`, OSV reports an advisory for a supported exact package version. Review whether affected code paths are used. Published fixed versions may cover different release branches. Severity comes from an explicit database severity or a supported CVSS v3 base vector; unavailable/unsupported severity uses clearly labeled high review priority. |
| HTTP001 | The selected probe URL uses plaintext HTTP. Local development endpoints may intentionally omit TLS. |
| HTTP002 | An HTTPS response lacks a valid HSTS header with a positive max-age. Parent-domain policy and browser preload coverage are not assessed. |
| HTTP003 | An HTML response lacks `X-Content-Type-Options: nosniff`. Non-HTML responses are excluded. |
| HTTP004 | An HTML response lacks an enforcing CSP header. CSP in the page body is not inspected, and existing policy strength is not analyzed. |
| HTTP005 | A cookie issued over HTTPS lacks `Secure`. Cookie purpose is not inferred. |
| HTTP006 | An issued cookie lacks `HttpOnly`. Cookies intentionally read by JavaScript require context. |
| HTTP007 | An issued cookie lacks explicit `SameSite=Lax` or `Strict`. `SameSite=None` can be necessary for cross-site use and needs separate CSRF review. |
| HTTP008 | TLS validation failed. The probe does not retry with verification disabled. Inspect certificate hostname, expiry, and chain; header checks remain incomplete. |

Python uses its standard-library AST, common imported-symbol resolution, and bounded local assignment tracking. This does not model all control flow, function arguments across calls, decorators, monkey-patching, dependency versions, or cross-file behavior. Text rules use bounded pattern matching and do not fully parse JavaScript, PHP, YAML, or shell code.

Comments and string literals are filtered for many code-pattern rules. Explicit key/token rules also inspect comments and documentation because credentials can leak there. Reports contain fixed explanations and locations rather than excerpts or secret values.

Dependency lookups send only validated names, versions, and ecosystems to the fixed OSV endpoint. Requirements source overrides and explicit non-public package sources are excluded from public advisory queries. Other unsupported manifests, unresolved entries, environmental conditions, and resource limits are recorded in coverage notes. Package/version matching is delegated to OSV; it is not whole-program reachability analysis.

The HTTP probe performs one GET with normal certificate validation, no redirects, and no body reads. It reads response headers only. It does not test authentication, paths other than the supplied URL, exploit payloads, request smuggling, or application state changes. HTTP report locations are URLs rather than source lines.

Adding a rule should include a vulnerable example, its safe counterpart, a concrete limitation, and a test verifying that the report does not expose source values.
