# Tobacco

**Point Tobacco at an application's source code and get a report of potential security weaknesses.**

Tobacco is a security auditor for open-source projects. It reads a directory or a single file, checks for common dangerous patterns, and reports the file, line, severity, confidence, and suggested fix. Source scans run offline by default and never import or execute the application. Optional dependency checks query public advisories; a separate HTTP probe checks a running application's response headers and TLS.

This is the first working version: 27 rule families covering source code, credentials, configuration, dependencies, and HTTP. Findings are review candidates. A scanner cannot identify every vulnerability or prove exploitability from a suspicious pattern alone.

## Run it

Linux or macOS with Python 3.11 or newer is required. Running from this checkout needs no third-party packages:

```sh
cd tobacco
python3 -m tobacco scan /path/to/application
```

Try the intentionally unsafe example:

```sh
python3 -m tobacco scan examples/vulnerable_app.py
```

The example produces five findings and exits with status `1`. It is source for demonstrating the scanner; do not deploy it.

To install the `tobacco` command in a virtual environment:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/tobacco scan /path/to/application
```

Installation may download the setuptools build backend. Tobacco has no third-party runtime dependencies. Source scanning accepts local paths; clone a remote project separately before scanning it.

## Check dependencies

```sh
python3 -m tobacco scan /path/to/application --dependencies
```

`--dependencies` opts into online queries to [OSV](https://osv.dev/). It sends the selected package names, exact versions, and ecosystems to the OSV API. It does not upload source code, complete manifests, or registry URLs, and does not install dependencies. Without this flag, no dependency lookup runs.

Supported inputs are exactly pinned `requirements*.txt`, npm `package-lock.json` v1–3 and `npm-shrinkwrap.json`, `Pipfile.lock`, and `poetry.lock`. Resolved transitive entries are checked when present. Queries are deduplicated, but findings retain each manifest location. Environment markers are not evaluated, so every supported pinned variant is considered. Requirements source overrides, non-public registry sources, includes, links, version ranges, and unsupported lock formats are recorded as gaps in coverage.

Advisory findings include identifiers, a link, severity provenance, and published fixed versions where available. Fixed versions can belong to different release branches; review the advisory before upgrading. Standard CVSS v3 base vectors are interpreted when an explicit advisory severity label is unavailable. Unsupported or missing severity receives **high review priority**, explicitly labeled, so it is not silently excluded by the default failure threshold.

The audit limits each run to 500 unique package versions, five response pages per package, and a soft 60-second budget checked between requests. The default socket timeout is 10 seconds; change it with `--dependency-timeout`. Requests already in progress are bounded by their socket timeout, not an absolute wall-clock deadline. Network failures and resource limits produce coverage errors and exit status `2`, preserving partial findings.

## Check a running app

```sh
python3 -m tobacco probe http://127.0.0.1:8000
python3 -m tobacco probe https://your-app.example --format json --fail-on medium
```

The probe makes one unauthenticated GET request to the supplied URL. It checks HTTP/TLS, HSTS, selected HTML security headers, and cookie attributes. It does not follow redirects, crawl links, read the response body, send attack payloads, or start the application. Cookie names and values are omitted from the report.

The selected URL is included in the report. URLs containing credentials, queries, or fragments are rejected. The probe ignores environment proxy settings and ambient cookies. `--timeout` changes the socket-operation timeout; it is not a total elapsed-time deadline.

Missing headers and cookie attributes are contextual review candidates. Development HTTP, intentional JavaScript-readable cookies, parent-domain HSTS policies, and CSP meta elements can explain findings. Redirects and non-HTML responses have coverage notes; HTTP failures, invalid cookies, and connection/TLS failures produce exit status `2`.

## Read a finding

Each finding includes:

- A stable rule ID and a description of the suspicious operation.
- Its relative file path, line, and column, starting at 1.
- Severity, confidence, a CWE category, and a suggested fix.
- A location fingerprint in structured reports.

Severity describes possible impact when the code is reachable with attacker-controlled input. Confidence describes how clearly the code matches the rule, not the probability of a successful exploit. Confirm input origins, validation, execution paths, and deployment settings before treating a candidate as a vulnerability.

Reports do not include source excerpts or matched secret values. File paths are included. Fingerprints identify a rule at a location and will change when the finding moves.

## Built-in checks

| Rules | Coverage |
| --- | --- |
| SEC001–SEC003 | Private-key headers, selected service-token formats, and possible hardcoded credentials |
| PY001–PY003 | Dynamic Python evaluation, shell commands, and SQL string construction |
| PY004–PY005 | Pickle-like deserialization and unsafe YAML loading |
| PY006–PY008 | Disabled TLS verification, debug settings, and insecure temporary filenames |
| JS001–JS003 | Dynamic evaluation, Node shell execution, and interpolated SQL |
| PHP001 | Request data passed directly to selected execution or deserialization operations |
| CFG001–CFG003 | Disabled TLS verification, privileged Compose containers, and untrusted checkout in privileged Actions workflows |
| DEP001 | Pinned package versions matching OSV advisories, with published fix information |
| HTTP001–HTTP008 | Transport encryption, TLS validation, HSTS, HTML security headers, and cookie attributes |

```sh
python3 -m tobacco rules
```

Python analysis resolves common import aliases and tracks some local assignments and branches. The JavaScript, TypeScript, PHP, and configuration checks use text patterns with limited comment/string handling. Other languages receive credential checks only. See [rule coverage and limitations](docs/RULES.md) for details.

## Reports and CI

```sh
python3 -m tobacco scan /path/to/application --format json > /tmp/tobacco-report.json
python3 -m tobacco scan /path/to/application --format sarif > /tmp/tobacco-report.sarif
python3 -m tobacco scan /path/to/application --fail-on medium
```

Write reports outside the scanned directory so they do not become input to the scan. SARIF output follows the 2.1.0 format, including locations, rule IDs, and fingerprints; it can be consumed by compatible tools. See [GitHub's SARIF documentation](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support) for platform-specific requirements.

| Exit status | Meaning |
| --- | --- |
| `0` | No reported findings reached the selected threshold |
| `1` | At least one reported finding reached the threshold; default is `high` |
| `2` | Invalid input or incomplete analysis caused by read, parse, network, or resource-limit errors |

`--fail-on none` reports findings without failing on them. Analysis errors still return `2`, and partial findings remain in the report. `--min-severity` filters reported findings before the failure threshold is applied. Both `scan` and `probe` support text, JSON, SARIF, severity filtering, rule filtering, and failure thresholds. A status of `0` is not a security clearance: inspect the coverage notes too.

## Control the scope

```sh
python3 -m tobacco scan /path/to/application \
  --exclude 'tests/*' \
  --exclude '*.min.js' \
  --ignore-rule PY008 \
  --min-severity medium

python3 -m tobacco scan /path/to/application \
  --no-default-excludes \
  --max-file-bytes 4194304
```

Exclusion globs match relative paths or basenames, including directories. Quote globs so your shell does not expand them. `--exclude` and `--ignore-rule` can be repeated. This version does not interpret `.gitignore` or inline suppression comments.

By default, Tobacco skips version-control metadata, dependency directories such as `node_modules` and `vendor`, virtual environments, common build/cache directories, symlinks, binary files, non-UTF-8 files, and files larger than 1 MiB. Hidden source/configuration files such as `.env` and `.github/workflows` are eligible. Every skipped entry is listed in coverage notes; a skipped directory represents its entire subtree. `--no-default-excludes` includes the default excluded directories; symlink, encoding, file type, and size checks still apply. Check the report's `options` field for the exact default directory list.

## Current limits

Tobacco does not perform whole-program dataflow analysis, exploit execution, authentication/authorization testing, or full parsing of languages other than Python. It does not inspect Git history or fetch missing source/dependencies. The HTTP probe inspects a single unauthenticated response, so it cannot assess application behavior or protected routes. Dependency coverage depends on supported resolved versions and the advisory database. Python syntax support follows the interpreter running the scanner. UTF-8 is the supported source encoding.

False positives and missed vulnerabilities are expected, especially for dynamic imports, wrappers, custom sanitizers, complex control flow, generated code, and business logic. The report counts files read, not files proven safe. Use the findings to direct review and testing.

## Development

```sh
python3 -m unittest discover -s tests -v
python3 -m tobacco scan tobacco
```

Tests cover vulnerable and safe patterns, secret redaction, dependency parsing and mocked advisory responses, HTTP behavior, scope exclusions, coverage errors, report formats, and CLI exit codes. The test suite and example intentionally contain suspicious code; scanning the entire repository can report those fixtures. GitHub Actions runs tests on Linux with Python 3.11, 3.12, and 3.13, and on macOS with Python 3.13, including an installed-command check.

Dependency integration follows the [OSV query API](https://google.github.io/osv.dev/post-v1-query/) and [OSV schema](https://ossf.github.io/osv-schema/). CVSS is owned by FIRST and used by permission; the base-score implementation follows the [CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document).

Licensed under the [GNU Affero General Public License v3](LICENSE).
