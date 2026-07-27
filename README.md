```
██████╗  █████╗ ████████╗██╗  ██╗██████╗  ██████╗ ██╗   ██╗███████╗██████╗
██╔══██╗██╔══██╗╚══██╔══╝██║  ██║██╔══██╗██╔═══██╗██║   ██║██╔════╝██╔══██╗
██████╔╝███████║   ██║   ███████║██████╔╝██║   ██║██║   ██║█████╗  ██████╔╝
██╔═══╝ ██╔══██║   ██║   ██╔══██║██╔══██╗██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗
██║     ██║  ██║   ██║   ██║  ██║██║  ██║╚██████╔╝ ╚████╔╝ ███████╗██║  ██║
╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝
```

**Automated path traversal exploitation for confirmed vulnerabilities.**

---

> **Legal disclaimer**
>
> PathROVER is intended for use against systems you own or have explicit written
> authorization to test. Unauthorized use against systems you do not have
> permission to test is illegal. You are solely responsible for complying with
> all applicable laws. The author accepts no liability for misuse.

---

## How it works

1. **Baseline**: sends 3 probe requests with garbage values to fingerprint the server's normal response (status code, body length, content type)
2. **Scan**: fires all wordlist payloads concurrently against the injection point you marked in your request file
3. **Classify**: compares each response against the baseline and assigns a confidence level (see [Classification legend](#classification-legend))
4. **Extract & report**: parses confirmed hits offline for sensitive data (credentials, keys, tokens, hashes, and more) and writes a report in your chosen format

---

## Prerequisites

- Python 3.10 or later
- [`pipx`](https://pipx.pypa.io/)

> **Note: externally managed Python (Kali Linux / Debian 12+ / Ubuntu 23.04+)**
> These distributions mark the system Python as "externally managed", which
> means `pip install` is blocked system-wide.  Install `pipx` first, then use
> it to install PathROVER into an isolated environment:
>
> ```bash
> sudo apt install pipx && pipx ensurepath
> ```
>
> After running `pipx ensurepath`, open a new shell (or run `source ~/.bashrc`)
> so that `~/.local/bin` is on your `PATH`.

---

## Installation

Clone the repository, then install with `pipx` from the repo root:

```bash
pipx install .
```

This makes `pathrover` available as a command in your shell.

---

## Usage

```
pathrover -r <request_file> --os <os> --report-type <format> --output <file> [options]
```

### Flags

| Flag | Required | Default | Description |
|---|---|---|---|
| `-r`, `--request` | yes | (none) | Raw HTTP request file (Burp Suite format). Must contain the `ROVER` marker. |
| `--os` | yes | (none) | Target OS. One of: `linux`, `windows`, `macos`. |
| `--report-type` | yes | (none) | Output format. One of: `html`, `json`, `csv`. |
| `--output` | yes | (none) | Output file path for the report. |
| `--threads` | no | `10` | Number of concurrent async requests (1–200). |
| `--threshold` | no | `5` | Response length delta % to flag as CANDIDATE (0–100). |
| `--timeout` | no | `10` | Per-request timeout in seconds (1–300). |
| `--proxy` | no | (none) | HTTP/HTTPS proxy URL (e.g. `http://127.0.0.1:8080`). |
| `--version` | no | (none) | Print version and exit. |

### Examples

```bash
pathrover -r req.txt --os linux --report-type html --output report.html
pathrover -r req.txt --os windows --report-type json --output out.json --threads 20
pathrover -r req.txt --os macos --report-type csv --output out.csv --proxy http://127.0.0.1:8080
```

---

## Request file format

PathROVER accepts a raw HTTP request in Burp Suite format. Place the `ROVER`
marker after a traversal prefix at the injection point you want tested, and
it will be replaced with each payload during the scan.

**Example: query parameter**

```
GET /download?file=../../../../../../../ROVER HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Accept: */*
```

**Example: POST body**

```
POST /api/fetch HTTP/1.1
Host: example.com
Content-Type: application/json
Content-Length: 37

{"path":"../../../../../../../ROVER"}
```

The marker is supported in the URL path, query parameters, headers, form body
parameters, and JSON body fields.

---

## Classification legend

| Result | Meaning |
|---|---|
| `CONFIRMED` | Binary magic bytes matched, known file content signature matched, or general content heuristic matched. Sensitive data extraction is run on these. |
| `CANDIDATE` | Response diverged structurally from baseline (status code change or body length delta beyond threshold) but no content match. Worth manual review. |
| `MISS` | Response is indistinguishable from baseline. |
| `ERROR` | Request timed out or a network error occurred. |

---

## Report formats

| Format | Description |
|---|---|
| `html` | Self-contained HTML report with scan summary, hit table, and extracted findings. |
| `json` | Machine-readable JSON, useful for piping into other tools or scripts. |
| `csv` | Flat CSV of all findings, easy to import into a spreadsheet. |

---

## License

[MIT](LICENSE), Copyright (c) 2026 Stu Skove

---

## Known behaviors

- **SSL verification is disabled.** PathROVER sets `verify=False` on all HTTPS connections. This is intentional: pentest targets commonly use self-signed certificates. It means all HTTPS traffic is susceptible to MITM interception. Only run PathROVER on networks you control or trust.

- **Report files contain sensitive data.** Confirmed hits produce reports with extracted credentials, private keys, and tokens in plaintext. The `.gitignore` in this repository excludes all three report formats (`*.html`, `*.csv`, `*.json`). Never commit report output to version control.
