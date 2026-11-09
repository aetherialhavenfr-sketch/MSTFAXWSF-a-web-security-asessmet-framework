# MSTFAXWSF

A black-and-red terminal framework that chains **Katana, FFUF, WhatWeb, Nikto and Nuclei** into one
automated web security assessment. Type a domain, get live output and a professional HTML + JSON report.

Pure Python standard library: no `pip install`, nothing heavy. Built for Kali Linux (any Debian-based distro works).

> **Authorized use only.** MSTFAXWSF refuses targets that are not in your scope file or a recognised lab.
> Scanning systems without permission can be illegal. You are responsible for how you use it.

## Quick start

```bash
cd MSTFAXWSF
./install.sh                    # optional: installs the tools + a `mstfaxwsf` command
./mstfaxwsf.py                  # interactive menu (best for beginners)
./mstfaxwsf.py 192.168.56.101   # scan a lab VM straight away
./mstfaxwsf.py testphp.vulnweb.com -p quick
```

Your own site or a client's? Add it to scope first, with a written authorization reference:

```bash
./mstfaxwsf.py scope add example.com --subdomains --note "Own site, owner: me"
./mstfaxwsf.py example.com
```

## What it does

| Step | Module | Purpose |
|------|--------|---------|
| 1 | **Recon** (built in) | DNS, reverse DNS, web-port check, HTTP probe, TLS summary, security headers, cookie flags, robots.txt, sitemap.xml, security.txt |
| 2 | **WhatWeb** | Website and technology fingerprinting |
| 3 | **Katana** | Endpoint crawling (kept on the target host), parameters, JS files |
| 4 | **FFUF** | Directory and file discovery with auto-calibration |
| 5 | **Nikto** | Classic web server checks |
| 6 | **Nuclei** | Template-based vulnerability scanning |

Missing tools are detected and skipped, never fatal. `mstfaxwsf tools --install` installs them (apt first, `go install` as fallback) after asking.

## Commands

```
mstfaxwsf                          interactive menu
mstfaxwsf <target> [options]       scan (shortcut for `scan`)
  -p, --profile quick|standard|deep
  -m, --modules recon,whatweb,...  run only these      --skip nikto,nuclei   leave these out
  -w, --wordlist FILE              custom FFUF wordlist
  -q, --quiet                      hide live tool output
  -y, --yes                        skip the typed confirmation (target must already be in scope)
  --oob                            allow Nuclei out-of-band (interactsh) checks
  --user-agent UA                  override the identifying User-Agent
mstfaxwsf tools [--install] [-y]   detect / install tools
mstfaxwsf history [show|delete|clear] [#]
mstfaxwsf report <#> [--format html|json|both]    regenerate a report
mstfaxwsf scope list|add|remove|check [value] [--note TEXT] [--subdomains]
mstfaxwsf templates                update Nuclei templates
```

**While scanning:** `Ctrl+C` skips the current tool; press it twice within 6 seconds to abort. Partial results are always saved.

## Profiles

| Profile | Nuclei severities | Crawl depth | FFUF wordlist | Notes |
|---------|------------------|-------------|---------------|-------|
| `quick` | high, critical | 2 | bundled mini list | ~5-10 min |
| `standard` (default) | medium and up | 3 | common.txt | ~15-30 min |
| `deep` | all | 4 | large list + extensions | crawled endpoints are fed to Nuclei |

All profiles use conservative rate limits and exclude DoS-tagged Nuclei templates.

## Authorization model

A target is accepted only if it is:

1. in `~/.mstfaxwsf/authorized_targets.txt` (domain, `*.domain`, IP or CIDR, each with a note), or
2. localhost, a private/loopback IP (10/8, 172.16/12, 192.168/16, 127/8), or a lab-style name (`.local .lab .test .htb .thm .vm .localhost`), or
3. an intentionally vulnerable public test site (e.g. `testphp.vulnweb.com`).

Additionally: every interactive scan needs the typed word `AUTHORIZED`; `--yes` never bypasses the scope check;
redirects to out-of-scope hosts are not followed; Katana is limited to the target host; Nuclei does not contact
third-party interactsh servers unless you pass `--oob`; all decisions are written to `~/.mstfaxwsf/audit.log`;
and all traffic carries an identifying User-Agent so defenders can recognise it.

This guard is a safety net against mistakes and typos, not proof of permission. Only you can confirm that.

## Output

```
~/.mstfaxwsf/
├── history.json  audit.log  authorized_targets.txt
└── scans/<timestamp>-<target>/
    ├── report.html     self-contained, filterable, safe to email
    ├── report.json     full machine-readable session
    └── raw/            each tool's own output and log
```

Set `MSTFAXWSF_HOME` to relocate it. `NO_COLOR=1` or `--no-color` disables colour.
Nikto does not grade findings, so its severities are keyword heuristics (noted in the report).

## Architecture

```
mstfaxwsf.py            launcher
mstfax/
├── cli.py              argparse + interactive menu
├── engine.py           pipeline, Ctrl+C handling, reports, history
├── scope.py            authorization guard + audit log
├── dependencies.py     detection, versions, flag probing, installer
├── runner.py           streaming subprocess runner (never uses a shell)
├── ui.py / banner.py   black-and-red theme, gradient banner
├── history.py          scan index        target.py   strict input validation
├── models.py           Finding, ModuleResult, ScanSession
├── modules/            recon, whatweb, katana, ffuf, nikto, nuclei (+ base.py)
└── reporting/          html_report.py, json_report.py
```

### Adding a module

Subclass `ExternalToolModule` in `mstfax/modules/`, set `key`, `tool`, `title`, implement `build_command()`
and `parse()` (optionally `format_line()` for live output), then register it in `modules/__init__.py` and
`config.MODULE_ORDER`. Optional tool flags go through `dependencies.optional_flags()`, which only adds a flag
when the installed version advertises it.

## Troubleshooting

- **Nuclei finds nothing / fails on first run:** run `mstfaxwsf templates` (needs internet).
- **`katana`/`nuclei` not in Kali's apt:** `mstfaxwsf tools --install` falls back to `go install` (needs Go); binaries land in `~/go/bin`, which is added to PATH automatically.
- **Target "not reachable":** Recon found no HTTP(S) response, so the remaining tools are skipped. Check the host, port and scheme (`https://host:8443`).
