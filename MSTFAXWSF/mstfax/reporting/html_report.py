"""Self-contained HTML report (no external assets). Works from the session dict, so any
saved report.json can be re-rendered. Every dynamic value is HTML-escaped because scan data
originates from remote servers and must be treated as untrusted."""
from __future__ import annotations

from html import escape
from pathlib import Path

from ..banner import banner_rows
from ..models import SEV_RANK, SEVERITIES

CSS = """
:root{--bg:#050505;--line:#2b0c10;--red:#ff2626;--crimson:#c81424;--dark:#6e0a14;
--text:#dadada;--muted:#8d8d8d;--critical:#ff1e46;--high:#ff5c30;--medium:#ffb020;
--low:#e8dc5a;--info:#6eaadc;--ok:#4cd678}
*{box-sizing:border-box}
html{background:var(--bg);color:var(--text);
font:14px/1.55 "JetBrains Mono","DejaVu Sans Mono",Menlo,Consolas,monospace}
body{margin:0;padding-bottom:4rem}
.wrap{max-width:1080px;margin:0 auto;padding:0 1.25rem}
header.top{padding:2.2rem 0 1.5rem;border-bottom:1px solid var(--line)}
pre.logo{margin:0 0 1.2rem;font-size:clamp(5px,1.3vw,13px);line-height:1.08;white-space:pre;
overflow:hidden;font-weight:700;color:var(--red);
background:linear-gradient(100deg,#ff2626 0%,#c81424 45%,#56000a 100%);
-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
@supports not (background-clip:text){pre.logo{-webkit-text-fill-color:currentColor}}
h1{font-size:1.5rem;margin:0 0 .3rem;color:#fff}
h1 .host{color:var(--red)}
h2{font-size:1.05rem;margin:2.6rem 0 .9rem;padding-left:.7rem;border-left:3px solid var(--red);color:#fff}
h3{font-size:.95rem;margin:1.4rem 0 .5rem;color:#fff}
a{color:var(--red)}
code{font-family:inherit;color:#f0c4c4;word-break:break-all}
.muted{color:var(--muted)}
.kv{display:grid;grid-template-columns:max-content 1fr;gap:.25rem 1.4rem;margin:.6rem 0}
.kv dt{color:var(--muted)}.kv dd{margin:0;word-break:break-word}
.sevbar{display:flex;height:10px;margin:1rem 0 .8rem;background:#161012;overflow:hidden}
.sevbar span{display:block;min-width:2px}
.filters{display:flex;flex-wrap:wrap;gap:.5rem;margin-bottom:1rem}
button{font:inherit;color:var(--text);background:#0c0809;border:1px solid var(--line);
padding:.3rem .8rem;cursor:pointer}
button b{color:#fff;margin-left:.35rem}
button[aria-pressed=true]{border-color:var(--red);background:#1a0a0c}
button:focus-visible,input:focus-visible,summary:focus-visible{outline:2px solid var(--red);outline-offset:2px}
input[type=search]{font:inherit;color:var(--text);background:#0c0809;border:1px solid var(--line);
padding:.35rem .7rem;min-width:16rem;max-width:100%}
.dot{display:inline-block;width:.65rem;height:.65rem;margin-right:.45rem;background:var(--c)}
.sev-critical{--c:var(--critical)}.sev-high{--c:var(--high)}.sev-medium{--c:var(--medium)}
.sev-low{--c:var(--low)}.sev-info{--c:var(--info)}
ul.findings{list-style:none;margin:0;padding:0}
.finding{display:grid;grid-template-columns:6rem 1fr;gap:1rem;padding:.8rem .9rem;
border-left:3px solid var(--c);border-bottom:1px solid var(--line)}
.finding[hidden]{display:none}
.finding .badge{color:var(--c);font-weight:700}
.finding .title{color:#fff;word-break:break-word}
.finding .where{margin-top:.15rem;font-size:.9em;color:var(--muted)}
.finding .where .tool{margin-right:.8rem;color:var(--crimson)}
details{margin-top:.4rem}summary{cursor:pointer;color:var(--muted)}
details p{margin:.4rem 0 0;white-space:pre-wrap;word-break:break-word}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%}
th{text-align:left;color:var(--red);font-weight:700;border-bottom:1px solid var(--dark);padding:.4rem .8rem .4rem 0}
td{padding:.35rem .8rem .35rem 0;border-bottom:1px solid var(--line);vertical-align:top}
.st-ok{color:var(--ok)}.st-failed,.st-missing{color:var(--critical)}
.st-timeout,.st-interrupted{color:var(--medium)}.st-skipped{color:var(--muted)}
.chips{display:flex;flex-wrap:wrap;gap:.4rem}
.chip{border:1px solid var(--dark);padding:.1rem .6rem;background:#0c0809}
.chip i{font-style:normal;color:var(--muted);margin-left:.4rem}
ul.endpoints{margin:.5rem 0 0;padding-left:1.1rem;max-height:26rem;overflow:auto}
footer{margin-top:3rem;padding-top:1rem;border-top:1px solid var(--line);color:var(--muted);font-size:.9em}
@media(max-width:640px){.finding{grid-template-columns:1fr;gap:.2rem}}
"""

JS = """
(function(){
var rows=[].slice.call(document.querySelectorAll('.finding'));
var btns=[].slice.call(document.querySelectorAll('[data-filter]'));
var q=document.getElementById('q');var active={};
function apply(){
 var term=(q&&q.value||'').toLowerCase();var any=Object.keys(active).length>0;var shown=0;
 rows.forEach(function(r){
  var ok=(!any||active[r.dataset.sev])&&(!term||r.dataset.text.indexOf(term)>-1);
  r.hidden=!ok;if(ok)shown++;});
 var c=document.getElementById('shown');if(c)c.textContent=shown;}
btns.forEach(function(b){b.addEventListener('click',function(){
 var f=b.dataset.filter;
 if(active[f]){delete active[f];b.setAttribute('aria-pressed','false');}
 else{active[f]=1;b.setAttribute('aria-pressed','true');}
 apply();});});
if(q)q.addEventListener('input',apply);
})();
"""

SEV_COLOR = {"critical": "#ff1e46", "high": "#ff5c30", "medium": "#ffb020",
             "low": "#e8dc5a", "info": "#6eaadc"}


def e(value) -> str:
    return escape("" if value is None else str(value), quote=True)


def _risk(counts: dict) -> str:
    for sev in ("critical", "high", "medium", "low"):
        if counts.get(sev):
            return sev
    return "informational"


def _kv(pairs) -> str:
    rows = "".join(f"<dt>{e(k)}</dt><dd>{v}</dd>" for k, v in pairs if v not in ("", None))
    return f'<dl class="kv">{rows}</dl>'


def _all_findings(data: dict) -> list:
    items = [f for m in data["modules"] for f in m["findings"]]
    return sorted(items, key=lambda f: (SEV_RANK.get(f["severity"], 99), f["tool"], f["title"]))


def _summary(data: dict, counts: dict) -> str:
    total = sum(counts.values()) or 1
    bar = "".join(
        f'<span style="flex:{counts[s]};background:{SEV_COLOR[s]}"></span>'
        for s in SEVERITIES if counts.get(s))
    buttons = "".join(
        f'<button type="button" data-filter="{s}" aria-pressed="false" class="sev-{s}">'
        f'<span class="dot"></span>{s.capitalize()}<b>{counts.get(s, 0)}</b></button>'
        for s in SEVERITIES)
    risk = _risk(counts)
    sentence = (f"Highest severity observed: <b style=\"color:{SEV_COLOR.get(risk, '#6eaadc')}\">{risk}</b>. "
                f"{sum(counts.values())} findings across {len(data['modules'])} modules.")
    return (f"<p>{sentence}</p><div class=\"sevbar\" role=\"img\" aria-label=\"Severity distribution\">"
            f"{bar}</div><div class=\"filters\">{buttons}</div>")


def _modules_table(data: dict) -> str:
    rows = []
    for m in data["modules"]:
        rows.append(
            f"<tr><td>{e(m['name'])}</td><td class=\"st-{e(m['status'])}\">{e(m['status'])}</td>"
            f"<td>{m['duration']:.0f}s</td><td>{len(m['findings'])}</td>"
            f"<td><code>{e(m['command'])}</code>{('<div class=muted>' + e(m['error']) + '</div>') if m['error'] else ''}</td></tr>")
    return ('<div class="scroll"><table><thead><tr><th>Module</th><th>Status</th><th>Time</th>'
            '<th>Findings</th><th>Command / notes</th></tr></thead><tbody>'
            + "".join(rows) + "</tbody></table></div>")


def _findings_list(findings: list) -> str:
    if not findings:
        return '<p class="muted">No findings were recorded.</p>'
    items = []
    for f in findings:
        sev = f["severity"] if f["severity"] in SEV_RANK else "info"
        text = " ".join([f["title"], f["detail"], f["url"], f["tool"], sev]).lower()
        detail = ""
        extras = []
        if f.get("detail"):
            extras.append(e(f["detail"]))
        if f.get("reference"):
            extras.append("Reference: " + e(f["reference"]))
        if extras:
            detail = f"<details><summary>Details</summary><p>{'<br>'.join(extras)}</p></details>"
        where = (f'<div class="where"><span class="tool">{e(f["tool"])}</span>'
                 f'{("<code>" + e(f["url"]) + "</code>") if f["url"] else ""}</div>')
        items.append(
            f'<li class="finding sev-{sev}" data-sev="{sev}" data-text="{e(text)}">'
            f'<span class="badge">{sev}</span><div><div class="title">{e(f["title"])}</div>'
            f'{where}{detail}</div></li>')
    return "<ul class=\"findings\">" + "".join(items) + "</ul>"


def _overview(data: dict) -> str:
    recon = next((m for m in data["modules"] if m["key"] == "recon"), None)
    if not recon or not recon["data"]:
        return '<p class="muted">Reconnaissance data is not available.</p>'
    d = recon["data"]
    http = d.get("http", {})
    tls = d.get("tls", {})
    pairs = [
        ("Host", e(d.get("host"))),
        ("IP addresses", e(", ".join(d.get("ips", [])))),
        ("Reverse DNS", e(d.get("reverse_dns"))),
        ("Open web ports", e(", ".join(map(str, d.get("open_web_ports", []))))),
        ("Final URL", f"<code>{e(http.get('url'))}</code>" if http else ""),
        ("HTTP status", e(http.get("status"))),
        ("Server", e(http.get("server"))),
        ("Page title", e(http.get("title"))),
        ("TLS", e(f"{tls.get('protocol', '')} {tls.get('cipher', '')}".strip()) if tls else ""),
        ("Certificate", e(f"{tls.get('subject', '')} issued by {tls.get('issuer', '')}") if tls.get("subject") else ""),
        ("Certificate trusted", ("yes" if tls.get("verified") else "no") if tls and "verified" in tls else ""),
        ("Expires in", e(f"{tls['days_left']} days") if tls.get("days_left") is not None else ""),
    ]
    return _kv(pairs)


def _technologies(data: dict) -> str:
    ww = next((m for m in data["modules"] if m["key"] == "whatweb"), None)
    techs = ww["data"].get("technologies", []) if ww else []
    if not techs:
        return '<p class="muted">No technologies were fingerprinted.</p>'
    chips = "".join(
        f'<span class="chip">{e(t["name"])}{("<i>" + e(t["version"]) + "</i>") if t.get("version") else ""}</span>'
        for t in techs)
    return f'<div class="chips">{chips}</div>'


def _paths(data: dict) -> str:
    ff = next((m for m in data["modules"] if m["key"] == "ffuf"), None)
    rows = ff["data"].get("directories", []) if ff else []
    if not rows:
        return '<p class="muted">No paths were discovered.</p>'
    body = "".join(
        f"<tr><td><code>{e(r['url'])}</code></td><td>{e(r['status'])}</td><td>{e(r['length'])}</td>"
        f"<td>{e(r['words'])}</td><td>{e(r['lines'])}</td><td><code>{e(r.get('redirect'))}</code></td></tr>"
        for r in rows[:1000])
    note = f'<p class="muted">Showing 1000 of {len(rows)} paths.</p>' if len(rows) > 1000 else ""
    return (f'<div class="scroll"><table><thead><tr><th>URL</th><th>Status</th><th>Size</th><th>Words</th>'
            f'<th>Lines</th><th>Redirect</th></tr></thead><tbody>{body}</tbody></table></div>{note}')


def _endpoints(data: dict) -> str:
    kt = next((m for m in data["modules"] if m["key"] == "katana"), None)
    d = kt["data"] if kt else {}
    urls = d.get("endpoints", [])
    if not urls:
        return '<p class="muted">No endpoints were crawled.</p>'
    params = ", ".join(d.get("parameters", [])[:60])
    shown = urls[:2000]
    items = "".join(f"<li><code>{e(u)}</code></li>" for u in shown)
    return (_kv([("Endpoints", e(d.get("count"))), ("With parameters", e(d.get("with_params"))),
                 ("JavaScript files", e(d.get("js_files"))), ("Parameter names", e(params))])
            + f"<details><summary>Show {len(shown)} endpoints</summary><ul class=\"endpoints\">{items}</ul></details>")


def _authorization(data: dict) -> str:
    a = data.get("authorization") or {}
    return _kv([("Scope decision", e(a.get("scope_reason"))), ("Scope category", e(a.get("scope_category"))),
                ("Confirmed by", e(a.get("operator"))), ("Confirmation", e(a.get("attestation"))),
                ("Note", e(a.get("authorization_note"))), ("Time", e(a.get("time")))])


def render(data: dict) -> str:
    counts = data.get("counts") or {s: 0 for s in SEVERITIES}
    findings = _all_findings(data)
    logo = e("\n".join(banner_rows()))
    host = e(data["target"].get("host"))
    tools = data.get("system", {}).get("tools", {})
    tool_line = ", ".join(f"{k} {v.get('version') or ''}".strip() for k, v in tools.items() if v.get("installed"))
    meta = _kv([
        ("Target", f"<code>{e(data['target'].get('input'))}</code>"),
        ("Scan ID", e(data["id"])), ("Profile", e(data["profile"])),
        ("Started", e(data["started"])), ("Finished", e(data.get("finished"))),
        ("Duration", e(f"{data.get('duration', 0):.0f} seconds")),
        ("Status", "aborted by operator" if data.get("aborted") else "completed"),
        ("Tools", e(tool_line)), ("Framework", e(f"MSTFAXWSF {data.get('version', '')}")),
    ])
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MSTFAXWSF report - {host}</title>
<style>{CSS}</style></head><body><div class="wrap">
<header class="top"><pre class="logo" aria-label="MSTFAXWSF">{logo}</pre>
<h1>Web security assessment of <span class="host">{host}</span></h1>
{meta}</header>
<h2>Summary</h2>{_summary(data, counts)}
<h3>Modules</h3>{_modules_table(data)}
<h2>Findings</h2>
<p><input id="q" type="search" placeholder="Search findings" aria-label="Search findings">
<span class="muted"> showing <span id="shown">{len(findings)}</span> of {len(findings)}</span></p>
{_findings_list(findings)}
<h2>Target overview</h2>{_overview(data)}
<h2>Technology fingerprint</h2>{_technologies(data)}
<h2>Discovered paths</h2>{_paths(data)}
<h2>Crawled endpoints</h2>{_endpoints(data)}
<h2>Authorization record</h2>{_authorization(data)}
<footer><p>Generated by MSTFAXWSF. Nikto does not grade its results, so Nikto severities are keyword
heuristics. Automated tools produce false positives and miss issues; validate findings manually.
Use only against systems you own or are explicitly authorized to test.</p></footer>
</div><script>{JS}</script></body></html>
"""


def write(data: dict, path: Path) -> Path:
    path = Path(path)
    path.write_text(render(data), encoding="utf-8")
    return path
