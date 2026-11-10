"""Human-readable reports. All values come from untrusted sources and are escaped."""
import html
from pathlib import Path
from urllib.parse import urlsplit

MAX_ROWS = 500
OUTCOME_TEXT = {
    "passed": ("Scan completed and policy passed", "#17603a"),
    "policy_blocked": ("Scan completed and policy blocked the build", "#a3231f"),
    "incomplete": ("Scan incomplete, unsupported or failed", "#8a5a00"),
}


def esc(value):
    return html.escape("" if value is None else str(value), quote=True)


def safe_url(value):
    """Only ordinary web links survive; anything else becomes inert text."""
    if not isinstance(value, str) or any(ord(c) < 32 for c in value):
        return ""
    try:
        parts = urlsplit(value)
    except ValueError:
        return ""
    return value if parts.scheme.lower() in ("https", "http") and parts.hostname else ""


def _link(url, text):
    target = safe_url(url)
    return f'<a href="{esc(target)}" rel="noopener noreferrer">{esc(text)}</a>' if target else esc(text)


def _table(headers, rows):
    head = "".join(f"<th>{esc(item)}</th>" for item in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _list(items):
    return "<ul>" + "".join(f"<li>{esc(item)}</li>" for item in items) + "</ul>" if items else "<p>None.</p>"


def _finding_row(finding):
    triage = finding["triage"]
    provenance = triage.get("provenance") or {}
    paths = [" &gt; ".join(esc(step) for step in row["path"]) + (f" ({esc(row['configuration'])})" if row.get("configuration") else "") for row in finding["dependency_paths"]]
    detail = (
        f"<p><strong>Match.</strong> {esc(finding['matching']['rationale'])} Confidence: {esc(finding['matching']['confidence'])}.</p>"
        f"<p><strong>Source.</strong> {_link(finding['vulnerability']['source']['url'], finding['vulnerability']['source']['namespace'])}</p>"
        f"<p>{esc(finding['vulnerability']['description'])}</p>"
        f"<p><strong>Shipped: {esc(finding['presence']['shipped'])}.</strong> {esc(' '.join(finding['presence']['shipped_rationale']))}</p>"
        f"<p><strong>Dependency paths.</strong> {'<br>'.join(paths) or 'None known.'}</p>"
        f"<p><strong>Artifacts.</strong> {esc(', '.join(finding['artifacts']) or 'None known.')}</p>"
        f"<p><strong>Remediation.</strong> {esc(finding['remediation']['note'])} Fixed in: {esc(', '.join(finding['remediation']['fixed_in']) or 'not reported')}.</p>"
        f"<p><strong>Exploitability.</strong> {esc(finding['exploitability']['basis'])}</p>"
        + (f"<p><strong>KEV.</strong> {esc(finding['kev']['meaning'])}</p>" if finding["kev"]["listed"] else "")
        + "<p><strong>Uncertainty.</strong></p>" + _list(finding["uncertainty"])
        + "<p><strong>Missing evidence.</strong></p>" + _list(finding["missing_evidence"])
        + f"<p><strong>Triage.</strong> {esc(triage['status'])} {esc(triage.get('justification'))} {esc(triage.get('statement'))}"
        + (f" Decided by {esc(provenance.get('author'))} in {esc(provenance.get('document'))} ({esc(provenance.get('scope'))}, not authenticated)." if provenance else "")
        + (f" Rejected statement: {esc(triage['problem'])}." if triage.get("problem") else "") + "</p>"
    )
    title = f"<details><summary>{esc(finding['vulnerability']['id'])}</summary>{detail}</details>"
    return [title, esc(finding["severity"]) + (" <b>KEV</b>" if finding["kev"]["listed"] else ""),
            f"{esc(finding['component']['name'])} {esc(finding['component']['version'])}",
            esc(finding["presence"]["shipped"]), esc(finding["matching"]["confidence"]), esc(triage["status"])]


def render_html(result, inventory):
    build = result["evaluation"]["build"]
    title, color = OUTCOME_TEXT[build["outcome"]]
    versions = [[esc(item.get("name")), esc(item.get("version")), esc(item.get("output_schema", ""))] for item in result["scanners"] if isinstance(item, dict)]
    database = (result["vulnerability_data"] or {}).get("grype") or {}
    kev = (result["vulnerability_data"] or {}).get("kev") or {}
    component_rows = [[esc(item["identity"]["name"]), esc(item["identity"]["version"] or "UNKNOWN"), esc(item["identity"]["ecosystem"]),
                       "yes" if item["presence"]["declared"] else "", "yes" if item["presence"]["resolved"] else "", "yes" if item["presence"]["observed"] else "",
                       esc(item["presence"]["shipped"]), esc(item["scope"]), esc(", ".join(item["linkage"])), esc(", ".join(sorted(item["configurations"])))]
                      for item in inventory["components"][:MAX_ROWS]]
    reasons = lambda rows: _list([f"[{row.get('code')}] {row.get('message')}" for row in rows])
    findings = result["findings"]
    readiness = result.get("readiness")
    readiness_html = ""
    if readiness:
        readiness_html = (f"<h2>CRA readiness records</h2><p class=note>{esc(readiness['disclaimer'])}</p>"
                          + ("<p class=note>These records are demo data.</p>" if readiness.get("demo_data") else "")
                          + _table(["Checklist status", "Requirements"], [[esc(k), esc(v)] for k, v in sorted(readiness["checklist_counts"].items())])
                          + "<h3>Release blockers from the records</h3>" + _list(readiness["release_failures"][:100]))
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>{esc(result['product'].get('name'))} security evidence</title>
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<style>body{{font:15px/1.5 system-ui,sans-serif;max-width:1120px;margin:2rem auto;padding:0 1rem;color:#1b1f24}}
table{{border-collapse:collapse;width:100%;margin:.6rem 0}}th,td{{border-bottom:1px solid #dde1e6;padding:.35rem .5rem;text-align:left;vertical-align:top}}
th{{background:#f4f5f7}}.banner{{color:#fff;padding:.8rem 1rem;border-radius:4px;background:{color}}}.note{{color:#4a5158}}summary{{cursor:pointer}}</style></head><body>
<h1>{esc(result['product'].get('name'))} {esc(result['product'].get('version'))}</h1>
<div class=banner><strong>{esc(title)}</strong> (build mode)</div>
<p class=note>Release mode outcome: {esc(result['evaluation']['release']['outcome'])}. Source revision: {esc(result['source'].get('revision') or 'unknown')}{' (uncommitted changes)' if result['source'].get('dirty') else ''}. Findings are scanner matches and records, not verified root causes or proof of exploitability.</p>
<h2>Why this outcome</h2>
<h3>Incomplete</h3>{reasons(build['incomplete_reasons'])}
<h3>Policy violations ({len(build['policy_violations'])})</h3>{reasons(build['policy_violations'][:200])}
<h2>Findings ({len(findings)})</h2>
<p class=note>{min(len(findings), MAX_ROWS)} shown. result.json keeps every finding.</p>
{_table(['Vulnerability', 'Severity', 'Component', 'Shipped', 'Match confidence', 'Triage'], [_finding_row(item) for item in findings[:MAX_ROWS]])}
<h2>Inventory ({len(inventory['components'])} components)</h2>
<p class=note>Declared by the project, resolved for a build, observed in build outputs, and present in the shipped product are separate facts.</p>
{_table(['Component', 'Version', 'Ecosystem', 'Declared', 'Resolved', 'Observed', 'Shipped', 'Scope', 'Linkage', 'Configurations'], component_rows)}
<h2>Conflicts ({len(inventory['conflicts'])})</h2>{_list([f"{row['kind']}: {row['subject']}: {row['detail']} Values: {', '.join(map(str, row['values']))}" for row in inventory['conflicts']][:200])}
<h2>Coverage</h2>
{_table(['Source', 'Subject', 'Status', 'Reason'], [[esc(row.get('source')), esc(row.get('subject')), esc(row.get('status')), esc(row.get('reason'))] for row in inventory['coverage']['sources']])}
<p class=note>{esc(inventory['coverage']['scope_note'])}</p>
<h3>Components no vulnerability feed can match ({len(result.get('not_matchable') or [])})</h3>
<p class=note>Having no findings for these says nothing about them.</p>{_list([f"{row['name']} {row.get('version') or ''}" for row in result.get('not_matchable') or []])}
<h3>Limitations</h3>{_list(sorted({f"{row.get('subject')}: {row.get('message')}" for row in inventory['coverage']['limitations']}))}
<h2>Failures in our own tooling</h2>
<p class=note>These concern the scanning software and services, not the product.</p>
{reasons(result['tool_diagnostics'])}
{readiness_html}
<h2>Versions</h2>
{_table(['Tool', 'Version', 'Output schema'], versions)}
<p>Collector {esc(result['collector'].get('version'))}. Engine {esc(result['engine']['version'])}. Policy {esc(result['policy'].get('version'))} ({esc(result['policy'].get('sha256') or 'built in')}).
Vulnerability data built {esc(database.get('built'))}. KEV catalogue {esc(kev.get('catalog_version'))}, released {esc(kev.get('date_released'))}.</p>
<h2>Artifacts</h2>
{_table(['ID', 'Kind', 'Name', 'SHA-256', 'Digest', 'Shipped'], [[esc(row.get('id')), esc(row.get('kind')), esc(row.get('name')), esc(row.get('sha256')), esc(row.get('digest')), esc(row.get('shipped'))] for row in result['artifacts']])}
</body></html>
"""


def render_markdown(result):
    build, release = result["evaluation"]["build"], result["evaluation"]["release"]
    lines = [f"# {_md(result['product'].get('name'))} {_md(result['product'].get('version'))}", "",
             f"Build mode: **{OUTCOME_TEXT[build['outcome']][0]}**.", f"Release mode: **{OUTCOME_TEXT[release['outcome']][0]}**.", "",
             f"| Findings | KEV listed | Components | Conflicts |", "| --- | --- | --- | --- |",
             f"| {result['summary']['total']} | {result['summary']['kev']} | {result['inventory_summary']['components']} | {result['inventory_summary']['conflicts']} |", ""]
    if build["incomplete_reasons"]:
        lines += ["## Incomplete", ""] + [f"- `{_md(row['code'])}`: {_md(row['message'])}" for row in build["incomplete_reasons"][:30]] + [""]
    if build["policy_violations"]:
        lines += ["## Policy violations", ""] + [f"- `{_md(row['code'])}`: {_md(row['message'])}" for row in build["policy_violations"][:30]] + [""]
    return "\n".join(lines)


def _md(value):
    """Keep untrusted text from becoming markup in a CI job summary."""
    text = "" if value is None else str(value)
    return "".join("\\" + c if c in "\\`*_{}[]<>|#" else (" " if c in "\r\n" else c) for c in text)


def write_reports(result, inventory, destination):
    destination = Path(destination)
    (destination / "report.html").write_text(render_html(result, inventory), encoding="utf-8")
    (destination / "summary.md").write_text(render_markdown(result), encoding="utf-8")
