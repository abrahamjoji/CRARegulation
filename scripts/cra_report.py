#!/usr/bin/env python3
"""CRA readiness report generator.

Merges a CycloneDX SBOM (plus manual components), a Grype JSON scan,
an OpenVEX triage file and the CISA KEV catalogue into one HTML report
and one JSON summary for the technical file. Standard library only.

Usage:
  python scripts/cra_report.py --product product.json \
      --sbom out/sbom.cdx.json --manual sbom/manual-components.cdx.json \
      --scan out/scan.grype.json --vex vex/demo200.openvex.json \
      --risk risk/risk-assessment.json --register vuln/register.json \
      --kev out/kev.json --out out/cra-report.html --gate

--gate fails on problems that must never wait. --release-gate adds the checks
a product has to pass before it is placed on the market.
"""
import argparse
import datetime as dt
import html
import json
import sys
from pathlib import Path

import cra_checks as checks

DEADLINE = checks.APPLICATION_DATE
REPORTING_START = checks.REPORTING_START
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "negligible": 4, "unknown": 5}
MAX_FINDING_ROWS = 200  # the JSON summary always keeps every finding
MAX_ALERTS = 3
MAX_GATE_LINES = 50
STATUS_LABEL = {
    "needs_triage": "Needs triage",
    "under_investigation": "Investigating",
    "affected": "Affected",
    "not_affected": "Not affected",
    "fixed": "Fixed",
}
JUSTIFICATION = {
    "component_not_present": "Component not present",
    "vulnerable_code_not_present": "Vulnerable code not present",
    "vulnerable_code_not_in_execute_path": "Vulnerable code not in execute path",
    "vulnerable_code_cannot_be_controlled_by_adversary": "Cannot be controlled by an attacker",
    "inline_mitigations_already_exist": "Mitigations already in place",
}


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8")) if path else None


def esc(value):
    return html.escape(str(value), quote=True)


def components_from(bom, default_source):
    out = []
    for c in (bom or {}).get("components", []):
        props = {p.get("name"): p.get("value") for p in c.get("properties", [])}
        lic = ""
        for entry in c.get("licenses", []):
            item = entry.get("license", {})
            lic = entry.get("expression") or item.get("id") or item.get("name") or lic
        out.append({
            "name": c.get("name", "?"),
            "version": c.get("version", "?"),
            "type": c.get("type", "library"),
            "purl": c.get("purl", ""),
            "supplier": (c.get("supplier") or {}).get("name", ""),
            "license": lic,
            "source": props.get("cra:source", default_source),
            "note": props.get("cra:note", ""),
        })
    return out


def load_kev(path):
    """Return the catalogue's CVE IDs, or None if it is missing, unreadable or empty."""
    if not path:
        return None
    try:
        ids = {v.get("cveID") for v in load(path).get("vulnerabilities", [])} - {None}
    except (OSError, ValueError, AttributeError):
        return None
    return ids or None


def vex_index(vex):
    index = {}
    for st in (vex or {}).get("statements", []):
        vid = st.get("vulnerability", {}).get("name")
        products = [p.get("@id") for p in st.get("products", [])] or [None]
        for purl in products:
            index[(vid, purl)] = st
    return index


def build(args):
    product = load(args.product)
    comps = components_from(load(args.sbom), "auto")
    comps += components_from(load(args.manual), "manual") if args.manual else []
    seen, unique = set(), []
    for c in comps:
        key = c["purl"] or f'{c["name"]}@{c["version"]}'
        if key not in seen:
            seen.add(key)
            unique.append(c)
    comps = unique

    kev = load_kev(args.kev)
    kev_loaded = kev is not None
    kev = kev or set()
    vex = load(args.vex)
    vidx = vex_index(vex)
    vex_date = (vex or {}).get("timestamp")

    today = dt.date.fromisoformat(args.date) if args.date else dt.date.today()
    now = (dt.datetime.combine(today, dt.time(23, 59, 59), dt.timezone.utc) if args.date
           else dt.datetime.now(dt.timezone.utc))
    entries, register_problems = checks.validate_register(load(args.register))
    by_vuln = {e["vulnerability"]: e for e in entries if e.get("type") == "vulnerability" and checks.text(e.get("vulnerability"))}
    max_days = product.get("triage_policy", {}).get("max_investigation_days", checks.DEFAULT_MAX_INVESTIGATION_DAYS)

    scan = load(args.scan)
    scan_ok = isinstance(scan, dict) and "matches" in scan
    records = []
    for m in (scan or {}).get("matches") or []:
        vul, art = m.get("vulnerability", {}), m.get("artifact", {})
        scores = [c.get("metrics", {}).get("baseScore") for c in vul.get("cvss", [])]
        scores = [x for x in scores if x is not None]
        records.append({
            "id": vul.get("id"), "component": art.get("name"), "version": art.get("version"), "purl": art.get("purl"),
            "severity": (vul.get("severity") or "unknown").lower(), "score": max(scores) if scores else None,
            "fix": ", ".join(vul.get("fix", {}).get("versions", [])) or "none",
            "description": vul.get("description", ""), "url": vul.get("dataSource", ""), "source": "scanner",
        })
    # Vulnerabilities known from other sources count too, not only scanner matches (paras 233-234)
    scanned = {r["id"] for r in records}
    for vid, e in by_vuln.items():
        if vid not in scanned:
            records.append({
                "id": vid, "component": e.get("component", "?"), "version": e.get("version", "?"), "purl": e.get("purl"),
                "severity": (e.get("severity") or "unknown").lower(), "score": None, "fix": e.get("fix") or "none",
                "description": e.get("description", ""), "url": e.get("url", ""), "source": e.get("source", "other"),
            })

    findings = []
    for f in records:
        vid, purl = f["id"], f["purl"]
        st = vidx.get((vid, purl)) or vidx.get((vid, None))
        problem = checks.vex_problem(st) if st else ""
        status = st.get("status") if st and not problem else "needs_triage"
        started = checks.parse_time((st or {}).get("timestamp") or vex_date)
        entry = by_vuln.get(vid)
        exploited = (entry or {}).get("actively_exploited_in_product")
        f.update({
            "status": status,
            "justification": JUSTIFICATION.get(st.get("justification", ""), "") if st else "",
            "note": (st.get("impact_statement") or st.get("action_statement") or "") if st else "",
            "kev": vid in kev,
            "entry": entry,
            "exploited": exploited,
            "vex_problem": problem,
            "investigation_overdue": status == "under_investigation" and (
                started is None or (now - started).days > max_days),
        })
        # A KEV listing alone is not a reportable event: exploitation must be in this product (para 218)
        f["reporting_check"] = exploited is True or (
            f["kev"] and exploited is not False and status not in ("not_affected", "fixed"))
        f["open"] = status in checks.OPEN_STATUSES
        findings.append(f)
    findings.sort(key=lambda f: (not f["reporting_check"], not f["open"], SEV_ORDER.get(f["severity"], 9), f["id"]))

    for c in comps:
        c["findings"] = sum(1 for f in findings if f["purl"] == c["purl"])

    sbom = checks.sbom_report(comps)
    product_problems = checks.product_problems(product, today)
    part_1, part_2 = product["annex_i"]["part_1"], product["annex_i"]["part_2"]
    known_ids = {i["id"] for i in part_1 + part_2}
    ra = load(args.risk)
    risk_problems = checks.validate_risk_assessment(ra, known_ids)
    root = Path(args.evidence_root) if args.evidence_root else Path(args.product).resolve().parent
    rationales = checks.not_applicable_rationales(ra)
    blocking = sum(1 for f in findings if f["open"] and not (f["entry"] or {}).get("release_decision"))
    judge = lambda item: checks.evaluate_item(item, root, rationales, sbom["ok"], blocking)
    general = checks.general_requirement(ra, risk_problems, args.risk)
    part_1 = [judge(i) for i in [general] + part_1]
    part_2 = [judge(i) for i in part_2]
    items = part_1 + part_2

    checklist_pct = checks.score_checklist(items)
    decided = sum(1 for f in findings if f["status"] not in ("needs_triage", "under_investigation"))
    triage_pct = round(100 * decided / len(findings)) if findings else 100
    score = round(0.7 * checklist_pct + 0.3 * triage_pct)

    register = [{"entry": e, "clock": checks.reporting_clock(e, now)} for e in entries]
    return {
        "product": product,
        "components": comps,
        "findings": findings,
        "items": items,
        "part_1": part_1,
        "part_2": part_2,
        "generated": today.isoformat(),
        "days_left": (DEADLINE - today).days,
        "checklist_pct": checklist_pct,
        "triage_pct": triage_pct,
        "score": score,
        "open": sum(1 for f in findings if f["open"]),
        "untriaged": sum(1 for f in findings if f["status"] == "needs_triage"),
        "reporting": [f for f in findings if f["reporting_check"]],
        "counts": {s: sum(1 for i in items if i["effective"] == s) for s in checks.CHECKLIST_STATUSES},
        "sample": bool(args.sample),
        "kev_loaded": kev_loaded,
        "scan_ok": scan_ok,
        "sbom": sbom,
        "by_component": checks.component_summary(findings),
        "demo": bool(product.get("demo")),
        "duties": checks.duties(product, today),
        "risk": ra if isinstance(ra, dict) else None,
        "risk_problems": risk_problems,
        "product_problems": product_problems,
        "register": register,
        "register_problems": register_problems,
        "max_investigation_days": max_days,
    }


def pill(status):
    return f'<span class="pill s-{esc(status)}">{esc(STATUS_LABEL.get(status, status))}</span>'


CHECK_LABEL = {"met": "Met", "unverified": "Unverified", "partial": "Partial", "missing": "Missing", "not_applicable": "N/A"}


def check_rows(rows):
    out = []
    for r in rows:
        status = r["effective"]
        flag = f'<small class="flag">{esc(r["flag"])}</small>' if r.get("flag") else ""
        out.append(
            f'<li class="chk c-{status}"><span class="cid">{esc(r["id"])}</span>'
            f'<span class="creq">{esc(r["req"])}<small>{esc(r["evidence"])}</small>{flag}</span>'
            f'<span class="pill k-{status}">{CHECK_LABEL[status]}</span></li>'
        )
    return "\n".join(out)


def part_bar(rows):
    n = len(rows)
    seg = []
    for s in ("met", "unverified", "partial", "missing", "not_applicable"):
        k = sum(1 for r in rows if r["effective"] == s)
        if k:
            seg.append(f'<span class="seg k-{s}" style="flex:{k}" title="{k} {s}"></span>')
    met = sum(1 for r in rows if r["effective"] == "met")
    return f'<div class="bar">{"".join(seg)}</div><p class="barlbl">{met} of {n} met with evidence</p>'


def register_rows(register):
    rows = []
    for row in register:
        e, clock = row["entry"], row["clock"]
        name = e.get("vulnerability") or e.get("title") or e.get("id")
        exploited = {True: "Yes", False: "No"}.get(e.get("actively_exploited_in_product"), "Not assessed")
        if clock is None and e.get("actively_exploited_in_product") is None:
            steps = '<span class="pill st-due">Assess exploitation</span>'
        elif clock is None:
            steps = '<span class="dim">Nothing to report</span>'
        elif clock["exempt"]:
            steps = esc(clock["note"])
        else:
            steps = "".join(
                f'<div><span class="pill st-{esc(c["state"].replace(" ", "-"))}">{esc(c["state"])}</span> {esc(c["label"])} '
                f'<span class="mono dim small">{esc(c["due"] or c["waiting"])}</span></div>' for c in clock["steps"]
            ) + f'<div class="small dim">Users informed: {"yes" if clock["users_informed"] else "not yet"}</div>'
        upstream = (e.get("upstream") or {}).get("status", "not recorded").replace("_", " ")
        decision = (e.get("release_decision") or {}).get("decision", "none recorded").replace("_", " ")
        rows.append(
            f'<tr><td><code>{esc(e.get("id"))}</code><div class="desc">{esc(name)}</div></td>'
            f'<td>{esc(e.get("source") or e.get("type"))}</td><td>{esc(exploited)}</td><td>{steps}</td>'
            f'<td>{esc(upstream)}</td><td>{esc(decision)}</td></tr>'
        )
    return "".join(rows)


def render(d):
    p = d["product"]
    sev_cls = lambda s: f"sev-{s}"
    f_rows = []
    for f in d["findings"][:MAX_FINDING_ROWS]:
        flags = '<span class="tag kev">Known exploited</span>' if f["kev"] else ""
        detail = f["justification"] or ""
        if f["note"]:
            detail = f"{detail}. {f['note']}" if detail else f["note"]
        f_rows.append(
            f'<tr class="{sev_cls(f["severity"])}" data-status="{esc(f["status"])}" data-open="{int(f["open"])}">'
            f'<td class="stripe"><a href="{esc(f["url"])}">{esc(f["id"])}</a>{flags}'
            f'<div class="desc">{esc(f["description"])}</div></td>'
            f'<td><code>{esc(f["component"])}</code> <span class="mono dim">{esc(f["version"])}</span></td>'
            f'<td><span class="sev">{esc(f["severity"].title())}</span> <span class="mono dim">{esc(f["score"] or "")}</span></td>'
            f'<td class="mono">{esc(f["fix"])}</td>'
            f'<td>{pill(f["status"])}<div class="desc">{esc(detail)}</div></td></tr>'
        )
    c_rows = []
    for c in d["components"]:
        badge = f'<span class="tag warn">{c["findings"]}</span>' if c["findings"] else '<span class="dim">0</span>'
        src = '<span class="tag manual">Manual</span>' if c["source"] == "manual" else '<span class="dim">Auto</span>'
        note = f'<div class="desc">{esc(c["note"])}</div>' if c["note"] else ""
        c_rows.append(
            f'<tr><td><code>{esc(c["name"])}</code>{note}</td><td class="mono">{esc(c["version"])}</td>'
            f'<td>{esc(c["type"])}</td><td>{src}</td><td>{esc(c["license"])}</td>'
            f'<td class="mono dim small">{esc(c["purl"])}</td><td class="num">{badge}</td></tr>'
        )
    rep_html = ""
    for n, f in enumerate(d["reporting"][:MAX_ALERTS]):
        exploited = f["exploited"] is True
        headline = "is being exploited in this product" if exploited else "is on the CISA known-exploited list"
        advice = ("Report it through the ENISA Single Reporting Platform. The register below tracks the deadlines."
                  if exploited else
                  "A listing alone does not trigger a report. Assess promptly whether it is being exploited in this product, "
                  "and record the answer in the register. If it is, the clock runs from the moment you have reasonable certainty.")
        rep_html += f"""
    <section class="alert" aria-labelledby="rep-h{n}">
      <div class="alert-head">
        <p class="eyebrow">Reporting check · CRA Article 14</p>
        <h2 id="rep-h{n}">{esc(f["id"])} in <code>{esc(f["component"])} {esc(f["version"])}</code> {headline}</h2>
        <p>{advice} Status: {pill(f["status"])}</p>
      </div>
      <ol class="clock">
        <li><b>Within 24 h</b><span>Early warning: affected product, cross-border relevance</span></li>
        <li><b>Within 72 h</b><span>Notification: details, impact, mitigations so far</span></li>
        <li><b>14 days after fix</b><span>Final report: root cause, severity, corrective update</span></li>
      </ol>
      <p class="small dim">{"The scan data lists no upstream fix." if f["fix"] == "none" else f"Fix available upstream in {esc(f['fix'])}."}</p>
    </section>"""
    extra = d["reporting"][MAX_ALERTS:]
    if extra:
        codes = " ".join(f"<code>{esc(f['id'])}</code>" for f in extra)
        rep_html += f"""
    <section class="alert" aria-labelledby="rep-more">
      <div class="alert-head">
        <p class="eyebrow">Reporting check · CRA Article 14</p>
        <h2 id="rep-more">{len(extra)} more known-exploited findings to assess</h2>
        <p class="small">{codes}</p>
      </div>
    </section>"""
    shown = min(len(d["findings"]), MAX_FINDING_ROWS)
    truncated = (
        f'<p class="small dim" style="margin:0 0 10px">Showing the {shown} highest-priority of {len(d["findings"])} findings. '
        'Filters apply to these rows. Every finding is in <code>cra-summary.json</code>.</p>'
        if len(d["findings"]) > shown else ""
    )
    comp_rows = "".join(
        f'<tr><td><code>{esc(r["component"])}</code> <span class="mono dim">{esc(r["version"])}</span></td>'
        f'<td class="num">{r["total"]}</td><td class="num">{r["kev"]}</td><td class="num">{r["untriaged"]}</td>'
        f'<td class="num">{r["critical"]}</td><td class="num">{r["high"]}</td></tr>'
        for r in d["by_component"]
    )
    if d["sample"]:
        sample_banner = (
            '<div class="banner">Demo with curated sample data. The company and product are fictional. '
            'The CVE records are real, but this is a small hand-picked subset: a real scan of these versions finds far more.</div>'
        )
    elif d["demo"]:
        sample_banner = (
            '<div class="banner">Demo product. The company and product are fictional, and the triage decisions are illustrative. '
            'Findings come from a live scan of the declared component versions, and most are not triaged.</div>'
        )
    else:
        sample_banner = ""
    kev_banner = (
        "" if d["kev_loaded"] else
        '<div class="banner crit">The known-exploited check did not run: the KEV catalogue was missing, '
        'unreadable or empty. Reporting checks in this report are incomplete.</div>'
    )
    laws = "".join(f"<li>{esc(x)}</li>" for x in p.get("other_laws", []))
    a1, a2 = d["part_1"], d["part_2"]
    problems = d["risk_problems"] + d["product_problems"] + d["register_problems"]
    problem_html = ""
    if problems:
        problem_html = ('<section class="card" aria-labelledby="pr-h"><h2 id="pr-h">Data to fix before release</h2><ul class="problems">'
                        + "".join(f"<li>{esc(x)}</li>" for x in problems) + "</ul></section>")
    ra = d["risk"] or {}
    rdps = ra.get("remote_data_processing") if isinstance(ra.get("remote_data_processing"), dict) else {}
    rdps_text = {True: "Yes", False: "No"}.get(rdps.get("present"), "Not assessed")
    risks = ra.get("risks") if isinstance(ra.get("risks"), list) else []
    risk_rows = "".join(
        f'<tr><td><code>{esc(r.get("id"))}</code></td><td>{esc(r.get("description"))}</td><td>{esc(r.get("treatment"))}</td>'
        f'<td class="mono small">{esc(", ".join(map(str, r["requirements"])) if isinstance(r.get("requirements"), list) else "")}</td><td>{esc(r.get("status"))}</td></tr>'
        for r in risks if isinstance(r, dict))
    score_state = "good" if d["score"] >= 80 else "warn" if d["score"] >= 50 else "crit"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CRA Readiness Report {esc(p["product"])}</title>
<style>
:root {{
  /* Layout: report sheet, summary tiles first, then action, findings, Annex I, SBOM */
  --bg: #f4f5f7; --paper: #ffffff; --ink: #14202e; --muted: #5a6676; --line: #dde1e7;
  --accent: #1d4fa3; --accent-soft: #e6eefb;
  --crit: #b4232c; --crit-soft: #fbe9ea; --warn: #a15c00; --warn-soft: #fdf1df;
  --good: #1e7a46; --good-soft: #e3f4ea; --info-soft: #eef0f3;
  --display: system-ui, -apple-system, "Segoe UI", sans-serif;
  --body: system-ui, -apple-system, "Segoe UI", sans-serif;
  --mono: ui-monospace, "SFMono-Regular", Menlo, monospace;
  color-scheme: light;
}}
@media (prefers-color-scheme: dark) {{
  :root:not([data-theme="light"]) {{
    --bg: #0f141b; --paper: #161d27; --ink: #e6ebf2; --muted: #9aa6b6; --line: #2a3442;
    --accent: #7fa8f0; --accent-soft: #1b2a44;
    --crit: #f08a8f; --crit-soft: #3a1c20; --warn: #f0b45c; --warn-soft: #3a2b14;
    --good: #6fcf97; --good-soft: #17301f; --info-soft: #1f2732; color-scheme: dark;
  }}
}}
:root[data-theme="dark"] {{
  --bg: #0f141b; --paper: #161d27; --ink: #e6ebf2; --muted: #9aa6b6; --line: #2a3442;
  --accent: #7fa8f0; --accent-soft: #1b2a44;
  --crit: #f08a8f; --crit-soft: #3a1c20; --warn: #f0b45c; --warn-soft: #3a2b14;
  --good: #6fcf97; --good-soft: #17301f; --info-soft: #1f2732; color-scheme: dark;
}}
* {{ box-sizing: border-box; }}
body {{ margin: 0; background: var(--bg); color: var(--ink); font: 15px/1.55 var(--body); }}
.wrap {{ max-width: 1120px; margin: 0 auto; padding: 24px 20px 56px; display: grid; gap: 20px; }}
h1, h2, h3 {{ font-family: var(--display); text-wrap: balance; margin: 0; }}
h1 {{ font-size: 28px; font-weight: 600; letter-spacing: -0.01em; }}
h2 {{ font-size: 19px; font-weight: 600; }}
h3 {{ font-size: 15px; font-weight: 600; }}
a {{ color: var(--accent); }}
a:focus-visible, button:focus-visible {{ outline: 2px solid var(--accent); outline-offset: 2px; }}
code, .mono {{ font-family: var(--mono); font-size: 13px; }}
.dim {{ color: var(--muted); }} .small {{ font-size: 12.5px; }}
.banner {{ background: var(--accent-soft); color: var(--ink); border: 1px solid var(--line); border-radius: 8px; padding: 8px 14px; font-size: 13.5px; }}
.banner.crit {{ background: var(--crit-soft); border-color: var(--crit); }}
.card {{ background: var(--paper); border: 1px solid var(--line); border-radius: 10px; padding: 20px 22px; }}
.head {{ display: grid; grid-template-columns: 1fr auto; gap: 16px 24px; align-items: start; }}
.eyebrow {{ margin: 0 0 4px; font-size: 12px; letter-spacing: 0.06em; text-transform: uppercase; color: var(--muted); font-weight: 500; }}
.meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 10px 20px; margin: 16px 0 0; }}
.meta div {{ display: grid; gap: 2px; }} .meta dt {{ font-size: 12px; color: var(--muted); }} .meta dd {{ margin: 0; font-weight: 500; }}
.laws {{ margin: 12px 0 0; padding: 0; list-style: none; display: flex; flex-wrap: wrap; gap: 6px; }}
.laws li {{ font-size: 12.5px; background: var(--info-soft); border-radius: 999px; padding: 3px 10px; }}
.score {{ text-align: right; }}
.score .big {{ font: 600 52px/1 var(--display); font-variant-numeric: tabular-nums; }}
.score .big.good {{ color: var(--good); }} .score .big.warn {{ color: var(--warn); }} .score .big.crit {{ color: var(--crit); }}
.tiles {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 12px; }}
.tile {{ background: var(--paper); border: 1px solid var(--line); border-radius: 10px; padding: 14px 16px; }}
.tile .v {{ font: 600 28px/1.1 var(--display); font-variant-numeric: tabular-nums; }}
.tile .l {{ font-size: 13px; color: var(--muted); }}
.tile.hot {{ border-color: var(--crit); background: var(--crit-soft); }} .tile.hot .v {{ color: var(--crit); }}
.alert {{ background: var(--paper); border: 1px solid var(--crit); border-left: 6px solid var(--crit); border-radius: 0; padding: 18px 22px; display: grid; gap: 12px; }}
.alert p {{ margin: 6px 0 0; }}
.clock {{ list-style: none; margin: 0; padding: 0; display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; }}
.clock li {{ background: var(--crit-soft); border-radius: 8px; padding: 10px 12px; display: grid; gap: 2px; font-size: 13.5px; }}
.clock b {{ color: var(--crit); font-weight: 600; }}
.sec-head {{ display: flex; flex-wrap: wrap; justify-content: space-between; align-items: end; gap: 10px; margin-bottom: 12px; }}
.filters {{ display: flex; flex-wrap: wrap; gap: 6px; }}
.filters button {{ font: 500 13px var(--body); color: var(--ink); background: var(--paper); border: 1px solid var(--line); border-radius: 999px; padding: 5px 12px; cursor: pointer; }}
.filters button[aria-pressed="true"] {{ background: var(--accent); border-color: var(--accent); color: var(--paper); }}
.tablewrap {{ overflow-x: auto; }}
table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
th {{ text-align: left; font-size: 12px; font-weight: 500; color: var(--muted); padding: 8px 10px; border-bottom: 1px solid var(--line); white-space: nowrap; }}
td {{ padding: 10px; border-bottom: 1px solid var(--line); vertical-align: top; }}
td.num, th.num {{ text-align: right; }}
tr:last-child td {{ border-bottom: 0; }}
td.stripe {{ border-left: 4px solid var(--line); min-width: 260px; }}
tr.sev-critical td.stripe {{ border-left-color: var(--crit); }} tr.sev-high td.stripe {{ border-left-color: var(--warn); }}
tr.sev-critical .sev {{ color: var(--crit); font-weight: 600; }} tr.sev-high .sev {{ color: var(--warn); font-weight: 600; }}
.desc {{ font-size: 12.5px; color: var(--muted); margin-top: 4px; max-width: 60ch; }}
.pill {{ display: inline-block; font-size: 12px; font-weight: 500; border-radius: 999px; padding: 2px 9px; white-space: nowrap; }}
.s-needs_triage {{ background: var(--crit-soft); color: var(--crit); }}
.s-under_investigation, .s-affected {{ background: var(--warn-soft); color: var(--warn); }}
.s-not_affected, .s-fixed {{ background: var(--good-soft); color: var(--good); }}
.k-met {{ background: var(--good-soft); color: var(--good); }} .k-partial {{ background: var(--warn-soft); color: var(--warn); }} .k-missing {{ background: var(--crit-soft); color: var(--crit); }}
.k-unverified {{ background: var(--warn-soft); color: var(--warn); }} .k-not_applicable {{ background: var(--info-soft); color: var(--muted); }}
.st-overdue, .st-done-late {{ background: var(--crit-soft); color: var(--crit); }} .st-due, .st-waiting {{ background: var(--warn-soft); color: var(--warn); }} .st-done {{ background: var(--good-soft); color: var(--good); }}
.creq small.flag {{ color: var(--warn); }} .problems {{ margin: 10px 0 0; padding-left: 18px; font-size: 13.5px; }}
.tag {{ display: inline-block; font-size: 11.5px; font-weight: 500; border-radius: 4px; padding: 1px 6px; margin-left: 6px; }}
.tag.kev {{ background: var(--crit); color: var(--paper); }} .tag.warn {{ background: var(--warn-soft); color: var(--warn); margin: 0; }}
.tag.manual {{ background: var(--accent-soft); color: var(--accent); margin: 0; }}
.annex {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(420px, 1fr)); gap: 16px; }}
@media (max-width: 520px) {{ .annex {{ grid-template-columns: 1fr; }} .head {{ grid-template-columns: 1fr; }} .score {{ text-align: left; }} }}
.bar {{ display: flex; height: 8px; border-radius: 999px; overflow: hidden; background: var(--info-soft); margin-top: 10px; }}
.seg.k-met {{ background: var(--good); }} .seg.k-partial {{ background: var(--warn); }} .seg.k-missing {{ background: var(--crit); }} .seg.k-unverified {{ background: var(--warn); opacity: .55; }} .seg.k-not_applicable {{ background: var(--line); }}
.barlbl {{ margin: 6px 0 10px; font-size: 12.5px; color: var(--muted); }}
.chks {{ list-style: none; margin: 0; padding: 0; }}
.chk {{ display: grid; grid-template-columns: 62px 1fr auto; gap: 10px; padding: 9px 0; border-top: 1px solid var(--line); align-items: start; font-size: 13.5px; }}
.cid {{ font-family: var(--mono); font-size: 12.5px; color: var(--muted); }}
.creq small {{ display: block; color: var(--muted); font-size: 12px; }}
.pipeline {{ list-style: none; margin: 0; padding: 0; display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 8px; counter-reset: s; }}
.pipeline li {{ counter-increment: s; background: var(--info-soft); border-radius: 8px; padding: 10px 12px; font-size: 13px; }}
.pipeline li::before {{ content: counter(s) "  "; font-family: var(--mono); color: var(--accent); font-weight: 500; }}
footer {{ font-size: 12.5px; color: var(--muted); }}
@media (prefers-reduced-motion: no-preference) {{ .filters button {{ transition: background .15s, color .15s; }} }}
</style>
</head>
<body>
<main class="wrap">
  {sample_banner}
  {kev_banner}
  <header class="card head">
    <div>
      <p class="eyebrow">CRA readiness report · generated {esc(d["generated"])}</p>
      <h1>{esc(p["product"])}</h1>
      <dl class="meta">
        <div><dt>Manufacturer</dt><dd>{esc(p["manufacturer"])}</dd></div>
        <div><dt>Firmware</dt><dd class="mono">{esc(p["firmware_version"])} · {esc(p["build_id"])}</dd></div>
        <div><dt>CRA class</dt><dd>{esc(p["cra_class"])}</dd></div>
        <div><dt>Support period ends</dt><dd>{esc(p["support_period_end"])}</dd></div>
        <div><dt>Article 14 reporting</dt><dd>{esc(d["duties"]["reporting"])}</dd></div>
        <div><dt>Annex I duties</dt><dd>{esc(d["duties"]["annex_i"])}</dd></div>
      </dl>
      <ul class="laws">{laws}</ul>
    </div>
    <div class="score">
      <p class="eyebrow">Readiness score</p>
      <div class="big {score_state}">{d["score"]}<span style="font-size:24px">%</span></div>
      <p class="small dim">70% Annex I checklist ({d["checklist_pct"]}%)<br>30% findings decided ({d["triage_pct"]}%)<br>Readiness indicator, not proof of conformity</p>
    </div>
  </header>

  <section class="tiles" aria-label="Summary">
    <div class="tile"><div class="v">{len(d["components"])}</div><div class="l">Components in SBOM</div></div>
    <div class="tile{' hot' if d['open'] else ''}"><div class="v">{d["open"]}</div><div class="l">Findings needing action</div></div>
    <div class="tile{' hot' if d['reporting'] or not d['kev_loaded'] else ''}"><div class="v">{len(d["reporting"]) if d["kev_loaded"] else "n/a"}</div><div class="l">Known-exploited, reporting check</div></div>
    <div class="tile"><div class="v">{d["counts"]["met"]}/{sum(d["counts"].values()) - d["counts"]["not_applicable"]}</div><div class="l">Annex I requirements met with evidence ({d["counts"]["unverified"]} unverified)</div></div>
    <div class="tile"><div class="v">{d["days_left"]}</div><div class="l">Days until full CRA (11 Dec 2027)</div></div>
  </section>
  {rep_html}
  {problem_html}
  <section class="card" aria-labelledby="c-h">
    <h2 id="c-h">Findings by component</h2>
    <p class="small dim" style="margin:4px 0 12px">Where the work is. Known-exploited findings come first.</p>
    <div class="tablewrap"><table>
      <thead><tr><th>Component</th><th class="num">Findings</th><th class="num">Known exploited</th><th class="num">Untriaged</th><th class="num">Critical</th><th class="num">High</th></tr></thead>
      <tbody>{comp_rows or '<tr><td colspan="6" class="dim">No findings.</td></tr>'}</tbody>
    </table></div>
  </section>

  <section class="card" aria-labelledby="f-h">
    <div class="sec-head">
      <div><h2 id="f-h">Vulnerability findings</h2><p class="small dim" style="margin:4px 0 0">Scanner matches and register entries, with VEX triage. Not-affected findings keep their written justification as evidence.</p></div>
      <div class="filters" role="group" aria-label="Filter findings">
        <button type="button" id="flt-all" data-f="all" aria-pressed="true">All {len(d["findings"])}</button>
        <button type="button" id="flt-open" data-f="open" aria-pressed="false">Needs action {d["open"]}</button>
        <button type="button" id="flt-triage" data-f="needs_triage" aria-pressed="false">Untriaged {d["untriaged"]}</button>
        <button type="button" id="flt-na" data-f="not_affected" aria-pressed="false">Not affected</button>
      </div>
    </div>
    {truncated}
    <div class="tablewrap"><table id="findings">
      <thead><tr><th>Vulnerability</th><th>Component</th><th>Severity</th><th>Fixed in</th><th>VEX status</th></tr></thead>
      <tbody>{"".join(f_rows)}</tbody>
    </table></div>
  </section>

  <section class="card" aria-labelledby="v-h">
    <h2 id="v-h">Vulnerability register and Article 14 clock</h2>
    <p class="small dim" style="margin:4px 0 12px">Deadlines run from when the manufacturer has reasonable certainty of exploitation or a severe incident. Inform impacted users as well.</p>
    <div class="tablewrap"><table>
      <thead><tr><th>Entry</th><th>Source</th><th>Exploited in product</th><th>Reporting</th><th>Upstream</th><th>Release decision</th></tr></thead>
      <tbody>{register_rows(d["register"]) or '<tr><td colspan="6" class="dim">No register supplied or no entries.</td></tr>'}</tbody>
    </table></div>
  </section>

  <section class="card" aria-labelledby="r-h">
    <h2 id="r-h">Cybersecurity risk assessment</h2>
    <p class="small dim" style="margin:4px 0 12px">Version {esc(ra.get("version", "none"))}, dated {esc(ra.get("date", "n/a"))}. Remote data processing: {esc(rdps_text)}. Summary of the assessment supplied for this build.</p>
    <div class="tablewrap"><table>
      <thead><tr><th>Risk</th><th>Description</th><th>Treatment</th><th>Requirements</th><th>Status</th></tr></thead>
      <tbody>{risk_rows or '<tr><td colspan="5" class="dim">No risk assessment supplied.</td></tr>'}</tbody>
    </table></div>
  </section>

  <section class="card" aria-labelledby="a-h">
    <h2 id="a-h">Annex I essential requirements</h2>
    <p class="small dim" style="margin:4px 0 0">Claims are checked: "Met" needs a linked evidence file, and "N/A" needs a reason in the risk assessment. A file's existence is checked, not its content. Part I covers the product, Part II covers vulnerability handling.</p>
    <div class="annex" style="margin-top:14px">
      <div><h3>Part I · Product properties</h3>{part_bar(a1)}<ul class="chks">{check_rows(a1)}</ul></div>
      <div><h3>Part II · Vulnerability handling</h3>{part_bar(a2)}<ul class="chks">{check_rows(a2)}</ul></div>
    </div>
  </section>

  <section class="card" aria-labelledby="s-h">
    <h2 id="s-h">Software bill of materials</h2>
    <p class="small dim" style="margin:4px 0 12px">CycloneDX. Manual entries cover components the scanner cannot see. {len(d["sbom"]["no_version"])} with no version, {len(d["sbom"]["no_supplier"])} with no supplier.</p>
    <div class="tablewrap"><table>
      <thead><tr><th>Component</th><th>Version</th><th>Type</th><th>Source</th><th>License</th><th>Package URL</th><th class="num">Findings</th></tr></thead>
      <tbody>{"".join(c_rows)}</tbody>
    </table></div>
  </section>

  <section class="card" aria-labelledby="p-h">
    <h2 id="p-h">How this report was produced</h2>
    <ol class="pipeline" style="margin-top:12px">
      <li>SBOM by Syft + manual list</li><li>CVE match by Grype</li>
      <li>Known-exploited check against CISA KEV</li><li>Triage in OpenVEX</li><li>Register, risk assessment and evidence checks</li><li>Report and JSON evidence archived per release</li>
    </ol>
    <p class="small dim" style="margin:12px 0 0">Evidence: the SBOM, scan, VEX file, register, risk assessment and <code>cra-summary.json</code>. The manufacturer remains responsible for the EU declaration of conformity.</p>
  </section>
  <footer>Security contact: {esc(p["security_contact"])} · CRA reporting duty applies since {REPORTING_START.isoformat()} · Full application {DEADLINE.isoformat()}</footer>
</main>
<script>
(function () {{
  var buttons = document.querySelectorAll('.filters button');
  var rows = document.querySelectorAll('#findings tbody tr');
  function apply(f) {{
    rows.forEach(function (r) {{
      var show = f === 'all' || (f === 'open' ? r.dataset.open === '1' : r.dataset.status === f);
      r.hidden = !show;
    }});
    buttons.forEach(function (b) {{ b.setAttribute('aria-pressed', String(b.dataset.f === f)); }});
  }}
  buttons.forEach(function (b) {{ b.addEventListener('click', function () {{ apply(b.dataset.f); }}); }});
}})();
</script>
</body>
</html>"""


def main():
    ap = argparse.ArgumentParser(description="Generate a CRA readiness report")
    ap.add_argument("--product", required=True)
    ap.add_argument("--sbom", required=True)
    ap.add_argument("--manual")
    ap.add_argument("--scan", required=True)
    ap.add_argument("--vex")
    ap.add_argument("--kev")
    ap.add_argument("--risk", help="Cybersecurity risk assessment JSON")
    ap.add_argument("--register", help="Vulnerability and incident register JSON")
    ap.add_argument("--evidence-root", help="Folder that evidence_refs are relative to (default: folder of --product)")
    ap.add_argument("--out", default="out/cra-report.html")
    ap.add_argument("--summary", default="out/cra-summary.json")
    ap.add_argument("--date", help="Report date YYYY-MM-DD (default: today)")
    ap.add_argument("--sample", action="store_true", help="Show the sample-data banner")
    ap.add_argument("--gate", action="store_true",
                    help="Exit 2 on problems that must never wait: unusable inputs, untriaged known-exploited findings, rejected VEX decisions, overdue investigations or Article 14 steps")
    ap.add_argument("--release-gate", action="store_true",
                    help="Everything in --gate, plus the checks a product must pass before it is placed on the market")
    args = ap.parse_args()

    d = build(args)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(render(d), encoding="utf-8")
    summary = {k: d[k] for k in ("generated", "score", "checklist_pct", "triage_pct", "open", "untriaged", "days_left", "counts", "kev_loaded", "duties", "sbom")}
    summary["product"] = {k: d["product"][k] for k in ("product", "firmware_version", "build_id")}
    summary["reporting_checks"] = [f["id"] for f in d["reporting"]]
    summary["findings"] = [{k: f[k] for k in ("id", "component", "version", "severity", "status", "kev", "exploited", "source")} for f in d["findings"]]
    summary["checklist"] = [{k: i.get(k, "") for k in ("id", "status", "effective", "flag")} for i in d["items"]]
    summary["register"] = [{"id": r["entry"].get("id"), "clock": r["clock"]} for r in d["register"]]
    summary["by_component"] = d["by_component"]
    summary["problems"] = d["risk_problems"] + d["product_problems"] + d["register_problems"]
    Path(args.summary).parent.mkdir(parents=True, exist_ok=True)
    Path(args.summary).write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(f"CRA readiness {d['score']}% | {len(d['components'])} components | "
          f"{d['open']} findings need action | {d['untriaged']} untriaged | "
          f"{len(d['reporting'])} reporting check(s)")
    for r in d["by_component"][:5]:
        print(f"  {r['component']} {r['version']}: {r['total']} findings, {r['kev']} known exploited, {r['untriaged']} untriaged")
    print(f"Report: {args.out}\nSummary: {args.summary}")

    if args.gate or args.release_gate:
        failures = checks.gate_failures(d, args.release_gate)
        if failures:
            print(f"GATE FAILED with {len(failures)} problem(s):")
            for failure in failures[:MAX_GATE_LINES]:
                print(f"  - {failure}")
            if len(failures) > MAX_GATE_LINES:
                print(f"  ... and {len(failures) - MAX_GATE_LINES} more; see the summary file")
            sys.exit(2)
        print("Release gate passed." if args.release_gate else "Gate passed.")


if __name__ == "__main__":
    main()
