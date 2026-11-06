"""Rules behind the CRA readiness score and CI gate. Standard library only.

Paragraph numbers refer to the Commission guidance on the CRA, C(2026) 5252 annex.
This code checks that evidence and decisions exist and are consistent. It cannot
judge whether a decision is right; the manufacturer stays responsible for that.
"""
import calendar
import datetime as dt
from pathlib import Path

REPORTING_START = dt.date(2026, 9, 11)
APPLICATION_DATE = dt.date(2027, 12, 11)
MIN_SUPPORT_YEARS = 5
# The guidance asks for "prompt action" and sets no number of days (para 214).
# This default is a project policy, overridable in product.json.
DEFAULT_MAX_INVESTIGATION_DAYS = 14

CHECKLIST_STATUSES = ("met", "unverified", "partial", "missing", "not_applicable")
WEIGHT = {"met": 1.0, "unverified": 0.5, "partial": 0.5, "missing": 0.0}
OPEN_STATUSES = ("needs_triage", "under_investigation", "affected")
SOURCES = ("scanner", "kev", "public_database", "researcher", "customer", "internal_test", "media", "other")
UPSTREAM = ("pending", "reported", "maintainer_aware", "no_maintainer", "not_required")
DECISIONS = ("fix_before_release", "release_with_documented_risk")
DECISION_FIELDS = ("severity", "exploitability", "impact", "rationale", "decided_by", "date")


def parse_time(value):
    """Parse YYYY-MM-DD or an ISO 8601 time into an aware UTC datetime, or return None."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=dt.timezone.utc) if parsed.tzinfo is None else parsed.astimezone(dt.timezone.utc)


def parse_day(value):
    parsed = parse_time(value)
    return parsed.date() if parsed else None


def add_month(moment):
    year = moment.year + (moment.month == 12)
    month = moment.month % 12 + 1
    return moment.replace(year=year, month=month, day=min(moment.day, calendar.monthrange(year, month)[1]))


def add_years(day, years):
    try:
        return day.replace(year=day.year + years)
    except ValueError:  # 29 February
        return day.replace(year=day.year + years, day=28)


def text(value):
    return isinstance(value, str) and bool(value.strip())


# Risk assessment (Article 13(2), guidance section 7)

def validate_risk_assessment(ra, known_ids):
    if ra is None:
        return ["no risk assessment supplied (Article 13(2))"]
    if not isinstance(ra, dict):
        return ["risk assessment is not a JSON object"]
    problems = [f"risk assessment: '{key}' is empty" for key in
                ("version", "date", "assessor", "intended_purpose", "foreseeable_use", "environment", "expected_use_time")
                if not text(ra.get(key))]
    rdps = ra.get("remote_data_processing")
    if not isinstance(rdps, dict) or not isinstance(rdps.get("present"), bool) or not text(rdps.get("rationale")):
        problems.append("risk assessment: remote_data_processing needs 'present' (true/false) and a 'rationale' (section 8)")
    risks = ra.get("risks")
    if not isinstance(risks, list) or not risks:
        problems.append("risk assessment: no risks listed")
        risks = []
    seen = set()
    for risk in risks:
        rid = risk.get("id", "?") if isinstance(risk, dict) else "?"
        if not isinstance(risk, dict) or not all(text(risk.get(k)) for k in ("id", "description", "treatment")):
            problems.append(f"risk {rid}: needs id, description and treatment")
            continue
        if rid in seen:
            problems.append(f"risk {rid}: duplicate id")
        seen.add(rid)
        if risk.get("status") not in ("open", "treated"):
            problems.append(f"risk {rid}: status must be open or treated")
        reqs = risk.get("requirements")
        if not isinstance(reqs, list) or not reqs:
            problems.append(f"risk {rid}: list the Annex I requirements that treat it")
        else:
            problems += [f"risk {rid}: unknown requirement {r}" for r in reqs if str(r) not in known_ids]
    applicability = ra.get("applicability", [])
    if not isinstance(applicability, list):
        problems.append("risk assessment: applicability must be a list")
        applicability = []
    applicable_seen = set()
    for entry in applicability:
        req = entry.get("requirement") if isinstance(entry, dict) else None
        if str(req) not in known_ids:
            problems.append(f"applicability: unknown requirement {req}")
        if str(req) in applicable_seen:
            problems.append(f"applicability: duplicate requirement {req}")
        applicable_seen.add(str(req))
        if not isinstance(entry, dict) or not isinstance(entry.get("applies"), bool):
            problems.append(f"applicability {req}: applies must be true or false")
    return problems


def not_applicable_rationales(ra):
    """Requirements the risk assessment rules out, with a written reason (para 33)."""
    out = {}
    if isinstance(ra, dict):
        entries = ra.get("applicability", [])
        for entry in entries if isinstance(entries, list) else []:
            if (isinstance(entry, dict) and isinstance(entry.get("requirement"), str)
                    and entry["requirement"].startswith("I.2(")
                    and entry.get("applies") is False and text(entry.get("rationale"))):
                out[entry["requirement"]] = entry["rationale"]
    return out


def general_requirement(ra, problems, path):
    """Part I (1) is deemed met when identified risks are treated by the other requirements (para 166)."""
    item = {"id": "I.1", "req": "Appropriate level of cybersecurity based on the risks", "computed": True, "evidence_refs": []}
    if ra is None:
        return {**item, "status": "missing", "evidence": "Computed: no risk assessment"}
    if problems:
        return {**item, "status": "partial", "evidence": "Computed: risk assessment is incomplete"}
    still_open = [r["id"] for r in ra["risks"] if r["status"] == "open"]
    if still_open:
        return {**item, "status": "partial", "evidence": f"Computed: open risks {', '.join(still_open)}"}
    return {**item, "status": "met", "evidence": "Computed: all assessed risks are treated", "evidence_refs": [str(path)]}


# Checklist evidence

def evidence_exists(ref, root):
    """True only for a non-empty file inside the evidence root."""
    if not text(ref):
        return False
    root = Path(root).resolve()
    target = (root / ref).resolve()
    return target.is_relative_to(root) and target.is_file() and target.stat().st_size > 0


def evaluate_item(item, root, rationales, sbom_ok, blocking_findings):
    """Return the item with a checked 'effective' status and the reason for any change."""
    out = dict(item)
    status = item.get("status")
    if status not in ("met", "partial", "missing", "not_applicable"):
        return {**out, "effective": "missing", "flag": f"Unknown status '{status}'"}
    if status == "not_applicable":
        reason = rationales.get(item.get("id"))
        if reason:
            return {**out, "effective": "not_applicable", "flag": f"Risk assessment: {reason}"}
        return {**out, "effective": "missing", "flag": "Marked not applicable, but the risk assessment gives no reason"}
    if status != "met" or item.get("computed"):
        return {**out, "effective": status, "flag": ""}
    if item.get("id") == "I.2(a)" and blocking_findings:
        return {**out, "effective": "partial", "flag": f"Claimed met, but {blocking_findings} finding(s) are open with no release decision"}
    if item.get("id") == "II.1":
        if sbom_ok:
            return {**out, "effective": "met", "flag": "Checked by this pipeline run"}
        return {**out, "effective": "partial", "flag": "Claimed met, but the SBOM is empty or has components with no version"}
    refs = item.get("evidence_refs") or []
    missing = [r for r in refs if not evidence_exists(r, root)]
    if not refs:
        return {**out, "effective": "unverified", "flag": "Claimed met, with no evidence file linked"}
    if missing:
        return {**out, "effective": "unverified", "flag": f"Evidence file not found: {', '.join(map(str, missing))}"}
    return {**out, "effective": "met", "flag": ""}


def score_checklist(items):
    scored = [i for i in items if i["effective"] != "not_applicable"]
    if not scored:
        return 0
    return round(100 * sum(WEIGHT[i["effective"]] for i in scored) / len(scored))


# Product data

def product_problems(product, today):
    problems = [f"product: {field} is empty" for field in
                ("product", "manufacturer", "firmware_version", "build_id", "security_contact")
                if field in product and not text(product.get(field))]
    if not text(product.get("classification_rationale")):
        problems.append("product: classification_rationale is empty; record the core functionality behind the CRA class (para 139)")
    market = product.get("market")
    if not isinstance(market, dict):
        return problems + ["product: 'market' is missing"]
    placed = market.get("first_placed")
    if placed is not None and parse_day(placed) is None:
        problems.append(f"product: market.first_placed is not a date: {placed}")
    after = market.get("units_after_application")
    if not isinstance(after, bool):
        problems.append("product: market.units_after_application must be true or false")
    end = parse_day(product.get("support_period_end"))
    if end is None:
        problems.append("product: support_period_end is not a date")
    elif after is True or placed is None:
        start = max(parse_day(placed) or today, APPLICATION_DATE)
        if end < add_years(start, MIN_SUPPORT_YEARS) and not text(product.get("support_period_rationale")):
            problems.append(f"product: support ends {end}, under {MIN_SUPPORT_YEARS} years from {start}; "
                            "record why expected use is shorter in support_period_rationale (para 128)")
    return problems


def duties(product, today):
    """Which duties apply, given when units reach the market (paras 33, 210)."""
    market = product.get("market") if isinstance(product.get("market"), dict) else {}
    placed = parse_day(market.get("first_placed"))
    after = market.get("units_after_application")
    if placed is None:
        reporting = "Applies from the first placement on the market"
    elif today < REPORTING_START:
        reporting = f"Applies from {REPORTING_START}"
    else:
        reporting = "Applies now, and continues after support ends"
    if after is True:
        annex = f"Applies to units placed on the market from {APPLICATION_DATE}"
    elif after is False:
        annex = f"Not required while no units are placed on the market from {APPLICATION_DATE}"
    elif placed is None:
        annex = f"Applies to units placed on the market from {APPLICATION_DATE}"
    else:
        annex = "Unknown: set market.units_after_application"
    return {"reporting": reporting, "annex_i": annex}


def component_summary(findings):
    """Findings per component, worst first, so large scans stay readable."""
    rows = {}
    for f in findings:
        row = rows.setdefault((f["component"], f["version"]), {
            "component": f["component"], "version": f["version"], "total": 0, "kev": 0,
            "untriaged": 0, "critical": 0, "high": 0})
        row["total"] += 1
        row["kev"] += bool(f["kev"])
        row["untriaged"] += f["status"] == "needs_triage"
        row["critical"] += f["severity"] == "critical"
        row["high"] += f["severity"] == "high"
    return sorted(rows.values(), key=lambda r: (-r["kev"], -r["total"], str(r["component"])))


def sbom_report(components):
    no_version = [c["name"] for c in components if c["version"] in ("", "?", None, "UNKNOWN")]
    no_supplier = [c["name"] for c in components if not c["supplier"]]
    return {"components": len(components), "no_version": no_version, "no_supplier": no_supplier,
            "ok": bool(components) and not no_version}


# VEX decisions

def vex_problem(statement):
    """Why a statement cannot count as a triage decision, or '' if it can."""
    status = statement.get("status")
    if status == "not_affected" and not (text(statement.get("justification")) and text(statement.get("impact_statement"))):
        return "not_affected needs a justification and a written impact_statement (para 235)"
    if status == "not_affected" and statement.get("justification") not in (
        "component_not_present", "vulnerable_code_not_present", "vulnerable_code_not_in_execute_path",
        "vulnerable_code_cannot_be_controlled_by_adversary", "inline_mitigations_already_exist",
    ):
        return "not_affected has an unknown OpenVEX justification"
    if status == "affected" and not text(statement.get("action_statement")):
        return "affected needs an action_statement"
    if status not in ("not_affected", "affected", "fixed", "under_investigation"):
        return f"unknown VEX status '{status}'"
    return ""


# Vulnerability register and Article 14 clock

def validate_register(doc):
    if doc is None:
        return [], []
    entries = doc.get("entries") if isinstance(doc, dict) else None
    if not isinstance(entries, list):
        return [], ["register: 'entries' must be a list"]
    problems, seen, identities = [], set(), set()
    for entry in entries:
        if not isinstance(entry, dict) or not text(entry.get("id")):
            problems.append("register: every entry needs an id")
            continue
        eid = entry["id"]
        if eid in seen:
            problems.append(f"register {eid}: duplicate id")
        seen.add(eid)
        kind = entry.get("type")
        if kind not in ("vulnerability", "incident"):
            problems.append(f"register {eid}: type must be vulnerability or incident")
        if kind == "vulnerability" and not text(entry.get("vulnerability")):
            problems.append(f"register {eid}: name the vulnerability")
        if kind == "incident" and not text(entry.get("aware_at")):
            problems.append(f"register {eid}: an incident needs aware_at")
        if kind == "vulnerability" and entry.get("source") not in SOURCES:
            problems.append(f"register {eid}: source must be one of {', '.join(SOURCES)}")
        for key in ("first_seen", "aware_at", "early_warning_at", "notification_at", "fix_available_at", "final_report_at", "users_informed_at"):
            if entry.get(key) is not None and parse_time(entry[key]) is None:
                problems.append(f"register {eid}: {key} is not a date or time")
        if entry.get("actively_exploited_in_product") is True and not text(entry.get("aware_at")):
            problems.append(f"register {eid}: exploited in the product, so record aware_at, which starts the clock (para 213)")
        exploited = entry.get("actively_exploited_in_product")
        if exploited is not None and not isinstance(exploited, bool):
            problems.append(f"register {eid}: actively_exploited_in_product must be true, false or null")
        if kind == "vulnerability":
            purl = entry.get("purl")
            if purl is not None and (not text(purl) or not purl.startswith("pkg:")):
                problems.append(f"register {eid}: purl must be a package URL")
            identity = (str(entry.get("vulnerability")), str(purl or ""))
            if identity in identities:
                problems.append(f"register {eid}: duplicate vulnerability/component identity")
            identities.add(identity)
        aware = parse_time(entry.get("aware_at"))
        if aware:
            for key in ("early_warning_at", "notification_at", "final_report_at", "users_informed_at"):
                event = parse_time(entry.get(key))
                if event and event < aware:
                    problems.append(f"register {eid}: {key} precedes awareness")
        upstream = entry.get("upstream")
        if upstream is not None and (not isinstance(upstream, dict) or upstream.get("status") not in UPSTREAM):
            problems.append(f"register {eid}: upstream.status must be one of {', '.join(UPSTREAM)}")
            entry["upstream"] = None
        decision = entry.get("release_decision")
        if decision is not None:
            if not isinstance(decision, dict) or decision.get("decision") not in DECISIONS:
                problems.append(f"register {eid}: release_decision.decision must be one of {', '.join(DECISIONS)}")
                entry["release_decision"] = None
            else:
                problems += [f"register {eid}: release_decision.{k} is empty" for k in DECISION_FIELDS if not text(decision.get(k))]
    return [e for e in entries if isinstance(e, dict) and text(e.get("id"))], problems


def reporting_clock(entry, now):
    """Article 14 steps for one register entry, or None if nothing is reportable."""
    reportable = entry.get("type") == "incident" or entry.get("actively_exploited_in_product") is True
    aware = parse_time(entry.get("aware_at"))
    if not reportable or aware is None:
        return None
    if aware.date() < REPORTING_START:
        return {"exempt": True, "steps": [], "users_informed": True,
                "note": f"Became aware before {REPORTING_START}, so no retroactive report is required (para 217)"}

    def step(label, due, done_key, waiting=""):
        done = parse_time(entry.get(done_key))
        if done:
            state = "done late" if due and done > due else "done"
        elif due is None:
            state = "waiting"
        else:
            state = "overdue" if now > due else "due"
        return {"label": label, "due": due.isoformat() if due else "", "done": done.isoformat() if done else "",
                "state": state, "waiting": waiting if due is None else ""}

    notified = parse_time(entry.get("notification_at"))
    if entry.get("type") == "incident":
        final = step("Final report (1 month after notification)", add_month(notified) if notified else None,
                     "final_report_at", "Starts when the 72-hour notification is submitted")
    else:
        fix = parse_time(entry.get("fix_available_at"))
        final = step("Final report (14 days after a fix)", fix + dt.timedelta(days=14) if fix else None,
                     "final_report_at", "Starts when a fix or mitigation is available")
    return {"exempt": False, "note": "", "users_informed": bool(parse_time(entry.get("users_informed_at"))), "steps": [
        step("Early warning (24 hours)", aware + dt.timedelta(hours=24), "early_warning_at"),
        step("Notification (72 hours)", aware + dt.timedelta(hours=72), "notification_at"),
        final,
    ]}


# Gate

def gate_failures(d, release):
    """Reasons to fail the build. The first group always applies; the second only for a release."""
    fails = []
    if not d["kev_loaded"]:
        fails.append("the KEV catalogue is missing, unreadable or empty, so the known-exploited check did not run")
    if not d["scan_ok"]:
        fails.append("the scan file has no 'matches' section, so the vulnerability scan did not run")
    if not d["components"]:
        fails.append("the SBOM has no components, so there was nothing to scan")
    blocked = [f["id"] for f in d["findings"] if f["kev"] and f["status"] == "needs_triage"]
    if blocked:
        fails.append(f"known-exploited vulnerabilities without triage: {', '.join(blocked)}")
    fails += [f"VEX decision rejected for {f['id']}: {f['vex_problem']}" for f in d["findings"] if f["vex_problem"]]
    fails += [f"investigation of {f['id']} is older than the {d['max_investigation_days']}-day limit" for f in d["findings"] if f["investigation_overdue"]]
    fails += d["register_problems"]
    for row in d["register"]:
        clock = row["clock"]
        for step in (clock or {}).get("steps", []):
            if step["state"] == "overdue":
                fails.append(f"Article 14 overdue for {row['entry']['id']}: {step['label']} was due {step['due']}")
    if not release:
        return fails

    fails += d["risk_problems"] + d["product_problems"]
    fails += [f"{i['id']} is incomplete: {i['effective']}" for i in d["items"]
              if i["effective"] in ("missing", "partial")]

    if d["sbom"]["no_version"]:
        fails.append(f"SBOM components with no version cannot be matched to CVEs: {', '.join(d['sbom']['no_version'])}")
    fails += [f"not triaged: {f['id']}" for f in d["findings"] if f["status"] == "needs_triage"]
    for f in d["findings"]:
        if not f["open"]:
            continue
        entry = f["entry"] or {}
        if (entry.get("release_decision") or {}).get("decision") == "fix_before_release":
            fails.append(f"open finding {f['id']} must be fixed before release according to its release decision")
        if not entry.get("release_decision"):
            fails.append(f"no recorded release decision for open finding {f['id']} (para 237)")
        if f["kev"] and not isinstance(entry.get("actively_exploited_in_product"), bool):
            fails.append(f"{f['id']} is known exploited: record whether it is exploited in this product (para 218)")
        if f["status"] == "affected" and (entry.get("upstream") or {}).get("status", "pending") == "pending":
            fails.append(f"{f['id']}: record the upstream reporting status (Article 13(6))")
    for row in d["register"]:
        if row["clock"] and not row["clock"]["users_informed"]:
            fails.append(f"{row['entry']['id']}: impacted users not yet informed (Article 14(8))")
    fails += [f"{i['id']} is marked met without evidence: {i['flag']}" for i in d["items"] if i["effective"] == "unverified"]
    return fails
