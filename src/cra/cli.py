"""The cra command. Exit codes: see docs/CLI.md and cra.common.errors."""
import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .common.config import load_config
from .common.errors import EXIT_CONFIG, EXIT_INCOMPLETE, EXIT_OPERATIONAL, EXIT_PASSED, CraError, OperationalError, UntrustedInputError
from .common.safety import redact_text, write_json


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"cra: configuration error: {message}", file=sys.stderr)
        raise SystemExit(EXIT_CONFIG)


def _emit(args, payload, text):
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(text)


def cmd_prepare(args):
    from .collector.prepare import prepare
    config = load_config(args.config)
    results = prepare(config)
    write_json(config.output_dir / "prepare.json", {"schema_version": "cra.prepare/1", "results": results})
    lines = [f"{row['configuration']}: {row['status']}" + (f". {row['note']}" if row.get("note") else "") for row in results]
    _emit(args, results, "\n".join(lines) or "No CMake build directories are configured.")
    return EXIT_PASSED


def cmd_collect(args):
    from .collector.collect import collect
    config = load_config(args.config)
    out, destination = collect(config, args.out)
    gaps = [row for row in out["sources"] if row["status"] not in ("complete", "not_configured")]
    text = [f"Collected {len(out['observations'])} observations from {len(out['sources'])} sources into {destination}."]
    text += [f"  {row['source']} {row['subject']}: {row['status']}: {row['reason']}" for row in gaps]
    _emit(args, {"destination": str(destination), "sources": out["sources"]}, "\n".join(text))
    return EXIT_INCOMPLETE if any(row.get("required", True) for row in gaps) else EXIT_PASSED


def cmd_analyze(args):
    config = load_config(args.config)
    collection = Path(args.collection or config.output_dir / "collection")
    destination = Path(args.out or config.output_dir / "analysis")
    if args.hosted:
        from .collector.hosted_client import analyze_hosted
        return analyze_hosted(config, collection, destination, args)
    try:
        from .engine.analyze import run_analysis
    except ImportError as exc:
        raise OperationalError("engine_not_included", "This distribution has no local analysis engine. Use `cra analyze --hosted`.") from exc
    if not (collection / "collection.json").is_file():
        raise CraError("collection_missing", f"No collection at {collection}. Run `cra collect` first.", EXIT_INCOMPLETE)
    if config.analysis.kev is None and args.kev:
        config.analysis.kev = Path(args.kev).resolve()
    result = run_analysis(collection, config.analysis, config.tools, destination, kev_path=Path(args.kev).resolve() if args.kev else None)
    summary = result["summary"]
    _emit(args, {"destination": str(destination), "scan_status": result["scan_status"], "summary": summary},
          f"Analysis {result['scan_status']}: {summary['total']} findings, {summary['kev']} KEV listed. Results in {destination}.")
    return EXIT_PASSED if result["scan_status"] == "complete" else EXIT_INCOMPLETE


def _pairs(values):
    out = {}
    for value in values or []:
        key, separator, digest = value.partition("=")
        if not separator or not key or not digest:
            raise UntrustedInputError("gate_argument", f"--expect-artifact needs id=sha256, got {value!r}")
        out[key] = digest
    return out


def cmd_gate(args):
    from .gate import evaluate_gate
    record = evaluate_gate(args.result, args.mode, args.expect_revision, _pairs(args.expect_artifact), args.expect_policy, args.max_age_hours)
    if args.record:
        write_json(args.record, record)
    lines = [f"Gate ({args.mode}): {record['outcome']}"]
    lines += [f"  [{row.get('code')}] {row.get('message')}" for row in record["reasons"][:20]]
    if len(record["reasons"]) > 20:
        lines.append(f"  and {len(record['reasons']) - 20} more; see the gate record.")
    _emit(args, record, "\n".join(lines))
    return record["exit_code"]


def cmd_release(args):
    from .collector import update
    return update.main(args)


def cmd_init(args):
    from .onboard.init import generate
    try:
        result = generate(args)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        from .common.errors import ConfigError
        raise ConfigError("init_input_invalid", f"Cannot generate configuration: {exc}") from exc
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("Dry run - no files changed." if args.dry_run else "Generated and validated configuration. Review claims before scanning.")
        for row in result["detected"]: print("  Detected: " + row)
        for row in result["warnings"]: print("  Review: " + row)
        for path, content in result["files"].items():
            print("\n" + ("Would write: " if args.dry_run else "Wrote: ") + path)
            if args.dry_run: print(content)
        print("\nNext commands (from the project root; capture/build inputs first):")
        for command in result["next_commands"]: print("  " + command)
    return EXIT_PASSED


def cmd_validate(args):
    from .onboard.validate import preflight
    config, warnings = preflight(args.config, args.check_inputs)
    _emit(args, {"config": str(config.path), "valid": True, "warnings": warnings},
          "Configuration, policy and component records are valid.\n" + "\n".join("  Review: " + x for x in warnings))
    return EXIT_PASSED


def cmd_policy(args):
    from .onboard.policy import generate
    from .onboard.init import write_plan, _safe_destination
    from .onboard.serialize import toml, merge
    from .onboard.validate import document
    import tomllib
    path = Path(args.out).absolute()
    _safe_destination(path.parent.resolve(), path.name)
    value = generate(args.strictness, args.author, args.policy_version)
    if path.exists():
        if not args.force:
            from .common.errors import ConfigError
            raise ConfigError("init_exists", "Policy exists; use --force to merge existing reviewed values")
        value = merge(tomllib.loads(path.read_text()), value)
    document(value, "policy")
    if args.dry_run: print(toml(value))
    else:
        write_plan(path.parent, {path.name: toml(value)}, args.force)
        print(f"Policy written to {path}; trusted authors must be chosen by your team.")
    return EXIT_PASSED


def cmd_data(args):
    from .data_update import update
    result = update(args.config, kev_file=args.kev_file, skip_db=args.skip_db)
    _emit(args, result, f"Data updated: {result['kev']}; Grype DB updated: {result['grype_db_updated']}")
    return EXIT_PASSED


def build_parser():
    parser = Parser(prog="cra", description="CI dependency evidence, vulnerability analysis and policy gate. Does not certify CRA conformity.")
    parser.add_argument("--version", action="version", version=f"cra {__version__}")
    commands = parser.add_subparsers(dest="command", required=True, parser_class=Parser)
    init = commands.add_parser("init", help="Detect static build evidence and generate reviewed configuration scaffolds")
    init.add_argument("--root", default=".")
    init.add_argument("--name")
    init.add_argument("--version", dest="product_version", help="Product version, not the cra tool version")
    init.add_argument("--supplier")
    init.add_argument("--settings")
    init.add_argument("--author", action="append", default=[])
    init.add_argument("--sdk-root", action="append", default=[])
    init.add_argument("--policy", choices=("default", "strict"), default="default")
    init.add_argument("--with-readiness", action="store_true")
    init.add_argument("--grype", default="grype")
    init.add_argument("--skip-cpe-check", action="store_true")
    init.add_argument("--dry-run", action="store_true")
    init.add_argument("--force", action="store_true", help="Merge; preserve manual values, reviews and records")
    init.add_argument("--json", action="store_true")
    init.set_defaults(handler=cmd_init)
    validate = commands.add_parser("validate", help="Preflight config, policy and records without scanning")
    validate.add_argument("--config", default="cra.toml")
    validate.add_argument("--check-inputs", action="store_true", help="Also require configured capture/build paths to exist")
    validate.add_argument("--json", action="store_true")
    validate.set_defaults(handler=cmd_validate)
    policy = commands.add_parser("policy", help="Generate a customer policy scaffold")
    policy.add_argument("action", choices=("init",))
    policy.add_argument("--strictness", choices=("default", "strict"), default="default")
    policy.add_argument("--version", dest="policy_version", default="policy-1")
    policy.add_argument("--author", action="append", default=[])
    policy.add_argument("--out", default="policy.toml")
    policy.add_argument("--force", action="store_true")
    policy.add_argument("--dry-run", action="store_true")
    policy.set_defaults(handler=cmd_policy)
    data = commands.add_parser("data", help="Explicitly refresh advisory data")
    data.add_argument("action", choices=("update",))
    data.add_argument("--config", default="cra.toml")
    data.add_argument("--kev-file", help="Import an existing catalogue instead of downloading from CISA")
    data.add_argument("--skip-db", action="store_true", help="Import KEV only; use an already provisioned Grype DB")
    data.add_argument("--json", action="store_true")
    data.set_defaults(handler=cmd_data)
    for name, handler, helptext in (("prepare", cmd_prepare, "Register CMake File API queries before CMake configures"),
                                    ("collect", cmd_collect, "Read configured metadata and artifacts into an evidence bundle")):
        sub = commands.add_parser(name, help=helptext)
        sub.add_argument("--config", default="cra.toml")
        sub.add_argument("--json", action="store_true")
        if name == "collect":
            sub.add_argument("--out", help="Bundle directory (default: <output.dir>/collection)")
        sub.set_defaults(handler=handler)
    analyze = commands.add_parser("analyze", help="Reconcile, scan and evaluate a collected bundle")
    analyze.add_argument("--config", default="cra.toml")
    analyze.add_argument("--collection")
    analyze.add_argument("--out")
    analyze.add_argument("--kev", help="CISA KEV catalogue JSON (overrides analysis.kev)")
    analyze.add_argument("--hosted", action="store_true", help="Submit to the hosted service instead of analyzing locally")
    analyze.add_argument("--json", action="store_true")
    analyze.set_defaults(handler=cmd_analyze)
    gate = commands.add_parser("gate", help="Decide the CI outcome from an existing result, without rescanning")
    gate.add_argument("--result", default=".cra/analysis", help="Analysis directory containing result.json and manifest.json")
    gate.add_argument("--mode", choices=("build", "release"), default="build")
    gate.add_argument("--expect-revision", help="Fail unless the result is for this source revision")
    gate.add_argument("--expect-artifact", action="append", metavar="ID=SHA256", help="Fail unless this artifact hash is in the result")
    gate.add_argument("--expect-policy", metavar="SHA256", help="Fail unless the result used this policy")
    gate.add_argument("--max-age-hours", type=float, help="Fail if the result is older than this")
    gate.add_argument("--record", help="Write the gate record to this file")
    gate.add_argument("--json", action="store_true")
    gate.set_defaults(handler=cmd_gate)
    release = commands.add_parser("release", help="Verify, activate or roll back collector releases")
    from .collector.update import add_arguments
    add_arguments(release)
    release.set_defaults(handler=cmd_release)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.handler(args)
    except CraError as exc:
        print(f"cra: {exc}", file=sys.stderr)
        return exc.exit_code
    except UntrustedInputError as exc:
        print(f"cra: invalid input [{exc.code}]: {redact_text(str(exc))[0]}", file=sys.stderr)
        return EXIT_INCOMPLETE
    except Exception as exc:  # A bug in our tool must surface as our failure, never as a pass.
        print(f"cra: internal failure [{type(exc).__name__}]: {redact_text(str(exc))[0]}", file=sys.stderr)
        return EXIT_OPERATIONAL


def entrypoint():
    sys.exit(main())
