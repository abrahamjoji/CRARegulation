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


def build_parser():
    parser = Parser(prog="cra", description="CI dependency evidence, vulnerability analysis and policy gate. Does not certify CRA conformity.")
    parser.add_argument("--version", action="version", version=f"cra {__version__}")
    commands = parser.add_subparsers(dest="command", required=True, parser_class=Parser)
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
