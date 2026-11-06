"""Operator commands. Run on the server by an operator; none are exposed over the API."""
import argparse
import datetime as dt
import sys
from pathlib import Path

from .db import Database, utcnow
from .settings import from_environment
from .storage import Storage
from .worker import purge_expired


def main(argv=None):
    parser = argparse.ArgumentParser(prog="cra-server")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init")
    tenant = commands.add_parser("create-tenant")
    tenant.add_argument("--name", required=True)
    project = commands.add_parser("create-project")
    project.add_argument("--tenant", required=True)
    project.add_argument("--name", required=True)
    project.add_argument("--retention-days", type=int, default=90)
    project.add_argument("--policy", help="Policy TOML this project is evaluated against")
    token = commands.add_parser("create-token")
    token.add_argument("--project", required=True)
    token.add_argument("--scopes", default="submit,read")
    token.add_argument("--label", default="")
    token.add_argument("--expires-days", type=int, default=90)
    revoke = commands.add_parser("revoke-token")
    revoke.add_argument("--token-id", required=True)
    commands.add_parser("purge-expired")
    args = parser.parse_args(argv)

    settings = from_environment()
    settings.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    database = Database(settings.database)
    database.initialize()
    if args.command == "create-tenant":
        print(database.create_tenant(args.name))
    elif args.command == "create-project":
        policy = Path(args.policy).read_text(encoding="utf-8") if args.policy else None
        print(database.create_project(args.tenant, args.name, args.retention_days, policy))
    elif args.command == "create-token":
        expires = utcnow() + dt.timedelta(days=args.expires_days)
        secret, identifier = database.create_token(args.project, args.scopes.split(","), args.label, expires)
        print(f"token_id={identifier}", file=sys.stderr)
        print(secret)
    elif args.command == "revoke-token":
        database.revoke_token(args.token_id)
    elif args.command == "purge-expired":
        print(purge_expired(database, Storage(settings.storage)))
    return 0


def entrypoint():
    sys.exit(main())


if __name__ == "__main__":
    entrypoint()
