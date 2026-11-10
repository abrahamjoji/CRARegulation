"""Server settings from the environment. Nothing here comes from a client."""
import os
from dataclasses import dataclass
from pathlib import Path

MIB = 1024 * 1024


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    max_upload_bytes: int = 256 * MIB
    max_active_jobs_per_project: int = 8
    job_timeout_seconds: int = 1200
    lease_seconds: int = 1500
    max_attempts: int = 3
    grype: str = "grype"
    kev_path: Path | None = None
    default_retention_days: int = 90

    @property
    def database(self):
        return self.data_dir / "control.sqlite3"

    @property
    def storage(self):
        return self.data_dir / "tenants"


def from_environment():
    data = os.environ.get("CRA_SERVER_DATA")
    if not data:
        raise SystemExit("CRA_SERVER_DATA must name the server's data directory")
    kev = os.environ.get("CRA_SERVER_KEV")
    return Settings(data_dir=Path(data), max_upload_bytes=int(os.environ.get("CRA_SERVER_MAX_UPLOAD_BYTES", 256 * MIB)),
                    max_active_jobs_per_project=int(os.environ.get("CRA_SERVER_MAX_ACTIVE_JOBS", 8)),
                    job_timeout_seconds=int(os.environ.get("CRA_SERVER_JOB_TIMEOUT", 1200)),
                    grype=os.environ.get("CRA_SERVER_GRYPE", "grype"), kev_path=Path(kev) if kev else None)
