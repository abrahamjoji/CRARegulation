"""Tenant-separated evidence storage on a local filesystem. All path parts are server-generated."""
import os
import re
import shutil
from pathlib import Path

_ID = re.compile(r"^[0-9a-f]{32}$")


class Storage:
    def __init__(self, root):
        self.root = Path(root)

    def _job(self, tenant_id, project_id, job_id):
        for part in (tenant_id, project_id, job_id):
            if not _ID.match(part):
                raise ValueError("storage path parts must be server-generated identifiers")
        return self.root / tenant_id / project_id / job_id

    def _project_tmp(self, tenant_id, project_id):
        path = self._job(tenant_id, project_id, "0" * 32).parent / ".incoming"
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        return path

    def incoming_path(self, tenant_id, project_id, name):
        if not re.fullmatch(r"[0-9a-f]{32}", name):
            raise ValueError("bad upload name")
        return self._project_tmp(tenant_id, project_id) / name

    def job_dir(self, tenant_id, project_id, job_id, create=False):
        path = self._job(tenant_id, project_id, job_id)
        if create:
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
        return path

    def bundle(self, tenant_id, project_id, job_id):
        return self.job_dir(tenant_id, project_id, job_id) / "bundle.tar.gz"

    def result(self, tenant_id, project_id, job_id):
        return self.job_dir(tenant_id, project_id, job_id) / "result.tar.gz"

    def adopt_upload(self, source, tenant_id, project_id, job_id):
        target = self.job_dir(tenant_id, project_id, job_id, create=True) / "bundle.tar.gz"
        os.replace(source, target)
        target.chmod(0o600)
        return target

    def delete_job(self, tenant_id, project_id, job_id):
        shutil.rmtree(self.job_dir(tenant_id, project_id, job_id), ignore_errors=True)
