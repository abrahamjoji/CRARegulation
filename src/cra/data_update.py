"""Explicit advisory data refresh; never invoked as a side effect of init/analysis."""
import os
import tempfile
import urllib.request
from pathlib import Path
from .common.config import load_config
from .common.errors import ConfigError, OperationalError
from .common.safety import Limits, read_json, run_tool, tool_environment, write_json
from .common.kev import load as load_kev

KEV_URL='https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
MAX_KEV=32*1024*1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): return None


def update(config_path, *, kev_file=None, skip_db=False):
    config=load_config(config_path)
    target=config.analysis.kev
    if target is None: raise ConfigError('data_path_missing','Set analysis.kev before refreshing data')
    if target.is_symlink() or any(p.is_symlink() for p in target.parents):raise ConfigError('data_path_unsafe','KEV destination must not traverse symlinks')
    if not target.resolve().is_relative_to(config.root):raise ConfigError('data_path_unsafe','data update only writes within the configured project root')
    if not skip_db:
        with tempfile.TemporaryDirectory(prefix='cra-data-') as home:
            env=tool_environment({'HOME':home,'GRYPE_CHECK_FOR_APP_UPDATE':'false','GRYPE_DB_CACHE_DIR':os.environ.get('GRYPE_DB_CACHE_DIR',str(Path.home()/'.cache/grype/db'))})
            result=run_tool([config.tools.grype,'db','update'],limits=Limits(timeout_seconds=config.tools.timeout_seconds),env=env,cwd=home)
            if result.returncode or result.missing or result.timed_out:raise OperationalError('data_update_failed','Grype DB update failed; no clean analysis can be inferred')
    with tempfile.TemporaryDirectory(prefix='cra-kev-') as temporary:
        staged=Path(temporary)/'kev.json'
        if kev_file:
            value=read_json(kev_file,MAX_KEV);write_json(staged,value)
        else:
            try:
                with urllib.request.build_opener(NoRedirect).open(KEV_URL,timeout=60) as response:
                    data=response.read(MAX_KEV+1)
                if len(data)>MAX_KEV:raise OperationalError('data_update_failed','KEV download exceeds 32 MiB')
                staged.write_bytes(data)
            except OSError as exc:raise OperationalError('data_update_failed',f'KEV download failed: {type(exc).__name__}') from None
        _,identity,problem=load_kev(staged)
        if problem:raise ConfigError('data_kev_invalid',problem)
        # Same-directory staging makes the final publication atomic; old data survives errors.
        target.parent.mkdir(parents=True,exist_ok=True)
        value=read_json(staged,MAX_KEV);write_json(target,value)
    return {'kev':str(target),'identity':identity,'grype_db_updated':not skip_db}
