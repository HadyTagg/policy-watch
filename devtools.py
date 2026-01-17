import os
import stat
import shutil
from pathlib import Path


Path("policywatch.db").unlink(missing_ok=True)
def force_delete_dir(path: str) -> None:
    p = Path(path)

    def onerror(func, failed_path, exc_info):
        # Make the file/dir writable, then retry the operation
        os.chmod(failed_path, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
        func(failed_path)

    if p.exists():
        shutil.rmtree(p, onerror=onerror)

force_delete_dir("policies")
force_delete_dir(".policy_backups")
