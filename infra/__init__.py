import pickle
import subprocess
import sys
from pathlib import Path
from typing import Any

PYINFRA_WORKER: Path = Path(__file__).parent / "pyinfra_worker.py"

# Wire types for pyinfra_run_batch
OpSpec = tuple[str, str, dict[str, Any]]         # (op_module, op_name, norm_kwargs)
BatchResult = list[tuple[bool, str | None]]       # (success, error_or_None) per op


def pyinfra_run_batch(ops: list[OpSpec]) -> BatchResult:
    """Run a list of pyinfra operations in a single worker subprocess.

    The worker runs each operation independently so a failure in one does not
    abort the rest.  Returns one (success, error) pair per input operation.
    On catastrophic worker failure (non-zero exit before any result is written)
    every operation is reported as failed.
    """
    payload = pickle.dumps(ops)
    proc = subprocess.run(
        [sys.executable, str(PYINFRA_WORKER)],
        input=payload,
        capture_output=True,
    )
    if proc.returncode != 0:
        err = proc.stderr.decode(errors="replace")
        return [(False, err)] * len(ops)
    return pickle.loads(proc.stdout)
