"""
Subprocess entry point for pyinfra operations.

Spawned by pyinfra_run_batch (infra/__init__.py) to avoid the gevent/anyio
conflict: pyinfra's local connector uses gevent.subprocess.Popen which requires
the libev "default loop" for child watchers. FastAPI's anyio thread pool creates
non-default gevent hubs, causing crashes. A fresh subprocess gives gevent a clean
default loop.

Protocol:
  stdin:  pickle of list[(op_module, op_name, norm_kwargs)]
            norm_kwargs values may be ("__stringio__", content) tuples,
            reconstructed as io.StringIO before passing to the operation.
  stdout: pickle of list[(success, error_message_or_None)]
            one entry per input operation; errors are reported here, not via
            exit code, so a single failure does not abort subsequent operations.
  exit:   always 0 (non-zero only on catastrophic startup failure)
"""
import io
import importlib
import pickle
import sys

from pyinfra.api.config import Config
from pyinfra.api.connect import connect_all
from pyinfra.api.inventory import Inventory
from pyinfra.api.operations import run_ops
from pyinfra.api.state import State
from pyinfra.context import ctx_host, ctx_state


def _run_one(op_module: str, op_name: str, norm_kwargs: dict) -> tuple[bool, str | None]:
    kwargs = {
        k: io.StringIO(v[1]) if isinstance(v, tuple) and v[0] == "__stringio__" else v
        for k, v in norm_kwargs.items()
    }
    op = getattr(importlib.import_module(op_module), op_name)
    inventory = Inventory(([("@local", {})], {}))
    state = State(inventory, Config())
    connect_all(state)
    with ctx_state.use(state):
        for host in state.activated_hosts:
            with ctx_host.use(host):
                op(**kwargs)
    run_ops(state)
    return True, None


ops = pickle.loads(sys.stdin.buffer.read())
results: list[tuple[bool, str | None]] = []
for op_module, op_name, norm_kwargs in ops:
    try:
        results.append(_run_one(op_module, op_name, norm_kwargs))
    except Exception as exc:
        results.append((False, str(exc)))

sys.stdout.buffer.write(pickle.dumps(results))
