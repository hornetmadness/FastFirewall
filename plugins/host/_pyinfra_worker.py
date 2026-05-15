"""
Subprocess entry point for pyinfra operations.

Run by host_plugin._pyinfra_run to avoid the gevent/anyio conflict:
pyinfra's local connector uses gevent.subprocess.Popen, which requires
the libev "default loop" for child watchers.  FastAPI's anyio thread pool
creates non-default gevent hubs, so every pyinfra call would crash with
"child watchers are only available on the default loop".  Spawning a fresh
process gives gevent a clean default loop.

Protocol: pickled (op_module, op_name, norm_kwargs) on stdin.
  norm_kwargs values may be ("__stringio__", content) tuples, which are
  reconstructed as io.StringIO before passing to the operation.
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

op_module, op_name, norm_kwargs = pickle.loads(sys.stdin.buffer.read())

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
