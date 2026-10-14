import os
import sys

from pypiscan.cli import main

# Output piped into a command that exits early, such as `| head`, raises
# BrokenPipeError. This is the recipe from the "Note on SIGPIPE" in Python's
# signal module docs. SIGPIPE stays ignored rather than set to SIG_DFL, which
# would kill the process on any write to a closed socket, such as PyPI's.
try:
    status = main()
    sys.stdout.flush()
except BrokenPipeError:
    # Python flushes stdout again at exit; point it at devnull so that flush
    # doesn't raise too.
    devnull = os.open(os.devnull, os.O_WRONLY)
    os.dup2(devnull, sys.stdout.fileno())
    os.close(devnull)
    sys.exit(1)

raise SystemExit(status)
