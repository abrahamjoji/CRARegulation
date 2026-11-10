#!/bin/sh
exec env PYTHONPATH=/opt/cra python -m cra.cli_main "$@"
