#!/bin/bash
cd /home/kavia/workspace/code-generation/unified-app-connector-platform-167255-167265/connector_backend_api
source venv/bin/activate
flake8 .
LINT_EXIT_CODE=$?
if [ $LINT_EXIT_CODE -ne 0 ]; then
  exit 1
fi

