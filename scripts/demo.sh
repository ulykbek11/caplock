#!/usr/bin/env bash
set -euo pipefail
npm run build >/dev/null
node dist/cli.js version
npm run demo
