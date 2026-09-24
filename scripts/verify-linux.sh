#!/usr/bin/env bash
set -euo pipefail
npm run verify
npm run test:linux-native
npm run test:security
