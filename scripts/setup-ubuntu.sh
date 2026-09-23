#!/usr/bin/env bash
set -euo pipefail
echo 'Installs Linux dependencies for CapLock. Run manually only if you approve system package changes.'
sudo apt-get update
sudo apt-get install -y bubblewrap strace
