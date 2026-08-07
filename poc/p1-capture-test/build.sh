#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
clang -fobjc-arc -fmodules -Wall -O0 -g \
  -isysroot "$(xcrun --sdk macosx --show-sdk-path)" \
  -framework Foundation -framework IOKit -framework IOUSBHost -framework DiskArbitration \
  -o capture_test capture_test.m
echo "built ./capture_test"
