#!/usr/bin/env bash
set -euo pipefail
if [[ -e /dev/kvm ]]; then
  sudo chmod 0666 /dev/kvm
  echo "KVM acceleration enabled"
else
  echo "KVM unavailable; QEMU will use emulation"
fi

