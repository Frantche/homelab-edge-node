#!/usr/bin/env bash
set -euo pipefail

CI_ARCH_IMAGE="${CI_ARCH_IMAGE:-$PWD/.ci/cache/arch.qcow2}"
CI_SSH_KEY="${CI_SSH_KEY:-$PWD/.ci/ssh/id_ed25519}"

ci_vm_download_image() {
  install -d -m 0755 "$(dirname "$CI_ARCH_IMAGE")"
  if [[ ! -s "$CI_ARCH_IMAGE" ]]; then
    curl --fail --location --retry 3 \
      --output "$CI_ARCH_IMAGE" \
      https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2
  fi
}

ci_vm_generate_ssh_key() {
  install -d -m 0700 "$(dirname "$CI_SSH_KEY")"
  if [[ ! -f "$CI_SSH_KEY" ]]; then
    ssh-keygen -t ed25519 -N "" -f "$CI_SSH_KEY"
  fi
  chmod 0600 "$CI_SSH_KEY"
}

ci_vm_create() {
  local vm_dir="$1" repo_url="$2" repo_ref="$3"
  [[ "$repo_ref" =~ ^[0-9a-fA-F]{40}$ ]] || { echo "A full commit SHA is required" >&2; return 1; }
  case "$vm_dir" in "$PWD"/.ci/vm) ;; *) echo "Unexpected VM directory" >&2; return 1 ;; esac
  ci_vm_download_image
  ci_vm_generate_ssh_key
  install -d -m 0755 "$vm_dir"
  cp --reflink=auto "$CI_ARCH_IMAGE" "$vm_dir/disk.qcow2"
  qemu-img resize "$vm_dir/disk.qcow2" 20G
  CI_VM_DIR="$vm_dir" CI_SSH_PUBLIC_KEY="$CI_SSH_KEY.pub" \
    REPO_URL="$repo_url" REPO_REF="$repo_ref" python ci/render-cloud-init.py
  cat >"$vm_dir/meta-data" <<EOF
instance-id: edge-ci
local-hostname: edge-ci
EOF
  cloud-localds "$vm_dir/seed.img" "$vm_dir/user-data" "$vm_dir/meta-data"
}

ci_vm_start() {
  local vm_dir="$1" kvm=() cpu=qemu64
  if [[ -e /dev/kvm ]]; then kvm=(-enable-kvm); cpu=host; fi
  qemu-system-x86_64 "${kvm[@]}" -m 4096 -smp 2 -cpu "$cpu" -nographic \
    -drive "file=$vm_dir/disk.qcow2,format=qcow2,if=virtio" \
    -drive "file=$vm_dir/seed.img,format=raw,if=virtio" \
    -netdev user,id=net0,hostfwd=tcp::2222-:22,hostfwd=tcp::8443-:443,hostfwd=tcp::16690-:6690,hostfwd=udp::12456-:2456 \
    -device virtio-net-pci,netdev=net0 -serial mon:stdio >"$vm_dir/qemu.log" 2>&1 &
  echo "$!" >"$vm_dir/qemu.pid"
}

ci_vm_ssh() {
  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
    -i "$CI_SSH_KEY" -p 2222 admin@127.0.0.1 "$@"
}

ci_vm_wait_for_initial_ssh() {
  local vm_dir="$1" initial_boot=""
  local ssh_deadline=$((SECONDS + 600))
  local attempt=0
  while ((SECONDS < ssh_deadline)); do
    attempt=$((attempt + 1))
    initial_boot="$(ci_vm_ssh 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null || true)"
    [[ -n "$initial_boot" ]] && break
    if ((attempt % 12 == 0)); then
      echo "Still waiting for initial SSH (attempt $attempt)"
      tail -20 "$vm_dir/qemu.log" || true
    fi
    sleep 5
  done
  if [[ -z "$initial_boot" ]]; then
    tail -100 "$vm_dir/qemu.log" || true
    return 1
  fi
  printf '%s\n' "$initial_boot" >"$vm_dir/initial-boot-id"
}

ci_vm_wait_for_bootstrap() {
  local vm_dir="$1"
  local initial_boot
  initial_boot="$(cat "$vm_dir/initial-boot-id")"
  local deadline=$((SECONDS + 1800))
  local attempt=0
  while ((SECONDS < deadline)); do
    attempt=$((attempt + 1))
    current="$(ci_vm_ssh 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null || true)"
    if [[ -n "$current" && "$current" != "$initial_boot" ]] && \
       ci_vm_ssh 'test -f /var/lib/cloud/instance/boot-finished' 2>/dev/null; then
      return 0
    fi
    if ((attempt % 12 == 0)); then
      echo "Still waiting for cloud-init and reboot (attempt $attempt)"
      ci_vm_ssh 'sudo tail -20 /var/log/cloud-init-output.log' || true
    fi
    sleep 5
  done
  ci_vm_ssh 'sudo tail -100 /var/log/cloud-init-output.log' || true
  return 1
}

ci_vm_collect_logs() {
  local vm_dir="$1" out="$2"
  install -d -m 0755 "$out"
  cp "$vm_dir/qemu.log" "$out/qemu.log" 2>/dev/null || true
  ci_vm_ssh 'sudo cat /var/log/cloud-init-output.log' >"$out/cloud-init.log" 2>/dev/null || true
  ci_vm_ssh 'sudo journalctl --no-pager' >"$out/journal.log" 2>/dev/null || true
  ci_vm_ssh 'sudo docker ps -a' >"$out/docker-ps.log" 2>/dev/null || true
  ci_vm_ssh 'sudo docker logs edge-traefik' >"$out/traefik.log" 2>&1 || true
  ci_vm_ssh 'sudo docker logs edge-otel-collector' >"$out/otel-collector.log" 2>&1 || true
  ci_vm_ssh 'sudo cat /var/log/homelab-edge-node/traefik.json.log' >"$out/traefik-json.log" 2>/dev/null || true
  ci_vm_ssh 'sudo cat /var/log/homelab-edge-node/traefik-access.json.log' >"$out/traefik-access.log" 2>/dev/null || true
  ci_vm_ssh 'sudo nft list ruleset' >"$out/nftables.log" 2>/dev/null || true
}

ci_vm_stop() {
  local vm_dir="$1"
  if [[ -f "$vm_dir/qemu.pid" ]]; then
    kill "$(cat "$vm_dir/qemu.pid")" 2>/dev/null || true
    wait "$(cat "$vm_dir/qemu.pid")" 2>/dev/null || true
  fi
}
