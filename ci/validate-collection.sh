#!/usr/bin/env bash
set -euo pipefail

install -d -m 0755 .ci/build .ci/collections
ansible-galaxy collection install --collections-path .ci/collections -r requirements.yml
ansible-galaxy collection build --force --output-path .ci/build
archive="$(find .ci/build -maxdepth 1 -type f -name 'frantche-homelab_edge_node-*.tar.gz' -print -quit)"
[[ -n "$archive" ]]
ansible-galaxy collection install --force --collections-path .ci/collections "$archive"
ANSIBLE_COLLECTIONS_PATH="$PWD/.ci/collections" \
  ansible-playbook --syntax-check -i localhost, ci/playbooks/syntax.yml
ANSIBLE_COLLECTIONS_PATH="$PWD/.ci/collections" \
  ansible-playbook -i localhost, ci/playbooks/render.yml
