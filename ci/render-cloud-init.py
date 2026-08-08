#!/usr/bin/env python3
import os
import shlex
from pathlib import Path

import yaml

placeholder = "ssh-ed25519 AAAA_PLACEHOLDER_REPLACE_ME admin@example"
source = Path("cloud-init/edge.user-data.yml")
target = Path(os.environ.get("CI_VM_DIR", ".ci/vm")) / "user-data"
data = yaml.safe_load(source.read_text())
public_key = Path(os.environ["CI_SSH_PUBLIC_KEY"]).read_text().strip()
repo_url = os.environ["REPO_URL"]
repo_ref = os.environ["REPO_REF"]

for user in data["users"]:
    user["ssh_authorized_keys"] = [public_key if key == placeholder else key for key in user["ssh_authorized_keys"]]
for command in data["runcmd"]:
    if command[:2] == ["bash", "-lc"] and "$REPO_URL" in command[-1]:
        command[-1] = command[-1].replace('"$REPO_URL"', shlex.quote(repo_url))
        command[-1] = command[-1].replace('"$REPO_REF"', shlex.quote(repo_ref))

target.parent.mkdir(parents=True, exist_ok=True)
target.write_text("#cloud-config\n" + yaml.safe_dump(data, sort_keys=False))

