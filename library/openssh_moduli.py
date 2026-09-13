#!/usr/bin/python
"""Filter vendor DH moduli without changing the package-owned source."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: openssh_moduli
short_description: Maintain a filtered OpenSSH Diffie-Hellman moduli file
description:
  - Retain vendor-tested safe primes meeting a minimum actual bit length.
  - Preserve the vendor source, comments and record order.
  - Reject malformed records and an empty selection before writing the destination.
  - This module does not generate primes or repeat primality tests.
author:
  - Jonas Mauer
options:
  src:
    description: Package-owned OpenSSH moduli source file.
    type: path
    required: true
  path:
    description: Destination used by the sshd ModuliFile directive.
    type: path
    required: true
  minimum:
    description: Minimum actual modulus bit length, including the high bit.
    type: int
    default: 3072
  backup:
    description: Create a timestamped backup before replacing an existing destination.
    type: bool
    default: true
extends_documentation_fragment:
  - ansible.builtin.files
attributes:
  check_mode:
    support: full
  diff_mode:
    support: none
"""

EXAMPLES = r"""
- name: OPENSSH | Filter weak Diffie-Hellman moduli
  openssh_moduli:
    src: /etc/ssh/moduli
    path: /etc/ssh/moduli.ansible
    minimum: 3072
    owner: root
    group: root
    mode: '0644'
"""

RETURN = r"""
path:
  description: Managed destination path.
  type: str
  returned: always
retained:
  description: Number of retained safe-prime records.
  type: int
  returned: always
removed:
  description: Number of records excluded by size or vendor test metadata.
  type: int
  returned: always
backup_file:
  description: Backup path when an existing file was replaced with backup enabled.
  type: str
  returned: when a backup was created
"""


def filter_moduli(source: str, minimum: int) -> tuple[str, int, int]:
    """Select tested safe primes and reject inconsistent OpenSSH records."""
    if minimum < 3072:
        raise ValueError("minimum must be at least 3072 bits")
    output: list[str] = []
    retained = 0
    removed = 0
    for number, line in enumerate(source.splitlines(keepends=True), start=1):
        text = line.strip()
        if not text or text.startswith("#"):
            output.append(line)
            continue
        if usable_record(text, number, minimum):
            output.append(line)
            retained += 1
        else:
            removed += 1
    if not retained:
        raise ValueError("no tested safe primes satisfy the minimum bit length")
    return "".join(output), retained, removed


def usable_record(text: str, number: int, minimum: int) -> bool:
    """Check source format and vendor test metadata without testing primality."""
    fields = text.split()
    if len(fields) != 7:
        raise ValueError(f"line {number}: expected seven moduli fields")
    try:
        prime_type, tests, trials, size = (int(value) for value in fields[1:5])
        generator = int(fields[5], 16)
        prime = int(fields[6], 16)
    except ValueError as error:
        raise ValueError(f"line {number}: invalid numeric moduli field") from error
    # OpenSSH stores the bit length minus one in the size field (dh.c).
    if prime.bit_length() != size + 1 or not 1 < generator < prime:
        raise ValueError(f"line {number}: inconsistent modulus size or generator")
    return (
        prime_type == 2 and tests & 4 != 0 and tests & 1 == 0
        and trials > 0 and size + 1 >= minimum
    )


def write_moduli(module: AnsibleModule, destination: Path, content: str) -> str | None:
    """Use Ansible's backup and atomic replacement primitives."""
    backup = None
    if module.params["backup"] and destination.exists():
        backup = module.backup_local(str(destination))
    descriptor, temporary = tempfile.mkstemp(dir=module.tmpdir)
    with os.fdopen(descriptor, "w", encoding="ascii") as output:
        output.write(content)
    module.atomic_move(temporary, str(destination))
    return backup


def main() -> None:
    """Apply the filtered file with Ansible's backup and file attribute support."""
    module = AnsibleModule(
        argument_spec={
            "src": {"type": "path", "required": True},
            "path": {"type": "path", "required": True},
            "minimum": {"type": "int", "default": 3072},
            "backup": {"type": "bool", "default": True},
        },
        add_file_common_args=True,
        supports_check_mode=True,
    )
    source = Path(module.params["src"])
    destination = Path(module.params["path"])
    try:
        if source.resolve() == destination.resolve():
            raise ValueError("src and path must differ to preserve vendor moduli")
        content, retained, removed = filter_moduli(
            source.read_text(encoding="ascii"), module.params["minimum"]
        )
        after = f"# Managed by ansible.\n# file: {destination}\n" + content
        before = destination.read_text(encoding="ascii") if destination.exists() else ""
    except (OSError, ValueError, UnicodeError) as error:
        module.fail_json(msg=str(error))
        return
    changed = before != after
    result: dict[str, object] = {
        "path": str(destination), "retained": retained, "removed": removed,
    }
    if changed and not module.check_mode:
        try:
            result["backup_file"] = write_moduli(module, destination, after)
        except OSError as error:
            module.fail_json(msg=str(error))
    file_args = module.load_file_common_arguments(module.params)
    result["changed"] = module.set_fs_attributes_if_different(file_args, changed)
    module.exit_json(**result)


if __name__ == "__main__":
    main()
