# Ansible Role: openssh

![GitHub](https://img.shields.io/github/license/jomrr/ansible-role-openssh)
![GitHub last commit](https://img.shields.io/github/last-commit/jomrr/ansible-role-openssh)
![GitHub issues](https://img.shields.io/github/issues-raw/jomrr/ansible-role-openssh)
[![dev](https://img.shields.io/github/actions/workflow/status/jomrr/ansible-role-openssh/dev.yml?branch=dev&label=dev)](https://github.com/jomrr/ansible-role-openssh/actions/workflows/dev.yml?query=branch%3Adev)
[![main](https://img.shields.io/github/actions/workflow/status/jomrr/ansible-role-openssh/main.yml?branch=main&label=main)](https://github.com/jomrr/ansible-role-openssh/actions/workflows/main.yml?query=branch%3Amain)

Install and configure OpenSSH.

## Purpose

Install and configure OpenSSH clients and servers, manage host and authorized
keys, and keep the server enabled and started.

## Scope

### Managed

- Client and server hardening drop-ins, host-specific client options and server
  Match rules.
- Host keys, central authorized keys, known hosts and optional host-based trust
  data.
- A filtered DH moduli file derived from the package-owned source.

### Not Managed

- System-wide crypto-policy selection, FIPS activation, firewall rules and
  account provisioning.
- OS-wide CIS or STIG compliance, MFA enrollment, PAM authentication changes and
  login banners.

## Requirements

- Ansible-core 2.20 or later and the collections listed in collections.yml.
- OpenSSH with Include, Match final and RequiredRSASize support.
- Existing accounts for openssh_authorized_keys entries.

## Dependencies

```yaml
collections:
  - name: community.general
    version: '>=12.0.0'
  - name: community.crypto
    version: '>=3.0.0'
  - name: ansible.posix
    version: '>=2.0.0'
```

## Role Variables

### `openssh_backup`

Type: `bool`. Required: `false`.

Create module-provided backups before changing configuration and moduli files.

Default:

```yaml
openssh_backup: true
```

### `openssh_crypto_profile`

Type: `str`. Required: `false`.

Algorithm fallback profile; system leaves native algorithm policy unchanged.

Default:

```yaml
openssh_crypto_profile: system
```

### `openssh_crypto_options`

Type: `dict`. Required: `false`.

Algorithm fallback overrides for an explicitly selected non-system profile.

Default:

```yaml
openssh_crypto_options: {}
```

### `openssh_rsa_minimum`

Type: `int`. Required: `false`.

RSA minimum used only when native configuration does not already specify one.
Stronger or weaker system-policy values retain precedence; the fallback must be
at least 3072 bits.

Default:

```yaml
openssh_rsa_minimum: 3072
```

### `openssh_client_defaults`

Type: `dict`. Required: `false`.

Base client directives, merged with openssh_client_options.

Default:

```yaml
openssh_client_defaults:
  AddressFamily: any
  ForwardAgent: 'no'
  ForwardX11: 'no'
  HashKnownHosts: 'yes'
  HostbasedAuthentication: 'no'
  KbdInteractiveAuthentication: 'no'
  PasswordAuthentication: 'no'
  PubkeyAuthentication: 'yes'
  RekeyLimit: 1G 1h
  StrictHostKeyChecking: 'yes'
  Tunnel: 'no'
```

### `openssh_client_options`

Type: `dict`. Required: `false`.

Additional client directives and overrides using native SSH syntax.

Default:

```yaml
openssh_client_options: {}
```

### `openssh_client_hosts`

Type: `dict`. Required: `false`.

Host patterns mapped to client directive dictionaries, before global defaults.

Default:

```yaml
openssh_client_hosts: {}
```

### `openssh_server_defaults`

Type: `dict`. Required: `false`.

Base server directives, merged with openssh_server_options.

Default:

```yaml
openssh_server_defaults:
  AddressFamily: any
  Port: 22
  PermitRootLogin: 'no'
  AuthenticationMethods: publickey
  PubkeyAuthentication: 'yes'
  PasswordAuthentication: 'no'
  KbdInteractiveAuthentication: 'no'
  PermitEmptyPasswords: 'no'
  HostbasedAuthentication: 'no'
  IgnoreRhosts: 'yes'
  IgnoreUserKnownHosts: 'yes'
  StrictModes: 'yes'
  PermitUserEnvironment: 'no'
  AllowAgentForwarding: 'no'
  AllowTcpForwarding: 'no'
  AllowStreamLocalForwarding: 'no'
  GatewayPorts: 'no'
  X11Forwarding: 'no'
  X11UseLocalhost: 'yes'
  PermitTunnel: 'no'
  LoginGraceTime: 60
  MaxAuthTries: 3
  MaxSessions: 10
  MaxStartups: 10:30:60
  ClientAliveInterval: 300
  ClientAliveCountMax: 1
  LogLevel: VERBOSE
  SyslogFacility: AUTHPRIV
  RekeyLimit: 1G 1h
  UseDNS: 'no'
```

### `openssh_server_options`

Type: `dict`. Required: `false`.

Additional server directives and overrides using native sshd syntax.

Default:

```yaml
openssh_server_options: {}
```

### `openssh_listen_addresses`

Type: `list`. Required: `false`.

Explicit IPv4 or IPv6 listener addresses; an empty list uses native wildcard
listeners.

Default:

```yaml
openssh_listen_addresses: []
```

### `openssh_match_users`

Type: `dict`. Required: `false`.

User patterns mapped to Match User directive dictionaries.
Accepted user-key algorithms and authorized-key sources may be restricted per
match.

Default:

```yaml
openssh_match_users: {}
```

### `openssh_match_groups`

Type: `dict`. Required: `false`.

Group patterns mapped to Match Group directive dictionaries.
Accepted user-key algorithms and authorized-key sources may be restricted per
match; MFA is opt-in.

Default:

```yaml
openssh_match_groups: {}
```

### `openssh_host_keys`

Type: `list`. Required: `false`.

Managed host keys; Ed25519 keys are omitted on hosts running in FIPS mode.

Default:

```yaml
openssh_host_keys:
  - type: ed25519
    path: /etc/ssh/ssh_host_ed25519_key
  - type: ecdsa
    size: 384
    path: /etc/ssh/ssh_host_ecdsa_key
  - type: rsa
    size: 4096
    path: /etc/ssh/ssh_host_rsa_key
```

### `openssh_host_key_regenerate`

Type: `str`. Required: `false`.

Native keypair regeneration policy; changing key type or size can rotate host
identity.

Default:

```yaml
openssh_host_key_regenerate: partial_idempotence
```

### `openssh_moduli_minimum`

Type: `int`. Required: `false`.

Minimum actual DH modulus bit length; existing safe primes are filtered without
regeneration.

Default:

```yaml
openssh_moduli_minimum: 3072
```

### `openssh_authorized_keys_directory`

Type: `path`. Required: `false`.

Central directory containing authorized key files named after their users.

Default:

```yaml
openssh_authorized_keys_directory: /etc/ssh/authorized_keys.d
```

### `openssh_authorized_keys`

Type: `list`. Required: `false`.

Users and public keys managed through ansible.posix.authorized_key.

Default:

```yaml
openssh_authorized_keys: []
```

### `openssh_authorized_keys_exclusive`

Type: `bool`. Required: `false`.

Remove unlisted keys from each managed user file unless overridden per item.

Default:

```yaml
openssh_authorized_keys_exclusive: false
```

### `openssh_authorized_keys_files`

Type: `list`. Required: `false`.

AuthorizedKeysFile paths using native sshd tokens.

Default:

```yaml
openssh_authorized_keys_files:
  - .ssh/authorized_keys
  - /etc/ssh/authorized_keys.d/%u
```

### `openssh_known_hosts`

Type: `dict`. Required: `false`.

Host names mapped to complete public host-key lines in the system known_hosts
file.

Default:

```yaml
openssh_known_hosts: {}
```

### `openssh_shosts_equiv`

Type: `dict`. Required: `false`.

Trusted hosts mapped to user names for explicitly configured host-based
authentication.

Default:

```yaml
openssh_shosts_equiv: {}
```

## Managed Files

- `/etc/ssh/ssh_config.d/00-ansible.conf` Client authentication and host
  settings.
- `/etc/ssh/sshd_config.d/00-ansible.conf` Server authentication, forwarding and
  Match settings.
- `/etc/ssh/ssh_config.ansible` Client RSA and optional algorithm fallbacks,
  included at the end of the native main file.
- `/etc/ssh/sshd_config.ansible` Server RSA and optional algorithm fallbacks,
  included after native global configuration and before its first Match block.
- `/etc/ssh/moduli.ansible` Filtered DH moduli; the vendor source is retained.
- `/etc/ssh/authorized_keys.d` Central authorized keys, alongside
  /etc/ssh/ssh_known_hosts and /etc/ssh/shosts.equiv.
- `/etc/ssh/ssh_config and /etc/ssh/sshd_config` Native main files retained,
  with drop-in and fallback Includes enabled.

## Check Mode

Host keys, moduli and configuration support check mode.

- Initial check mode on a machine without OpenSSH cannot validate against
  executables or keys not yet installed.

## Service Behavior

Configuration and host-key changes validate the complete server configuration
before restarting the service.

### Handlers

- Ubuntu's native ssh.socket is reloaded and restarted after configuration
  changes and remains enabled and started alongside the SSH service.

## Security Notes

- The default system profile uses native algorithm settings and their Include
  order. Where no native policy specifies algorithms, the installed OpenSSH
  defaults apply.
- OpenSSH normally uses the first obtained value. Optional role profiles and
  openssh_crypto_options supply late fallbacks. Earlier native settings win even
  when weaker. A minus-prefixed list filters OpenSSH defaults, not system-policy
  values. Enforce restrictions through the native policy on policy-managed
  hosts. Role profiles cover SSH algorithm selection; full CIS, STIG or BSI
  compliance requires additional OS controls.
- RequiredRSASize uses openssh_rsa_minimum (3072 bits) only where native
  configuration does not set it. An earlier 4096-bit or 2048-bit policy remains
  effective. To enforce a minimum on such hosts, change the native policy, for
  example its RSA size setting, independently. This check covers RSA
  authentication/host keys and is separate from generating the role-managed
  4096-bit RSA host key.
- The client reads role fallbacks in a final pass; the server reads them after
  native global settings, before its first main-file Match block. Add native
  global settings before these fallback includes. Verify effective settings with
  ssh -G hostname and sshd -T, using sshd -T -C user=NAME,host=HOST,addr=IP for
  connection-specific rules.
- Optional modern retains the installed OpenSSH default ordering, removes legacy
  CBC/SHA-1/DSA and sub-3072-bit fixed DH choices, and automatically inherits
  newly enabled algorithms such as hybrid post-quantum KEX.
- cis uses AES-GCM/CTR and SHA-2 MACs as a conservative mapping of the CIS RHEL
  9 SSH recommendations, including the benchmark restrictions on ChaCha20 and
  EtM. modern retains supported ChaCha20 and SHA-2 EtM on patched OpenSSH.
- stig adds conventional NIST ECDH/DH and ECDSA/RSA-SHA2 restrictions. FIPS
  validation depends on the operating system's cryptographic implementation and
  policy.
- bsi maps TR-02102-4 version 2026-01 to supported AES-GCM/CTR, SHA-2 MAC, NIST
  ECDH/DH and NIST ECDSA choices. The document does not yet recommend OpenSSH's
  X25519-based hybrid KEX or Ed25519 as an SSH signature algorithm. Its
  classical KEX recommendation ends in 2031.
- The default server requires public-key authentication and disables password
  and keyboard-interactive authentication. The client also disables both
  interactive methods unless explicitly enabled for selected destinations. TCP,
  Unix-domain socket, agent and X11 forwarding are disabled by default.
- ClientAliveInterval and ClientAliveCountMax detect unresponsive clients; they
  do not log out a responsive but idle user. The optional ChannelTimeout example
  closes idle session channels, not the complete SSH connection, and requires a
  supporting OpenSSH version.
- MFA is opt-in. Token enrollment and PAM authentication are managed separately;
  examples are below.
- Default private host-key mode is 0600. A changed type or size can rotate an
  existing key under partial_idempotence and requires known_hosts updates. The
  never and fail policies can instead preserve host identity or reject
  mismatches. Ed25519 is omitted when the host is in FIPS mode.
- DH moduli are filtered to tested safe primes of at least 3072 actual bits by
  default. The vendor source is retained and package updates are incorporated on
  the next convergence.

## Operational Notes

- Native directive values use quoted yes/no strings and space-separated lists.
  The defaults dictionaries can be replaced explicitly; options dictionaries
  merge into them.
- Vendor PAM integration and SFTP subsystem paths are retained. On SUSE, absent
  local main configuration files are copied from /usr/etc/ssh.

## Supported Platforms

| OS Family | Distribution | Version | Container Image |
| --------- | ------------ | ------- | --------------- |
| RedHat | AlmaLinux | latest | [jomrr/molecule-almalinux:latest](https://hub.docker.com/r/jomrr/molecule-almalinux) |
| Debian | Debian | latest | [jomrr/molecule-debian:latest](https://hub.docker.com/r/jomrr/molecule-debian) |
| RedHat | Fedora | latest | [jomrr/molecule-fedora:latest](https://hub.docker.com/r/jomrr/molecule-fedora) |
| Suse | OpenSuse Leap | latest | [jomrr/molecule-opensuse-leap:latest](https://hub.docker.com/r/jomrr/molecule-opensuse-leap) |
| Suse | OpenSuse Tumbleweed | latest | [jomrr/molecule-opensuse-tumbleweed:latest](https://hub.docker.com/r/jomrr/molecule-opensuse-tumbleweed) |
| Debian | Ubuntu | latest | [jomrr/molecule-ubuntu:latest](https://hub.docker.com/r/jomrr/molecule-ubuntu) |

## Example Playbook

### Default hardening with native algorithm policy

Manage SSH using explicit public keys for an existing administrative account.

```yaml
---
- name: Configure OpenSSH
  hosts: ssh_servers
  gather_facts: true
  roles:
    - role: jomrr.openssh
      openssh_authorized_keys:
        - user: deploy
          key: "{{ lookup('ansible.builtin.file', 'files/deploy.pub') }}"
      openssh_server_options:
        AllowUsers: deploy
```

### BSI algorithm mapping

Apply the BSI SSH subset where system crypto policies do not already set the algorithms.

```yaml
openssh_crypto_profile: bsi
openssh_server_options:
  AllowGroups: ssh-admins
  Banner: /etc/issue.net
openssh_match_groups:
  sftp-users:
    ForceCommand: internal-sftp
openssh_match_users:
  backup:
    AllowTcpForwarding: local
```

### Optional modern algorithm fallbacks

Use modern fallbacks where native configuration does not set algorithms.

```yaml
openssh_crypto_profile: modern
openssh_rsa_minimum: 3072
```

### Configure a client host pattern

Set the remote user for selected destinations alongside server hardening.

```yaml
openssh_client_hosts:
  '*.example.net':
    User: deploy
```

### Optional Nitrokey FIDO2 authentication

For a Nitrokey with FIDO2 support, such as Nitrokey 3, generate the identity on
the client, for example with
`ssh-keygen -t ed25519-sk -O verify-required -f ~/.ssh/id_admin_nitrokey`.
Set up the token PIN first. Use `ecdsa-sk` where required by token support or
the applicable policy. Deploy only the public key to the server; retain the
private key handle on the client. The server does not need the USB token or
a FIDO PAM module. Select the identity with `ssh -i ~/.ssh/id_admin_nitrokey`.

The existing account must belong to ssh-fido. Both the client and the server
must support OpenSSH security-key signatures, and the native crypto policy
must permit the chosen SK algorithms. The stig and bsi fallback allowlists
do not include them; review compatibility before using this example. A Match
allowlist is an explicit authentication override, not an automatic
intersection with the system policy.

Requiring verification enforces the authenticator's PIN or biometric check
alongside possession. Touch alone proves presence, not a second factor.
Restricting accepted algorithms to SK keys prevents ordinary RSA, ECDSA or
Ed25519 keys from bypassing the verification requirement. This example uses
plain public keys; SSH certificates require their corresponding SK types
and separately managed certificate trust.

Supply the primary and spare public keys together in one entry per account.
The central-only Match rule excludes the user's own authorized_keys file;
review existing AuthorizedKeysCommand and certificate/CA trust separately.
Nitrokey Pro/Start use an OpenPGP smartcard integration instead of this FIDO2
flow. Their ordinary SSH signatures cannot prove a per-login PIN check to
sshd through PubkeyAuthOptions.

```yaml
openssh_match_groups:
  ssh-fido:
    AuthenticationMethods: publickey
    PubkeyAcceptedAlgorithms: sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com
    PubkeyAuthOptions: touch-required verify-required
    AuthorizedKeysFile: /etc/ssh/authorized_keys.d/%u
openssh_authorized_keys:
  - user: alice
    exclusive: true
    key: |
      {{ lookup('ansible.builtin.file', 'files/alice-nitrokey.pub') }}
      {{ lookup('ansible.builtin.file', 'files/alice-spare.pub') }}
```

### Optional public key and Google Authenticator TOTP

Install the distribution's package providing pam_google_authenticator.so
and enroll each affected account separately. The module validates TOTP
locally; a Google account or online Google verification is not required.
Compatible TOTP applications can hold the enrolled secret. Protect the
per-user secret file with user ownership and mode 0600, keep clocks
synchronized and store recovery codes separately. Do not place secrets or
QR codes in inventory or logs.

Configure /etc/pam.d/sshd through the distribution's supported PAM mechanism.
Its authentication path must require `auth required pam_google_authenticator.so`
without `nullok`, and must not contain a success path bypassing the OTP check.
Preserve native account and session processing. This is a PAM fragment, not
a replacement file: retaining the native password authentication stack may
require the account password as well as the OTP; an OTP-only authentication
stack requires a deliberate, separately managed PAM configuration. A global
PAM OTP requirement also affects other keyboard-interactive logins, so align
PAM scope with the selected group.

The existing account must belong to ssh-totp. The comma in
`publickey,keyboard-interactive:pam` requires both methods in sequence;
a space would introduce alternative authentication paths. PasswordAuthentication
remains disabled, but PAM can still request a password over keyboard-interactive.
The role retains UsePAM yes; it does not modify the authentication stack.

Enable keyboard-interactive on the connecting client for these destinations
as shown below, or with `ssh -o KbdInteractiveAuthentication=yes HOST`.
A private SSH key and a TOTP seed are both possession credentials; their
combination alone does not guarantee two distinct factor categories.
Retaining a required account password plus TOTP adds knowledge and possession.
TOTP is phishable; prefer verified hardware-key authentication where suitable.
Avoid overlapping FIDO/TOTP groups unless Match precedence is deliberately
designed and checked with sshd -T -C and an actual login.

```yaml
openssh_match_groups:
  ssh-totp:
    AuthenticationMethods: publickey,keyboard-interactive:pam
    KbdInteractiveAuthentication: 'yes'
openssh_client_hosts:
  '*.admin.example.net':
    KbdInteractiveAuthentication: 'yes'
```

### Optional idle administrative session timeout

Close idle session channels after 15 minutes on OpenSSH versions supporting ChannelTimeout.

```yaml
openssh_match_groups:
  ssh-admins:
    ChannelTimeout: session=15m
```

## References

- [OpenSSH client configuration](https://man.openbsd.org/ssh_config.5)
- [OpenSSH server configuration](https://man.openbsd.org/sshd_config.5)
- [OpenSSH key generation](https://man.openbsd.org/ssh-keygen.1)
- [Nitrokey FIDO2 SSH](https://docs.nitrokey.com/en/nitrokeys/features/fido2/ssh)
- [Nitrokey OpenPGP SSH](https://docs.nitrokey.com/en/nitrokeys/features/openpgp-card/ssh/index)
- [Google Authenticator PAM](https://github.com/google/google-authenticator-libpam/blob/master/README.md)
- [NIST authentication factors](https://pages.nist.gov/800-63-4/sp800-63/model/)
- [OpenSSH DH parser](https://github.com/openssh/openssh-portable/blob/master/dh.c)
- [Red Hat crypto policies](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/using-the-system-wide-cryptographic-policies_security-hardening)
- [SUSE OpenSSH hardening](https://documentation.suse.com/sles/15-SP7/html/SLES-all/cha-ssh.html)
- [Ubuntu SSH cryptography](https://ubuntu.com/server/docs/explanation/crypto/openssh-crypto-configuration/)
- [CIS RHEL 9 mappings](https://github.com/ComplianceAsCode/content/blob/master/products/rhel9/controls/cis_rhel9.yml)
- [DISA STIG RHEL 9 mappings](https://github.com/ComplianceAsCode/content/blob/master/products/rhel9/controls/stig_rhel9.yml)
- [BSI TR-02102-4](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR02102/BSI-TR-02102-4.pdf?__blob=publicationFile)

## Author

[Jonas Mauer](https://github.com/jomrr)

## License

This project is licensed under the MIT License.
See [LICENSE](LICENSE) for the full license text.

Copyright (c) 2019-2026 Jonas Mauer.
