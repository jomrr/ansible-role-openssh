# ansible-role-ssh [![Build Status](https://travis-ci.org/jam82/ansible-role-ssh.svg?branch=dev)](https://travis-ci.org/jam82/ansible-role-ssh)

Ansible role for setting up openssh.

  - [Supported Platforms](#Supported-Platforms)
  - [Requirements](#Requirements)
  - [Defaults and Variables](#Defaults-and-Variables)
    - [defaults/main/main.yml](#defaultsmainmainyml)
    - [defaults/main/ssh.yml](#defaultsmainsshyml)
    - [defaults/main/sshd.yml](#defaultsmainsshdyml)
    - [defaults/main/sshd_authentication.yml](#defaultsmainsshdauthenticationyml)
    - [defaults/main/sshd_directives.yml](#defaultsmainsshddirectivesyml)
    - [defaults/main/sshd_gssapi.yml](#defaultsmainsshdgssapiyml)
    - [defaults/main/sshd_kerberos.yml](#defaultsmainsshdkerberosyml)
  - [Dependencies](#Dependencies)
  - [Scenarios and example playbooks](#Scenarios-and-example-playbooks)
  - [License and Author](#License-and-Author)
  - [References](#References)

## Supported Platforms

* Amazon Linux 2
* Arch Linux
* Centos 6, 7
* Debian 8, 9, 10
* Raspbian 8, 9, 10
* OpenSuse Leap 15
* Oracle Linux 6, 7
* Ubuntu 16.04, 18.04

## Requirements

Ansible 2.7 or higher is required for defaults/main/*.yml to work.

OpenSSH Version 5.7 or above.

## Defaults and Variables

The default values for all variables are stored in the following files:

* defaults/main/main.yml
* defaults/main/ssh.yml
* defaults/main/sshd.yml
* defaults/main/sshd_authentication.yml
* defaults/main/sshd_directives.yml
* defaults/main/sshd_gssapi.yml
* defaults/main/sshd_hostbased.yml
* defaults/main/sshd_kerberos.yml

### defaults/main/main.yml

The file main.yml contains variables with defaults values that affect both, ssh client and sshd (the server).

| variable | default value | description |
| -------- | ------------- | ----------- |
| role_ssh_enabled | false | determine whether role is enabled (true) or not (false) |

The set of allowed algorithms is stored in the dict ssh_algorithms and is used to intersect with the detected supported algorithms:

```yaml
ssh_algorithms:
  ciphers:
    - chacha20-poly1305@openssh.com
    - aes256-gcm@openssh.com
    - aes128-gcm@openssh.com
    - aes256-ctr
    - aes192-ctr
    - aes128-ctr
  kexs:
    - sntrup4591761x25519-sha512@tinyssh.org
    - curve25519-sha256@libssh.org
    - curve25519-sha256
    - diffie-hellman-group18-sha512
    - diffie-hellman-group16-sha512
    - diffie-hellman-group14-sha256
    - diffie-hellman-group-exchange-sha256
  hostkeys:
    - ssh-ed25519-cert-v01@openssh.com
    - rsa-sha2-512-cert-v01@openssh.com
    - rsa-sha2-256-cert-v01@openssh.com
    - ssh-rsa-cert-v01@openssh.com
    - ssh-ed25519
    - rsa-sha2-512
    - rsa-sha2-256
    - ssh-rsa
  macs:
    - hmac-sha2-512-etm@openssh.com
    - hmac-sha2-256-etm@openssh.com
    - umac-128-etm@openssh.com
    - hmac-sha2-512
    - hmac-sha2-256
```

### defaults/main/ssh.yml

This file is for /etc/ssh/ssh_config default settings.

| variable | default value | description |
| -------- | ------------- | ----------- |
| ssh_enabled | True | enable configuration of /etc/ssh/ssh_config |
| ssh_deploy_key | '~/.ssh/id_ed25519.pub' | local publickey that is added to remote users authorized_keys file, so you do not lock yourself out, because the default configuration of this role is to only allow pubkey authentication. |
| ssh_conf_backup | 'no' | create a backup when replacing /etc/ssh/ssh_config |
| ssh_host_config | {} | host specific configuration, for example:<br/> <code>ssh_host_config:<br/>&nbsp;&nbsp;testhost:<br/>&nbsp;&nbsp;&nbsp;&nbsp;X11Forwarding: 'yes'<br/>&nbsp;&nbsp;&nbsp;&nbsp;GSSAPIAuthentication: 'yes'</code> |
| ssh_port | '22' | default port ssh tries to connect to |
| ssh_address_family | 'inet' | address family type |
| ssh_challenge_response_authentication | 'yes' | Enable challenge response (keyboard-interactive) authentication |
| ssh_enable_ssh_keysign | 'no' | Enable ssh-keysign, must be enabled on a client, if you want to do hostbased authentication |
| ssh_gssapi_authentication | 'no' | Enable GSSAPI authentication |
| ssh_hostbased_authentication | 'no' | Enable hostbased authentication |
| ssh_identity_files | [ '\~/.ssh/identity', '\~/.ssh/id_rsa', '\~/.ssh/id_ed25519' ] | List of paths where ssh looks for identity files |
| ssh_password_authentication | 'yes' | Enable password authentication |
| ssh_pubkey_authentication | 'yes' | Enable public key athentication |
| ssh_rekey_limit_data | '512M' | Rekey limit (data), this is after 512M of data exchanged |
| ssh_rekey_limit_time | '1800' | Rekey limit (time), this is after 1800 seconds |
| ssh_strict_host_key_checking | 'ask' | Enable strict host key checking (known_hosts) |
| ssh_test_create_key | False | This should be left to False, as it is used for testing only. When True, then an ssh key is generated for the remote user root and added to his authorized_keys file. In the pytest module `test_sshd.py` this is used to perform a login with `ssh -q localhost exit` to check if pubkey authentication is working. |

### defaults/main/sshd.yml

This file is for general /etc/ssh/sshd_config default settings.

| variable | default value | description |
| -------- | ------------- | ----------- |
| sshd_enabled | true | enable configuration of /etc/ssh/sshd_config |
| sshd_moduli_file | '/etc/ssh/moduli' | location of DH moduli file |
| sshd_moduli_minimum | 3072 | minimum length od DH parameters |
| sshd_host_key_regenerate | false | regenerate ssh host keys |
| sshd_rsa_keylength | 4096 | length of RSA keys that are created by the role |
| sshd_port | 22 | sshd listen port |
| sshd_address_family | 'inet' | sshd address family |
| sshd_listen_addr_v4 | [ "{{ ansible_default_ipv4.address \| default(ansible_all_ipv4_addresses[0]) }}" ] | IPv4 interface addresses sshd binds to |
| sshd_listen_addr_v6 | [] | IPv6 interface addresses sshd binds to |


... and many more tbd.

### defaults/main/sshd_authentication.yml

| variable | default value | description |
| -------- | ------------- | ----------- |
| sshd_login_grace_time | '60' | time to wait for login in seconds |
| sshd_permit_root_login | 'no' |  |
| sshd_max_auth_tries | 3 |  |
| sshd_max_sessions | 3 |  |
| sshd_pubkey_auth | 'yes' |  |
| sshd_authorized_keys_file | '%h/.ssh/authorized_keys' | |
| sshd_password_auth | 'no' | |
| sshd_challenge_auth | 'no' | |
| sshd_use_pam | 'yes' | With password and challenge response auth disabled, this runs pam session checks without pam authentication.  |
| sshd_use_dns | 'yes' | Look up the remote host name and check that the resolved host name or the remote IP address maps back to the very same IP address. |

### defaults/main/sshd_directives.yml

| variable | default value | description |
| -------- | ------------- | ----------- |
| sshd_deny_users | [] | Deny ssh login for listed users. |
| sshd_allow_users | [] | Allow ssh login for listed users only. |
| sshd_deny_groups | [] | Deny ssh login for listed groups. |
| sshd_allow_groups | [] | Allow ssh login for listed groups only. |
| sshd_per_group_settings | {} | Group specific settings defined via `Match Group` directive. |
| sshd_per_user_settings | {} | User specific settings defined via `Match User` directive. |

### defaults/main/sshd_gssapi.yml

| variable | default value | description |
| -------- | ------------- | ----------- |

### defaults/main/sshd_kerberos.yml

| variable | default value | description |
| -------- | ------------- | ----------- |

## Dependencies

None.

## Scenarios and example playbooks

This role by default configures pubkey authentication only, using reasonably secure settings. If you find a flaw, please feel free to comment.

### Running on localhost

### Public Key Authentication only for remote host

This one is the easiest, just generate a local ssh key with

```shell
ssh-keygen -t ed25519
```
if you do not have one.

Be sure to adjust the host pattern `ssh-servers`to a host group defined in your inventory file.

Then you can use a playbook like this to deploy:

```yaml
---
# play: test-site
# file: site.yml

- hosts: ssh-servers
  roles:
    - role: ansible-role-ssh
```

If you already have an existing rsa key, change the following variable:

```yaml
ssh_deploy_key: '~/.ssh/id_rsa.pub'
```

You can do this in your inventory (host or group variable) or just from the commandline:

```shell
ansible-playbook site.yml --extra-vars '{"ssh_deploy_key": "~/.ssh/id_rsa.pub"}'
```

## License and Author

* Author:: Jonas Mauer (<jam@kabelmail.net>)
* Copyright:: 2019, Jonas Mauer

Licensed under MIT License;
See LICENSE file in repository.

## References

* [FreeBSD Manual Pages - sshd_config\(5\)](https://www.freebsd.org/cgi/man.cgi?sshd_config)
* [Uni Konstanz - Starke Authentifizioerungsmethoden](https://www.kim.uni-konstanz.de/e-mail-und-internet/it-sicherheit-und-privatsphaere/sicherer-server-it-dienst/linux-fernadministration-mit-pam-und-ssh/starke-authentifizierungsmethoden/)
* [SSH absichern - Stephan Klein](https://klein-gedruckt.de/2015/04/ssh-absichern/)
* [OpenSSH Tip: Check Syntax Errors before Restarting SSHD Server](https://www.cyberciti.biz/tips/checking-openssh-sshd-configuration-syntax-errors.html)
* [BetterCrypto.org: OpenSSH](https://bettercrypto.org/#_openssh)
* [Abe Singer - Hostbased SSH](https://www.usenix.org/system/files/login/articles/09_singer.pdf)
* [DNS-based SSH host key verification](https://ayesh.me/sshfp-verification)
* [Hardening SSH](https://medium.com/@jasonrigden/hardening-ssh-1bcb99cd4cef)
* [How to create an SSH certificate authority](https://jameshfisher.com/2018/03/16/how-to-create-an-ssh-certificate-authority/)
* [SSH Host Key Signing - ein unterschätztes Feature](https://www.sipgate.de/blog/ssh-host-key-signing-ein-unterschaetztes-feature)
