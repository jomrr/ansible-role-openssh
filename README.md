# ansible-role-ssh

Ansible role for setting up ssh.

## Supported Platforms

* Debian 8, 9
* Ubuntu 16.04, 18.04

## Requirements

Ansible 2.7 or higher is recommended.

## Variables

Variables for this

| variable | default value in defaults/main.yml | description |
| -------- | ---------------------------------- | ----------- |
| role_ssh_enabled | false | determine whether role is enabled (true) or not (false) |

## Dependencies

None.

## Example Playbook

```yaml
---
# play: test-site
# file: site.yml

- hosts: ssh-servers
  roles:
    - role: ansible-role-ssh
```

## License and Author

- Author:: Jonas Mauer (<jam@kabelmail.net>)
- Copyright:: 2019, Jonas Mauer

Licensed under MIT License;
See LICENSE file in repository.

## References

- [FreeBSD Manual Pages - sshd_config\(5\)](https://www.freebsd.org/cgi/man.cgi?sshd_config)
- [Uni Konstanz - Starke Authentifizioerungsmethoden](https://www.kim.uni-konstanz.de/e-mail-und-internet/it-sicherheit-und-privatsphaere/sicherer-server-it-dienst/linux-fernadministration-mit-pam-und-ssh/starke-authentifizierungsmethoden/)
- [SSH absichern - Stephan Klein](https://klein-gedruckt.de/2015/04/ssh-absichern/)
- [OpenSSH Tip: Check Syntax Errors before Restarting SSHD Server](https://www.cyberciti.biz/tips/checking-openssh-sshd-configuration-syntax-errors.html)
- [BetterCrypto.org: OpenSSH](https://bettercrypto.org/#_openssh)
- [Abe Singer - Hostbased SSH](https://www.usenix.org/system/files/login/articles/09_singer.pdf)
- [DNS-based SSH host key verification](https://ayesh.me/sshfp-verification)
- [Hardening SSH](https://medium.com/@jasonrigden/hardening-ssh-1bcb99cd4cef)