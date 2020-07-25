import os

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


def test_sshd_active(host):
    # this is testing sshd_config
    os = host.system_info.distribution

    if os == 'alpine':
        assert host.service("sshd").is_running is True

    elif os == 'arch':
        assert host.service("sshd").is_running is True

    elif os == 'centos':
        assert host.service("sshd").is_running is True

    elif os == 'debian':
        assert host.service("ssh").is_running is True

    elif os == 'fedora':
        assert host.service("sshd").is_running is True

    elif os == 'manjaro':
        assert host.service("sshd").is_running is True

    elif os == 'oracle':
        assert host.service("sshd").is_running is True

    elif os == 'ubuntu':
        assert host.service("sshd").is_running is True


def test_ssh_login(host):
    # this is testing sshd and ssh_config
    login = host.run('ssh -q test@localhost exit')
    assert login.rc == 0
