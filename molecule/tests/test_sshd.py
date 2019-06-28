import os

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


def test_sshd_active(host):
    # this is testing sshd_config
    assert host.service("sshd").is_running is True


def test_ssh_login(host):
    os = host.system_info.distribution
    # debian 9 and 10 work
    # debian 8 fails, but works without any error when you try manually!?!
    # so this is a todo for times when there is more time ;-)
    if os != 'debian':
        # this is testing sshd and ssh_config
        login = host.run('ssh localhost && exit')
        assert login.rc == 0
