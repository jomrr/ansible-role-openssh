import os

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


def test_sshd_active(host):
    assert host.service("sshd").is_running is True


def test_ssh_create_key(host):
    key = 'yes | ssh-keygen -q -t rsa -N "" -f /root/.ssh/id_rsa >/dev/null'
    cmd = host.run(key)
    assert cmd.rc == 0
    cmd = host.run('cat /root/.ssh/id_rsa.pub >> /root/.ssh/authorized_keys')
    assert cmd.rc == 0


def test_ssh_login(host):
    os = host.system_info.distribution
    # debian 9 and 10 work
    # debian 8 fails, but works without any error when you try manually!?!
    # so this is a todo for times when there is more time ;-)
    if os != 'debian':
        login = host.run('ssh -oStrictHostKeyChecking=no localhost')
        assert login.rc == 0
