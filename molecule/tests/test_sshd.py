import os

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


def test_sshd_active(host):
    assert host.service("sshd").is_running is True

def test_ssh_create_key(host):
    cmd = host.run('yes | ssh-keygen -q -t rsa -N "" -f ~/.ssh/id_rsa >/dev/null')
    assert cmd.rc == 0
    cmd = host.run('cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys')
    assert cmd.rc == 0

def test_ssh_login(host):
    cmd = host.run('ssh -oStrictHostKeyChecking=no localhost')
    assert cmd.rc == 0
