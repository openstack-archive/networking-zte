# Copyright (c) 2014 Hewlett-Packard Development Company, L.P.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


"""
1. copy all_l3_agent_scheduler.py to ....neutron/scheduler/. ;
2. copy zenic_agent.py to ....neutron/agent/. ;
3. copy neutron-zenic-agent to /usr/bin/. ;
4. copy neutron-zenic-agent.service to /usr/lib/systemd/system/. ;
5. systemctl enable neutron-zenic-agent.service;
6. systemctl start neutron-zenic-agent.service;
7. systemctl status neutron-zenic-agent.service;  #check service status
8. openstack-config --set /etc/neutron/neutron.conf
default router_scheduler_driver
neutron.scheduler.all_l3_agents_scheduler.AllL3AgentsScheduler;
9. systemctl restart neutron-server.service;
10. systemctl status neutron-server.service;
"""

import os
import time
import commands

a1 = '/usr/lib/python2.7/site-packages/neutron/scheduler/'
a2 = '/usr/lib/python2.7/site-packages/neutron/agent/'
a3 = '/usr/lib/python2.7/site-packages/neutron/common/'

zenic_agent_src_files = {
    'all_l3_agents_scheduler.py': a1,
    'zenic_agent.py': a2,
    'neutron-zenic-agent': '/usr/bin/',
    'neutron-zenic-agent.service': '/usr/lib/systemd/system/',
    'proxy_server_manager.py': a3
}


def install_zenic_agent():
    copy_files_chmod()
    append_service()


def restart_zenic_agent_service_and_check():
    full_args = 'systemctl restart neutron-zenic-agent.service'
    excute_command(full_args)
    time.sleep(2)
    full_args = 'systemctl status neutron-zenic-agent.service'
    output = excute_command(full_args)
    if 'active (running)' not in output:
        print('Restarting neutron-zenic-agent.service fail.')
        return False
    return True


def update_zenic_agent():
    restart_zenic_agent_service_and_check()


def copy_files_chmod():
    curdir = os.path.abspath(os.curdir)
    for file_name in zenic_agent_src_files:
        full_args = 'cp -r %s/zenic/%s %s.' % \
            (curdir, file_name, zenic_agent_src_files[file_name])
        excute_command(full_args)
        if '.py' not in file_name and '.service' not in file_name:
            full_args = 'chmod +x -R %s%s' % \
                        (zenic_agent_src_files[file_name], file_name)
            excute_command(full_args)


def append_service():
    b1 = 'neutron.scheduler.all_l3_agents_scheduler.AllL3AgentsScheduler'
    enable_and_start_service('neutron-zenic-agent.service')
    stop_and_disable_service('neutron-l3-agent.service')
    config_l3_agents_scheduler(b1)
    restart_server_service_and_check()


def enable_and_start_service(service_full_name):
    full_args = 'systemctl enable %s' % service_full_name
    excute_command(full_args)
    full_args = 'systemctl start %s' % service_full_name
    excute_command(full_args)
    time.sleep(2)
    full_args = 'systemctl status %s' % service_full_name
    output = excute_command(full_args)
    if 'active (running)' not in output:
        print('Restarting %s fail.' % service_full_name)
        return False
    return True


def stop_and_disable_service(service_full_name):
    full_args = 'systemctl stop %s' % service_full_name
    excute_command(full_args)
    full_args = 'systemctl disable %s' % service_full_name
    excute_command(full_args)


def clean_l3_agent_service():
    full_args = 'systemctl disable neutron-l3-agent.service'
    excute_command(full_args)
    full_args = 'systemctl stop neutron-l3-agent.service'
    excute_command(full_args)


def config_l3_agents_scheduler(agent_scheduler_class):
    full_args = 'openstack-config --set /etc/neutron/neutron.conf ' \
                'DEFAULT router_scheduler_driver %s' % agent_scheduler_class
    excute_command(full_args)


def restart_server_service_and_check():
    full_args = 'systemctl restart neutron-server.service'
    excute_command(full_args)
    time.sleep(2)
    full_args = 'systemctl status neutron-server.service'
    output = excute_command(full_args)
    if 'active (running)' not in output:
        print('Restarting neutron-server.service fail.')
        return False
    return True


def excute_command(full_args):
    try:
        print('cmd:%s' % full_args)
        output = commands.getoutput(full_args)
        return output
    except Exception as e:
        print('error')
        msg = 'excute_command: %s failed, error: %s.' % (full_args, e)
        raise ValueError(msg)


def uninstall_zenic_agent():
    remove_files()
    clean_service()


def disable_zenic_agent_service():
    full_args = 'systemctl disable neutron-zenic-agent.service'
    excute_command(full_args)


def stop_service(service_full_name):
    full_args = 'systemctl stop %s' % service_full_name
    excute_command(full_args)


def clean_service():
    c1 = 'neutron.scheduler.l3_agent_scheduler.ChanceScheduler'
    enable_and_start_service('neutron-l3-agent.service')
    stop_and_disable_service('neutron-zenic-agent.service')
    config_l3_agents_scheduler(c1)
    restart_server_service_and_check()


def remove_files():
    for file_name in zenic_agent_src_files:
        full_args = 'rm -rf %s%s' % \
            (zenic_agent_src_files[file_name], file_name)
        excute_command(full_args)
