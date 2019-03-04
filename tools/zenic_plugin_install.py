from configobj import ConfigObj
import ConfigParser
import netaddr
import sdn_patch_api as api
import sys

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2017 ZTE, Inc.
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
 1. zenic plugin install include ml2 proxydriver install
    and zenic l3 agent install
 2. zenic plugin install shell be combine to one and support
    path/unpatch operation
"""

"""
1. copy proxydriver to /usr/lib/python2.7/site-packages/neutron/plugins,
   chmod +x;
2. modify /etc/neutron/plugin.ini, add proxydriver to mechanism_drivers,
   add[RESTPROXY]; servers&server_auth, values must be specified by users;
3. modify /usr/lib/python2.7/site-packages/neutron-2015.1.0-py2.7.egg-info
   /entry_points.txt, under [neutron.ml2.mechanism_drivers], add proxydriver=
   neutron.plugins.proxydriver.proxy_neutron_driver:ProxyMechanismDriver
4. restart neutron-server
"""

"""
1. copy all_l3_agent_scheduler.py to ....neutron/scheduler/. ;
2. copy zenic_agent.py to ....neutron/agent/. ;
3. copy neutron-zenic-agent to /usr/bin/. ;
4. copy neutron-zenic-agent.service to /usr/lib/systemd/system/. ;
5. systemctl enable neutron-zenic-agent.service;
6. systemctl restart neutron-zenic-agent.service;
7. systemctl status neutron-zenic-agent.service;  #check service status
8. openstack-config --set /etc/neutron/neutron.conf default router_scheduler_
   driver neutron.scheduler.all_l3_agents_scheduler.AllL3AgentsScheduler;
9. systemctl restart neutron-server.service;
10. systemctl status neutron-server.service;
"""

copy_files = {
    'zenic/all_l3_agents_scheduler.py': '/usr/lib/python2.7/site-'
    'packages/neutron/scheduler/',
    'zenic/zenic_agent.py': '/usr/lib/python2.7/site-packages/neutron/agent/',
    'zenic/neutron-zenic-agent': '/usr/bin/',
    'zenic/neutron-zenic-agent.service': '/usr/lib/systemd/system/',
    'zenic/proxy_server_manager.py': '/usr/lib/python2.7/site-packages'
    '/neutron/common/',
    'fw/zenic_fwaas_plugin.py': '/lib/python2.7/site-packages/neutron_fwaas'
    '/services/firewall/',
    'fw/zenic_firewall_pool.py': '/lib/python2.7/site-packages/neutron_fwaas'
    '/services/firewall/',
    'fw/zenic_server_manager.py': '/lib/python2.7/site-packages/neutron'
    '/common/',
    'ztetaas': '/lib/python2.7/site-packages/neutron_taas/services/taas/'
    'service_drivers',
    'qos/zenic_qos_plugin.py': '/lib/python2.7/site-packages/neutron/'
    'services/qos/',
    'qos/zenic_qos_pool.py': '/lib/python2.7/site-packages/neutron/'
    'services/qos/',
}

install_setservs = (
    'chmod 755 /usr/bin/neutron-zenic-agent',
    'systemctl disable neutron-l3-agent.service',
    'systemctl stop neutron-l3-agent.service',
)

enable_zenic_agent = (
    'systemctl enable neutron-zenic-agent.service',
)

install_chkservs = (
    'openstack-nova-api.service',
    'neutron-server.service',
    'neutron-zenic-agent.service',
)

install_chkcmccservs = (
    'neutron-server.service',
    'neutron-zenic-agent.service',
)

remove_setservs = (
    'systemctl disable neutron-zenic-agent.service',
    'systemctl stop neutron-zenic-agent.service',
    'systemctl enable neutron-l3-agent.service',
)

remove_zenic_servs = (
    'systemctl disable neutron-zenic-agent.service',
    'systemctl stop neutron-zenic-agent.service',
)

# remove_zenic_files = {
#     'zenic/neutron-zenic-agent': '/usr/bin/',
#     'zenic/neutron-zenic-agent.service': '/usr/lib/systemd/system/',
# }

remove_chkservs = (
    'neutron-l3-agent.service',
    'neutron-server.service',
)


def RAW_INPUT(str):
    return raw_input(str)


def recover_old_version():
    # /usr/lib/python2.7/site-packages/
    # neutron-2015.1.1-py2.7.egg-info/entry_points.txt
    full_args = "find /usr/lib -name entry_points.txt | grep neutron-"
    status, output = api.excute_command(full_args)

    full_args = "sed -i '/^proxydriver/d' %s" % output
    api.excute_command(full_args)

    full_args = "sed -i '/^zte_firewall/d' %s" % output
    api.excute_command(full_args)

    full_args = "sed -i '/^zte_qos/d' %s" % output
    api.excute_command(full_args)

    full_args = "sed -i '/^mechanism_drivers/s/,proxydriver//' " \
                "/etc/neutron/plugin.ini"
    api.excute_command(full_args)

    remove_git_code()

    api.remove_files(copy_files)


def recover_config(configs):

    # /etc/neutron/neutron.conf
    config_neutron = configs["config_neutron"]
    config_neutron['DEFAULT']['router_scheduler_driver'] = \
        'neutron.scheduler.l3_agent_scheduler.ChanceScheduler'
    #trunk
    try:
        del config_neutron['vlan_trunk']['trunk_drivers']
    except Exception as e:
        api.print_log("There is no key of %s in the neutron.conf" % e)
    config_neutron.write()

    # /etc/neutron/plugin.ini
    # taas
    config_plugin = configs["config_plugin"]
    taas_function = get_taas_para(config_plugin)
    api.save_log("get_taas_para taas_function = %s" % taas_function)
    if taas_function == 'tecs2.0':
        reset_taas_config("/etc/neutron/taas_plugin.conf")
    elif taas_function == 'tecs6.0':
        reset_taas_config("/etc/neutron/plugin.ini")
    elif taas_function == 'tecs3.0':
        reset_taas_config("/etc/neutron/plugin.ini")
    elif taas_function == 'openstack':
        reset_taas_config("/etc/neutron/taas_plugin.ini")
    else:
        api.save_log("recover config can not find taas function!")

    if check_op_version(config_plugin):
        op_version = config_plugin["RESTPROXY"]["op_version"]
    else:
        op_version = "False"
    if op_version != "bigcloud_K":
        # security_group_api
        config_nova = configs["config_nova"]
        config_nova['DEFAULT']['security_group_api'] = 'nova'
        config_nova.write()

    full_args = "sed -i '/^\[RESTPROXY/d' /etc/neutron/plugin.ini"
    api.excute_command(full_args)

    full_args = "sed -i '/^enable_qos/d' /etc/neutron/plugin.ini"
    api.excute_command(full_args)

    full_args = "sed -i '/^enable_M_qos/d' /etc/neutron/plugin.ini"
    api.excute_command(full_args)

    full_args = "sed -i '/^enable_bandwidth/d' /etc/neutron/plugin.ini"
    api.excute_command(full_args)

    full_args = "sed -i '/^enable_hierarchical_port/d' /etc/neutron/plugin.ini"
    api.excute_command(full_args)

    full_args = "sed -i '/^op_version/d' /etc/neutron/plugin.ini"
    api.excute_command(full_args)

    full_args = "sed -i '/^server_timeout/d' /etc/neutron/plugin.ini"
    api.excute_command(full_args)

    full_args = "sed -i '/^servers/d' /etc/neutron/plugin.ini"
    api.excute_command(full_args)

    full_args = "sed -i '/^server_auth/d' /etc/neutron/plugin.ini"
    api.excute_command(full_args)

    full_args = "sed -i '/^server_ssl/d' /etc/neutron/plugin.ini"
    api.excute_command(full_args)

    full_args = "sed -i '/^no_ssl_validation/d' /etc/neutron/plugin.ini"
    api.excute_command(full_args)

    full_args = "sed -i '/^enable_pre_commit/d' /etc/neutron/plugin.ini"
    api.excute_command(full_args)

    full_args = "sed -i '/^taas_function/d' /etc/neutron/plugin.ini"
    api.excute_command(full_args)

    full_args = "grep ^mechanism_drivers[[:space:]]*=.*," \
                "[[:space:]]*zte_ml2driver /etc/neutron/plugin.ini"
    status, output = api.excute_command(full_args)
    if output != '':
        full_args = "sed -i '/^mechanism_drivers/s/," \
                    "[[:space:]]*zte_ml2driver//' /etc/neutron/plugin.ini"
        api.excute_command(full_args)
    full_args = "grep ^mechanism_drivers[[:space:]]*=.*zte_ml2driver" \
                "[[:space:]]*, /etc/neutron/plugin.ini"
    status, output = api.excute_command(full_args)
    if output != '':
        full_args = "sed -i '/^mechanism_drivers/s/zte_ml2driver" \
                    "[[:space:]]*,//' /etc/neutron/plugin.ini"
        api.excute_command(full_args)

    # remove l3 router_no_schedule
    full_args = "sed -i '/^\[L3\]/d' /etc/neutron/plugin.ini"
    api.excute_command(full_args)

    full_args = "sed -i '/^router_no_schedule/d' /etc/neutron/plugin.ini"
    api.excute_command(full_args)

    full_args = "grep ^service_plugins[[:space:]]*=.*,[[:space:]]*zte_qos " \
                "/etc/neutron/neutron.conf"
    api.print_log("%s" % full_args)
    status, output = api.excute_command(full_args)
    if output != '':
        full_args = "sed -i '/^service_plugins/s/,[[:space:]]*zte_qos//' " \
                    "/etc/neutron/neutron.conf"
        api.print_log("%s" % full_args)
        api.excute_command(full_args)
        full_args = "sed -i '/^service_plugins/s/$/,qos/' " \
                    "/etc/neutron/neutron.conf"
        api.print_log("%s" % full_args)
        api.excute_command(full_args)

    full_args = "grep ^service_plugins[[:space:]]*=.*zte_qos[[:space:]]*, " \
                "/etc/neutron/neutron.conf"
    api.print_log("%s" % full_args)
    status, output = api.excute_command(full_args)
    if output != '':
        full_args = "sed -i '/^service_plugins/s/zte_qos[[:space:]]*,//' " \
                    "/etc/neutron/neutron.conf"
        api.print_log("%s" % full_args)
        api.excute_command(full_args)
        full_args = "sed -i '/^service_plugins/s/$/,qos/' " \
                    "/etc/neutron/neutron.conf"
        api.print_log("%s" % full_args)
        api.excute_command(full_args)


def set_taas_config(path):
    if api.check_if_file_exist(path):
        config_taas = ConfigObj(path, encoding='UTF8')
        if 'service_providers' not in config_taas.keys():
            config_taas['service_providers'] = {}
        config_taas['service_providers']['service_provider'] = \
            'TAAS:TAAS:networking_zte.taas.zte_taas_driver.ZTETaasDriver' \
            ':default'
        config_taas.write()
    return True


def delete_tecs2_taas_config(path):
    if api.check_if_file_exist(path):
        config_taas = ConfigObj(path, encoding='UTF8')
        if 'service_providers' in config_taas.keys():
            del config_taas['service_providers']
        config_taas.write()
    return True


def reset_taas_config(path):
    try:
        config_taas = ConfigObj(path, encoding='UTF8')
        config_taas['service_providers']['service_provider'] = \
            'TAAS:TAAS:neutron_taas.services.taas.service_drivers.' \
            'taas_rpc.TaasRpcDriver:default'
        config_taas.write()
    except Exception as e:
        api.print_log("no taas config found:%s,skip..." % e)


def remove_git_code():
    full_args = "rpm -qa|grep networking-zte|xargs rpm -e"
    api.print_log("%s" % full_args)
    api.excute_command(full_args)

    full_args = "rm -rf /usr/lib/python2.7/site-packages/networking_zte/"
    api.excute_command(full_args)


def append_config(kwargs, configs):
    config_neutron = ConfigObj('/etc/neutron/neutron.conf', encoding='UTF8')
    config_neutron['DEFAULT']['router_scheduler_driver'] = \
        'neutron.scheduler.l3_agent_scheduler.ChanceScheduler'

    # trunk
    if 'vlan_trunk' in config_neutron.keys():
        config_neutron['vlan_trunk']['trunk_drivers'] = 'networking_zte.' \
                                                        'trunk.driver'
    else:
        config_neutron['vlan_trunk'] = {}
        config_neutron['vlan_trunk']['trunk_drivers'] = 'networking_zte.' \
                                                        'trunk.driver'
    config_neutron.write()
    #taas
    if kwargs["taas_function"] == 'tecs2.0':
        if not set_taas_config("/etc/neutron/taas_plugin.conf"):
            return False
    elif kwargs["taas_function"] == 'tecs6.0':
        if not set_taas_config("/etc/neutron/plugin.ini"):
            return False
    elif kwargs["taas_function"] == 'tecs3.0':
        if not set_taas_config("/etc/neutron/plugin.ini"):
            return False
    elif kwargs["taas_function"] == 'openstack':
        if not api.check_if_file_exist('/etc/neutron/taas_plugin.ini'):
            api.print_log("use taas funtion of openstack while taas_plugin.ini"
                          " does not exist!")
            remove_git_code()
            return False
        if not set_taas_config("/etc/neutron/taas_plugin.ini"):
            return False
    else:
        api.save_log("append_config can not find taas function!")

    # plugin.ini
    full_args = "sed -i '$a \[RESTPROXY]' /etc/neutron/plugin.ini"
    api.excute_command(full_args)

    full_args = "sed -i '$a \enable_qos=%s' %s" % (
        kwargs["enable_qos"], "/etc/neutron/plugin.ini")
    api.excute_command(full_args)

    full_args = "sed -i '$a \enable_M_qos=%s' %s" % (
        kwargs["enable_M_qos"], "/etc/neutron/plugin.ini")
    api.excute_command(full_args)

    full_args = "sed -i '$a \op_version=%s' %s" % (
        kwargs["op_version"], "/etc/neutron/plugin.ini")
    api.excute_command(full_args)

    full_args = "sed -i '$a \enable_bandwidth=%s' %s" % (
        kwargs["enable_bandwidth"], "/etc/neutron/plugin.ini")
    if kwargs["enable_bandwidth"] is not None:
        api.excute_command(full_args)

    full_args = "sed -i '$a \enable_hierarchical_port=%s' %s" % (
        kwargs["enable_hierarchical_port"], "/etc/neutron/plugin.ini")
    if kwargs["enable_hierarchical_port"] is not None:
        api.excute_command(full_args)

    full_args = "sed -i '$a \server_timeout=100' %s" % (
        "/etc/neutron/plugin.ini")
    api.excute_command(full_args)

    full_args = "sed -i '$a \servers=%s' %s" % (
        kwargs["servers"], "/etc/neutron/plugin.ini")
    api.excute_command(full_args)

    full_args = "sed -i '$a \server_auth=%s' %s" % (
        kwargs["server_auth"], "/etc/neutron/plugin.ini")
    api.excute_command(full_args)

    full_args = "sed -i '$a \server_ssl=%s' %s" % (
        kwargs["ssl"], "/etc/neutron/plugin.ini")
    api.excute_command(full_args)

    full_args = "sed -i '$a \\no_ssl_validation=%s' %s" % (
        kwargs["ssl_validation"], "/etc/neutron/plugin.ini")
    api.excute_command(full_args)

    full_args = "sed -i '$a \\enable_pre_commit=%s' %s" % (
        kwargs["pre_commit"], "/etc/neutron/plugin.ini")
    api.excute_command(full_args)

    full_args = "sed -i '$a \\taas_function=%s' %s" % (
        kwargs["taas_function"], "/etc/neutron/plugin.ini")
    api.excute_command(full_args)

    full_args = "sed -i 's/^mechanism_drivers *=/mechanism_drivers " \
                "=zte_ml2driver,/g' /etc/neutron/plugin.ini"
    api.excute_command(full_args)

    # add l3 router_no_schedule
    full_args = "sed -i '$a \[L3\]' /etc/neutron/plugin.ini"
    api.excute_command(full_args)

    full_args = "sed -i '$a router_no_schedule=True' /etc/neutron/plugin.ini"
    api.excute_command(full_args)

    # full_args = "sed -i '/^service_plugins/s/$/,zte_firewall/'
    #/etc/neutron/neutron.conf"
    # api.excute_command(full_args)

    if kwargs["enable_M_qos"] == "True":
        api.save_log("using M qos!")
        full_args = "grep ^service_plugins[[:space:]]*=.*,[[:space:]]*qos " \
                    "/etc/neutron/neutron.conf"
        status, output = api.excute_command(full_args)
        if output != '':
            full_args = "sed -i '/^service_plugins/s/,[[:space:]]*qos//' " \
                        "/etc/neutron/neutron.conf"
            api.excute_command(full_args)
        full_args = "grep ^service_plugins[[:space:]]*=.*qos[[:space:]]*, " \
                    "/etc/neutron/neutron.conf"
        status, output = api.excute_command(full_args)
        if output != '':
            full_args = "sed -i '/^service_plugins/s/qos[[:space:]]*,//' " \
                        "/etc/neutron/neutron.conf"
            api.excute_command(full_args)

        full_args = "sed -i '/^service_plugins/s/$/,zte_qos/' " \
                    "/etc/neutron/neutron.conf"
        api.excute_command(full_args)

    if kwargs["op_version"] != "bigcloud_K":
        # security_group_api
        config_nova = configs["config_nova"]
        config_nova['DEFAULT']['security_group_api'] = 'neutron'
        config_nova.write()

    return True


def do_tecs_patch():
    try:
        import py_compile
        full_args = 'rm -f /usr/lib/python2.7/site-packages/neutron/plugins' \
                    '/proxydriver/common/rest/znic_l2/config.py'
        status, output = api.excute_command(full_args)
        api.print_log(output)
        full_args = 'cp -af config.py ' \
                    '/usr/lib/python2.7/site-packages/neutron/plugins' \
                    '/proxydriver/common/rest/znic_l2/config.py '
        status, output = api.excute_command(full_args)
        api.print_log(output)
        py_compile.compile('/usr/lib/python2.7/site-packages/neutron/plugins/'
                           'proxydriver/common/rest/znic_l2/config.py')
        return status
    except Exception as e:
        api.print_log("The reason for the failure of patch is %s!" % e)


def do_patch(op_patch):
    try:
        full_args = 'patch /usr/lib/python2.7/site-packages/neutron/' \
                    'services/l3_router/l3_router_plugin.py ' \
                    '<%s' % op_patch
        status, output = api.excute_command(full_args)
        api.print_log(output)
        return status
    except Exception as e:
        api.print_log("The reason for the failure of patch is %s!" % e)


def handle_auto_op_version(op_version):
    if not l3_scheduler_patch(op_version):
        return False
    return restart_neutron_server()


def handle_manual_op_version(op_version, configs):
    if not l3_scheduler_patch(op_version):
        return False
    full_args = "sed -i '/^mechanism_drivers/s/zte_ml2driver,//' " \
                "/etc/neutron/plugin.ini"
    api.excute_command(full_args)
    config = configs["config_plugin"]
    mechanism_drivers = config['ml2']['mechanism_drivers']
    api.print_log("patched mechanism_drivers is %s" % mechanism_drivers)
    return restart_neutron_server()


def l3_scheduler_patch(op_version):
    if op_version == 'tecs2.0' and api.check_if_file_exist(
            '/usr/lib/python2.7/site-packages/neutron/plugins/proxydriver'
            '/common/rest/znic_l2/config.py'):
        do_tecs_patch()
    value = 0
    if op_version in ['tecs2.0', 'tecs3.0', 'tecs6.0']:
        print ('This is %s, ignore patch '
              'to l3_router_plugin...\n' % op_version)
    else:
        if op_version in ['K', 'bigcloud_K']:
            value = do_patch('l3_scheduler_k.patch')
        elif op_version is 'L':
            value = do_patch('l3_scheduler_l.patch')
        elif op_version is 'M':
            value = do_patch('l3_scheduler_m.patch')
        elif op_version is 'N':
            value = do_patch('l3_scheduler_n.patch')
        elif op_version in ['O', 'bigcloud_O']:
            value = do_patch('l3_scheduler_o.patch')
    if value not in (0, 256, 1024):
        api.print_log("patch to l3_router_plugin failed!")
        return False

    if op_version == "bigcloud_K":
        install_openvswitch()

    return True


def restart_neutron_server():
    service = (
        'neutron-server.service',
    )
    return api.check_services(service)


def remove_plugin(configs):
    check_service_plugins("uninstall")
    api.excute_commads(remove_setservs)
    remove_openvswitch(configs)
    recover_old_version()
    recover_config(configs)
    remove_rpm_folder()
    return api.check_services(remove_chkservs)


def remove_rpm_folder():
    full_args = "rm -fr /usr/lib/python2.7/site-packages" \
                "/networking_zte-*.egg-info"
    api.print_log("%s" % full_args)
    api.excute_command(full_args)


def check_service_plugins(action):
    full_args = "grep ^service_plugins /etc/neutron/neutron.conf"
    api.print_log("%s" % full_args)
    status, output = api.excute_command(full_args)
    api.print_log("action:%s,service plugins:%s" % (action, output))
    full_args = "grep ^mechanism_drivers /etc/neutron/plugin.ini"
    api.print_log("%s" % full_args)
    status, output = api.excute_command(full_args)
    api.print_log("action:%s,mechanism_drivers:%s" % (action, output))


def patch_k_qos(qos_patch):
    full_args = 'patch /usr/lib/python2.7/site-packages/networking_zte/qos/' \
                'zenic_qos_plugin.py <%s' % qos_patch
    status, output = api.excute_command(full_args)
    api.print_log(output)
    return status


def post_install(op_version):
    api.excute_commads(install_setservs)
    if op_version == 'tecs2.0':
        patch_k_qos('qos.patch')
    if op_version == "bigcloud_K":
        return api.check_services(install_chkcmccservs)
    else:
        return api.check_services(install_chkservs)


def install_plugin(kwargs, configs):
    check_service_plugins("install")
    full_args = "rpm -ivh networking-zte-*"
    api.print_log("%s" % full_args)
    api.excute_command(full_args)
    #api.append_files(copy_files)
    ret = append_config(kwargs, configs)
    if not ret:
        return ret
    return post_install(kwargs["op_version"])


def update_plugin(kwargs, configs):
    """update code"""
    check_service_plugins("update")
    remove_rpm_folder()
    recover_old_version()
    recover_config(configs)
    full_args = "rpm -Uvh networking-zte-*"
    api.print_log("%s" % full_args)
    api.excute_command(full_args)
    #api.append_files(copy_files)
    ret = append_config(kwargs, configs)
    if not ret:
        return ret
    return post_install(kwargs["op_version"])


def if_update_config():
    operation = None
    while (not operation):
        operation = RAW_INPUT(
            "whether update configuration [y/n](default is n):\n")
        if str.lower(operation) == 'n':
            return False
        elif str.lower(operation) == 'y' or operation == '':
            return True
        else:
            operation = None
    return False


def manual_input_version():
    print ('****Please select openstack version****\n')
    print ('[1] Kilo\n')
    print ('[2] Liberty\n')
    print ('[3] Mitaka\n')
    print ('[4] Newton\n')
    print ('[5] Ocata\n')
    print ('[6] bigcloud_Kilo\n')
    print ('[7] bigcloud_Ocata\n')
    print ('[8] tecs2.0\n')
    print ('[9] tecs3.0\n')
    print ('[10] tecs6.0\n')
    all_version = {'1': 'K', '2': 'L', '3': 'M', '4': 'N', '5': 'O',
                   '6': 'bigcloud_K', '7': 'bigcloud_O', '8': 'tecs2.0',
                   '9': 'tecs3.0', '10': 'tecs6.0'}
    op_version_num = None
    while (1):
        op_version_num = RAW_INPUT("Press 1 or 2 or ... 10 to select:")
        if op_version_num not in ['1', '2', '3', '4', '5', '6', '7',
                                  '8', '9', '10']:
            print ("input parameter invaild, please input again:")
            continue
        else:
            break
    return all_version[op_version_num]


def interact_menu(op_version):
    all_input_para = {}

    ip = None
    while (not ip):
        ip = RAW_INPUT("Please input zenic IP Address:\n")
        try:
            netaddr.IPAddress(ip)
            if (4 != len(ip.strip().split('.'))):
                ip = None
        except BaseException:
            ip = None

    port = 0
    while (port < 1 or port > 65535):
        port = RAW_INPUT("Please input zenic Port(default: 8181):\n")
        port = '8181' if not port else port
        try:
            port = int(port)
        except BaseException:
            port = 0

    server = ''.join([ip, ':', str(port)])
    all_input_para["servers"] = server

    user = None
    while (not user):
        user = RAW_INPUT("Please input user name:\n")

    password = None
    while (not password):
        password = RAW_INPUT("Please input password:\n")

    auth = ''.join([user, ':', password])
    all_input_para["server_auth"] = auth

    ssl_flag = None
    ssl = None
    ssl_validation = None
    while (not ssl_flag):
        ssl_flag = RAW_INPUT(
            "Please confirm whether to enable HTTPS [y/n](default is n):\n")
        if str.lower(ssl_flag) == 'n' or ssl_flag == '':
            ssl = False
            ssl_validation = True
            break
        elif str.lower(ssl_flag) == 'y':
            ssl = True
            ssl_validation = True
        else:
            ssl_flag = None
    all_input_para["ssl"] = ssl
    all_input_para["ssl_validation"] = ssl_validation
    operation = None
    enable_M_qos = None
    enable_qos = None
    while (not operation):
        try:
            operation = RAW_INPUT(
                "Please confirm whether to enable qos function [y/n]:\n")
            if str.lower(operation) == 'y':
                if op_version in ['bigcloud_K', 'bigcloud_O']:
                    enable_qos = "True"
                    enable_M_qos = "False"
                else:
                    enable_qos = "False"
                    enable_M_qos = "True"
            elif str.lower(operation) == 'n' or operation == '':
                    enable_qos = "False"
                    enable_M_qos = "False"
            else:
                operation = None
        except Exception:
            operation = None
    all_input_para["enable_qos"] = enable_qos
    all_input_para["enable_M_qos"] = enable_M_qos
    function = None
    taas_function = None
    while (not function):
        try:
            function = RAW_INPUT('Please confirm whether to enable'
                                 ' taas function [y/n]:\n')
            if str.lower(function) == 'y':
                if op_version in ['tecs2.0', 'tecs3.0', 'tecs6.0']:
                    taas_function = op_version
                else:
                    taas_function = 'openstack'
            elif str.lower(function) == 'n' or function == '':
                taas_function = 'off'
            else:
                function = None
        except Exception:
            function = None
    all_input_para["taas_function"] = taas_function

    return all_input_para


def keep_zenic_agent():
    operation = None
    while (not operation):
        operation = RAW_INPUT(
            "whether zenic_agent keep alive [y/n](default is Y):\n")
        if str.lower(operation) == 'n':
            api.excute_commads(remove_zenic_servs)
            #api.remove_files(remove_zenic_files)
        elif str.lower(operation) == 'y' or operation == '':
            return True
        else:
            operation = None
    return True


def welcome():
    api.print_log("")
    api.print_log("================================================")
    api.print_log("    ZTE SDN Plugin Installation Wizard")
    api.print_log("================================================")


def menu():
    api.print_log("")
    api.print_log("1. install")
    api.print_log("2. uninstall")
    api.print_log("3. update(eg: tecs2.0->tecs2.0)")
    api.print_log("4. update_tecs6.0(tecs2.0->tecs6.0)")
    api.print_log("5. exit")
    api.print_log("")


def operation_menu():
    menu()
    operation = None
    while (not operation):
        try:
            operation = RAW_INPUT("Please select an operation: ")
            if operation == '1':
                action = "install"
            elif operation == '2':
                action = "uninstall"
            elif operation == '3':
                action = "update"
            elif operation == '4':
                action = "update_tecs6.0"
            elif operation == '5':
                action = "exit"
            else:
                operation = None
        except Exception:
            operation = None
    return action


def check_zenic_para(configs):
    config = configs["config_plugin"]
    para = config.keys()
    if 'RESTPROXY' in para:
        return True
    else:
        return False


def install_openvswitch():
    if api.check_if_file_exist('/usr/lib/python2.7'
                               '/site-packages/neutron/plugins/ml2/drivers/'
                               'mech_agent.py'):
        full_args = 'mv /usr/lib/python2.7/site-packages/neutron/' \
                 'plugins/ml2/drivers/mech_agent.py /usr/lib/python2.7/' \
                 'site-packages/neutron/plugins/ml2/drivers/mech_agent.py_ovs'
        status, output = api.excute_command(full_args)
    update_openvswitch()


def update_openvswitch():
    full_args = 'rm -fr /usr/lib/python2.7/site-packages/neutron/plugins'\
        '/ml2/drivers/mech_agent.py'
    status, output = api.excute_command(full_args)
    full_args = 'cp mech_agent.py /usr/lib/python2.7/site-packages'\
        '/neutron/plugins/ml2/drivers/'
    status, output = api.excute_command(full_args)


def remove_openvswitch(configs):
    config = configs["config_plugin"]
    if check_op_version(config):
        op_version = config["RESTPROXY"]["op_version"]
        if op_version == "bigcloud_K":
            full_args = 'rm -fr /usr/lib/python2.7/site-packages/neutron'\
                '/plugins/ml2/drivers/mech_agent.py'
            status, output = api.excute_command(full_args)
            full_args = 'mv /usr/lib/python2.7/site-packages/neutron/plugins'\
                '/ml2/drivers/mech_agent.py_ovs /usr/lib/python2.7/'\
                'site-packages/neutron/plugins/ml2/drivers/mech_agent.py'
            status, output = api.excute_command(full_args)


def check_qos_para(config):
    if 'RESTPROXY' in config.keys():
        zenic_para = config['RESTPROXY'].keys()
        if 'enable_qos' in zenic_para:
            return True
        else:
            return False
    else:
        return False


def check_op_version(config):
    if 'RESTPROXY' in config.keys():
        zenic_para = config['RESTPROXY'].keys()
        if 'op_version' in zenic_para:
            return True
        else:
            return False
    else:
        return False


def check_m_qos_para(config):
    if 'RESTPROXY' in config.keys():
        zenic_para = config['RESTPROXY'].keys()
        if 'enable_M_qos' in zenic_para:
            return True
        else:
            return False
    else:
        return False


def check_bandwidth_para(config):
    if 'RESTPROXY' in config.keys():
        zenic_para = config['RESTPROXY'].keys()
        if 'enable_bandwidth' in zenic_para:
            return True
        else:
            return False
    else:
        return False


def check_hierarchical_port_para(config):
    if 'RESTPROXY' in config.keys():
        zenic_para = config['RESTPROXY'].keys()
        if 'enable_hierarchical_port' in zenic_para:
            return True
        else:
            return False
    else:
        return False


def check_ssl_para(config):
    if 'RESTPROXY' in config.keys():
        zenic_para = config['RESTPROXY'].keys()
        if 'server_ssl' in zenic_para and 'no_ssl_validation' in zenic_para:
            return True
        else:
            return False
    else:
        return False


def check_pre_commit_para(config):
    if 'RESTPROXY' in config.keys():
        zenic_para = config['RESTPROXY'].keys()
        if 'enable_pre_commit' in zenic_para:
            return True
        else:
            return False
    else:
        return False


def check_taas_para(config):
    if 'RESTPROXY' in config.keys():
        zenic_para = config['RESTPROXY'].keys()
        if 'taas_function' in zenic_para:
            return True
        else:
            return False
    else:
        return False


def get_taas_para(config):
    taas_function = 'off'
    if check_taas_para(config):
        taas_function = config["RESTPROXY"]["taas_function"]
        return taas_function

    # full_args = 'openstack-config --get /etc/neutron/plugin.ini '\
    #             'service_providers service_provider'
    # status, output = api.excute_command(full_args)
    # if not status:
    #     taas_function = 'tecs3.0'
    #     return taas_function
    #
    config_tass = ConfigObj('/etc/neutron/taas_plugin.conf')
    if 'service_providers' in config_tass.keys():
        if 'service_provider' in config_tass['service_providers'].keys():
            taas_function = 'tecs2.0'
    return taas_function


def get_zenic_para(configs):
    all_input_para = {}
    config = configs["config_plugin"]
    all_input_para["servers"] = config['RESTPROXY']['servers']
    ini_config = ConfigParser.ConfigParser()
    ini_config.readfp(open('/etc/neutron/plugin.ini', "r"))
    all_input_para["server_auth"] = ini_config.get("RESTPROXY", "server_auth")
    if check_qos_para(config):
        all_input_para["enable_qos"] = config['RESTPROXY']['enable_qos']
    else:
        all_input_para["enable_qos"] = "False"
    if check_bandwidth_para(config):
        all_input_para["enable_bandwidth"] = \
            config['RESTPROXY']['enable_bandwidth']
    else:
        all_input_para["enable_bandwidth"] = None
    if check_hierarchical_port_para(config):
        all_input_para["enable_hierarchical_port"] = \
            config['RESTPROXY']['enable_hierarchical_port']
    else:
        all_input_para["enable_hierarchical_port"] = None
    if check_ssl_para(config):
        all_input_para["ssl"] = config['RESTPROXY']['server_ssl']
        all_input_para["ssl_validation"] = \
            config['RESTPROXY']['no_ssl_validation']
    else:
        all_input_para["ssl"] = False
        all_input_para["ssl_validation"] = True

    if check_pre_commit_para(config):
        all_input_para["pre_commit"] = \
            config['RESTPROXY']['enable_pre_commit']
    else:
        all_input_para["pre_commit"] = "False"
    if check_m_qos_para(config):
        all_input_para["enable_M_qos"] = \
            config['RESTPROXY']['enable_M_qos']
    else:
        all_input_para["enable_M_qos"] = "False"
    all_input_para["taas_function"] = get_taas_para(config)
    api.save_log("get_taas_para taas_function = %s" %
                 all_input_para["taas_function"])

    if check_op_version(config):
        all_input_para["op_version"] = config['RESTPROXY']['op_version']
    else:
        all_input_para["op_version"] = None

    return all_input_para


def check_ml2driver_if_install(configs):
    config = configs["config_plugin"]
    drivers = config['ml2']['mechanism_drivers']
    if 'zte_ml2driver' in drivers or 'proxydriver' in drivers:
        return True
    if api.check_if_file_exist('/usr/lib/python2.7'
                               '/site-packages/networking_zte'):
        return True
    full_args = "ls /usr/lib/python2.7/site-packages/ | grep networking_zte-"
    status, output = api.excute_command(full_args)
    if "egg-info" in output:
        return True
    return False


def get_all_para(configs, op_version):
    if check_zenic_para(configs):
        all_input_para = get_zenic_para(configs)

    else:
        all_input_para = interact_menu(op_version)
        all_input_para["pre_commit"] = "False"
        all_input_para["enable_bandwidth"] = None
        all_input_para["enable_hierarchical_port"] = None

    all_input_para["op_version"] = op_version
    return all_input_para


def update_tecs_six(all_input_para):
    if api.check_if_file_exist('/usr/lib/python2.7/site-packages/neutron/'
                               'plugins/proxydriver/common/rest/znic_l2'
                               '/config.py'):
        do_tecs_patch()
    if all_input_para["op_version"] is None or all_input_para["op_version"] \
            == 'tecs2.0':
        all_input_para["op_version"] = 'tecs6.0'
    if all_input_para["taas_function"] == 'tecs2.0':
        all_input_para["taas_function"] = 'tecs6.0'
    if api.check_if_file_exist('/etc/neutron/taas_plugin.conf'):
        delete_tecs2_taas_config('/etc/neutron/taas_plugin.conf')
    return all_input_para


def refact_params(input_dict):
    # change old config version to new config version
    if 'taas_function' not in input_dict \
            or input_dict['taas_function'] == 'openstack':
        input_dict['taas_function'] = 'off'
    return input_dict


def zenic_plugin_auto_install(auto_install, configs):
    action = auto_install
    if action == 'uninstall':
        if not remove_plugin(configs):
            return 1
        else:
            return 0

    # auto install must have plugin config in plugin.ini
    if not check_zenic_para(configs):
        api.print_log("Can not find sdn plugin config in plugin.ini!")
        return 1
    # get op_version and do patch files and restart neutron-server first
    config_plugin = configs["config_plugin"]
    if check_op_version(config_plugin):
        op_version = config_plugin["RESTPROXY"]["op_version"]
        if not handle_auto_op_version(op_version):
            return 1
    else:
        api.print_log("Sorry this plugin version does not support auto "
                      "install, please use manual install instead!")
        return 1
    # auto-install only deal with rpm package
    check_service_plugins(action)
    remove_rpm_folder()
    remove_git_code()
    if action == 'install':
        full_args = "rpm -ivh networking-zte-*"
    if action == 'update':
        full_args = "rpm -Uvh networking-zte-*"
    api.print_log("%s" % full_args)
    api.excute_command(full_args)

    if not post_install(op_version):
        api.print_log("\33[30mzenic plugin %s failed, please "
                      "fix and try again!!\33[0m" % action)
        return 1
    else:
        api.print_log("\33[36mzenic plugin %s success!\33[0m" % action)
        return 0


def zenic_plugin_install(configs):
    welcome()
    op_version = manual_input_version()
    if not handle_manual_op_version(op_version, configs):
        return 1
    action = operation_menu()
    api.print_log("User select to %s plugin...\n" % action)
    if action == 'install' and check_ml2driver_if_install(configs):
        api.print_log("zenic plugin has already installed!")
        return 1
    if action == 'update' and not check_ml2driver_if_install(configs):
        api.print_log("zenic plugin has not installed! "
                      "please install first!")
        return 1

    if action == 'install':
        all_input_para = get_all_para(configs, op_version)

        api.print_log("Start to %s plugin...\n" % action)

        rtn = install_plugin(all_input_para, configs)
        if rtn:
            keep_zenic_agent()
        api.excute_commads(enable_zenic_agent)
    elif action == 'update' or action == 'update_tecs6.0':
        all_input_para = get_all_para(configs, op_version)

        all_input_para = refact_params(all_input_para)

        if action == 'update_tecs6.0':
            all_input_para = update_tecs_six(all_input_para)
        api.print_log("Start to %s plugin...\n" % action)
        rtn = update_plugin(all_input_para, configs)
        if rtn:
            keep_zenic_agent()
        api.excute_commads(enable_zenic_agent)
    elif action == 'uninstall':
        api.print_log("Start to %s plugin...\n" % action)
        rtn = remove_plugin(configs)
    else:
        rtn = True

    if rtn:
        api.print_log("\33[36mzenic plugin %s success!\33[0m" % action)
        return 0
    else:
        api.print_log("\33[30mzenic plugin %s failed, please "
                      "fix and try again!!\33[0m" % action)
        return 1


def check_environment_config():
    configs = {}
    try:
        config_neutron = ConfigObj('/etc/neutron/neutron.conf',
                                   encoding='UTF8')
    except Exception as e:
        api.print_log("There some errors in the neutron.conf %s!" % e)
        return configs
    try:
        config_plugin = ConfigObj('/etc/neutron/plugin.ini',
                                  encoding='UTF8')
    except Exception as e:
        api.print_log("There some errors in the plugin.ini %s!" % e)
        return configs
    try:
        config_nova = ConfigObj('/etc/nova/nova.conf',
                                encoding='UTF8')
    except Exception as e:
        api.print_log("There some errors in the nova.conf %s!" % e)
        return configs
    configs["config_neutron"] = config_neutron
    configs["config_plugin"] = config_plugin
    configs["config_nova"] = config_nova

    return configs


if __name__ == '__main__':
    configs = check_environment_config()
    if len(configs) != 0:
        api.print_log("------------------------------------------------------")
        version = api.get_version_info('VERSION', 'version')
        date = api.get_version_info('VERSION', 'date')
        api.print_log("version: %s = %s" % ('zenic_plugin_version', "%s" %
                                            date))
        api.backup_old_files()
        install_type = None
        if len(sys.argv) > 1:
            install_type = sys.argv[1]
            api.print_log("\nRecognizing auto: {} zenic plugin...\n".
                          format(install_type))
            rtn = zenic_plugin_auto_install(install_type, configs)
        else:
            rtn = zenic_plugin_install(configs)
        api.set_sys_info('VERSION', 'zenic_version', "kilo_v2.1.%s" % version)
        api.set_sys_info('VERSION', 'date', date)
        sys.exit(rtn)
