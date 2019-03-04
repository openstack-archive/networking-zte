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

""""
 zte sdn patch install api
"""

import commands      # noqa
import ConfigParser
import logging
import os
import time

log_file = "install.log"
back_file = "patch.backup"
save_path = "/home/sdn_patch"
version_file = "version.info"
plugin_name = "networking_zte"
code_folder = "/usr/lib/python2.7/site-packages/%s/" % plugin_name
plugin_conf = "plugin.ini"
neutorn_conf = "neutron.conf"
taas_conf = "taas_plugin.conf"
if not os.path.exists(save_path):
    os.mkdir(save_path)


def mock_action():
    print_log("doing nothing, just for unittest")


def save_log(info):
    global save_path
    save_file = os.path.join(save_path, log_file)
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s %(name)-2s %(levelname)-2s %(message)s',
        datefmt='%m-%d %H:%M',
        filename=save_file,
        filemode='a')
    logger = logging.getLogger()
    logger.info(info)


def print_log(info):
    print (info)
    save_log(info)


def excute_command(full_args):
    try:
        status, output = commands.getstatusoutput(full_args)
        save_log('cmd:%s' % full_args)
        save_log('out:[%d]%s' % (status, output))
        if status not in (0, 256, 1024):
            print_log('cmd fail:%s' % full_args)
        return (status, output)
    except Exception as e:
        print_log('cmd err:%s' % full_args)
        msg = _('excute_command: full_args=%(full_args)s failed, '
                'error: e=%(e)s.'), {'full_args': full_args, 'e': e}
        raise ValueError(msg)


def backup_old_files():
    print_log("bakup old version files:...")
    bak_path = os.path.join(save_path, 'bak')
    if os.path.exists(bak_path):
        full_args = "rm -rf %s" % bak_path
        excute_command(full_args)
    os.mkdir(bak_path)
    full_args = "cp -af %s %s/%s" % (code_folder, bak_path, plugin_name)
    print_log(full_args)
    excute_command(full_args)
    full_args = "cp -af /etc/neutron/%s %s/%s" % (plugin_conf, bak_path,
                                                  plugin_conf)
    print_log(full_args)
    excute_command(full_args)
    full_args = "cp -af /etc/neutron/%s %s/%s" % (neutorn_conf, bak_path,
                                                  neutorn_conf)
    print_log(full_args)
    excute_command(full_args)
    full_args = "cp -af /etc/neutron/%s %s/%s" % (taas_conf, bak_path,
                                                  taas_conf)
    print_log(full_args)
    excute_command(full_args)


def get_sys_info(section, option):
    global save_path
    fpath = os.path.join(save_path, back_file)
    conf = ConfigParser.ConfigParser()
    conf.read(fpath)
    try:
        value = conf.get(section, option)
    except BaseException:
        value = None

    print_log("read conf: [%s] %s = %s" % (section, option, value))
    return value


def get_version_info(section, option):
    conf = ConfigParser.ConfigParser()
    conf.read(version_file)
    try:
        value = conf.get(section, option)
    except BaseException:
        value = None

    save_log("read conf: [%s] %s = %s" % (section, option, value))
    return value


def set_sys_info(section, option, value):
    global save_path
    fpath = os.path.join(save_path, back_file)
    conf = ConfigParser.ConfigParser()
    conf.read(fpath)
    if not conf.has_section(section):
        conf.add_section(section)
    try:
        conf.set(section, option, value)
    except BaseException:
        save_log("save err: [%s] %s = %s" % (section, option, value))

    conf.write(open(fpath, 'w'))
    save_log("save conf: [%s] %s = %s" % (section, option, value))


def excute_commads(cmdslist):
    for cmd in cmdslist:
        print_log(cmd)
        excute_command(cmd)


def remove_files(filelist):
    for file_name in filelist:
        file_path = os.path.join(
            filelist[file_name],
            os.path.basename(file_name))
        if os.path.isfile(file_path):
            full_args = "rm -f %s" % file_path
        elif os.path.isdir(file_path):
            full_args = "rm -rf %s" % file_path
        else:
            print_log("rm miss: %s" % file_path)
            continue  # you must not return here, one error not all error
        print_log(full_args)
        excute_command(full_args)


def append_files(filelist):
    remove_files(filelist)
    for file_name in filelist:
        file_path = os.path.join(os.getcwd(), file_name)
        if os.path.isfile(file_path):
            full_args = "cp -fp %s %s" % (file_path, filelist[file_name])
        elif os.path.isdir(file_path):
            full_args = "cp -rfp %s %s" % (file_path, filelist[file_name])
        else:
            print_log("cp fail: %s %s" % (file_path, filelist[file_name]))
            continue  # you must not return here, one error not all error
        print_log(full_args)
        excute_command(full_args)


def restart_service_and_check(serv_name):
    full_args = 'systemctl restart %s' % serv_name
    print_log(full_args)
    excute_command(full_args)
    time.sleep(3)
    return check_service_only(serv_name)


def check_service_only(serv_name):
    full_args = 'systemctl status %s' % serv_name
    print_log(full_args)
    status, output = excute_command(full_args)
    if 'active (running)' not in output:
        print_log('Restarting %s fail.' % serv_name)
        return False
    return True


def restart_openstack_and_check():
    full_args = 'openstack-service restart'
    print_log(full_args)
    excute_command(full_args)
    time.sleep(5)
    full_args = 'openstack-service status'
    print_log(full_args)
    status, output = excute_command(full_args)
    if 'inactive' in output:
        print_log('Restarting openstack fail.')
        return False
    if 'failed' in output:
        print_log('Restarting openstack fail.')
        return False
    return True


'''
flag default value is false,check and restart service
if flag value is true only check service
'''


def check_services(servslist, flag=False):
    checkerror = 0
    for serv in servslist:
        print_log("checking service: %s" % serv)
        if flag:
            if not check_service_only(serv):
                checkerror += 1
        else:
            if not restart_service_and_check(serv):
                checkerror += 1
    if checkerror != 0:
        return False
    else:
        return True


def check_if_file_exist(filename):
    if not os.path.exists(filename):
        return False
    return True
