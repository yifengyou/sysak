# -*- coding: utf-8 -*-
# @Author: lichen

import json
import time
import os,sys
import socket
import datetime,time
import subprocess
import re
import inspect

if sys.version[0] == '2':
    import httplib
    import md5
elif sys.version[0] == '3':
    import http.client as httplib
    from hashlib import md5
# define the severity level of OS exceptions.
SEVERE_LEVEL=["fatal","critical","error","warning","info"]

def intersect_strings(array1, array2):
    ret = []

    for str in array1:
        if str in array2:
            ret.append(str)

    return ret

def format_result(kbase='',category='',desc='',
	commitid='',cause='',solution='',added=''):
    result = ''
    if len(category) > 0:
        result += "问题类型:%s,"%(category)
    if len(desc) > 0:
        result += "问题描述:%s,"%(desc)
    if len(kbase) > 0:
        result += '知识库链接: %s,'%(kbase)
    if len(commitid) > 0:
        result += '社区修复补丁: %s,'%(commitid)
    if len(cause) > 0:
        result += '故障原因: %s,'%(cause)
    if len(solution) > 0:
        result += '修复建议: %s,'%(solution)
    if len(added) > 0:
        result += '%s'%(added)
    return result

def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True

def is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True

def is_valid_ip(ip):
    """Validates IP addresses.
    """
    return is_valid_ipv4_address(ip) or is_valid_ipv6_address(ip)

def get_ip_by_input():
    ipaddr = raw_input("请输入合法的IP地址，格式如10.10.10.10:")
    if not is_valid_ip(ipaddr):
        ipaddr = raw_input("IP地址不合法，请重新输入，格式如10.10.10.10:")
        if not is_valid_ip(ipaddr):
            return ''
    return ipaddr

def get_input_str(question):
    return raw_input(question)


def get_input_int(question):
    value = raw_input(question)
    try:
        value = int(value)
    except:
        value = -1
        pass
    return value

def post_ossre_diag(diagdata):
    return

def get_script_result(sn,data):
    mod = inspect.getmodule(inspect.stack()[1][0])
    if mod.__name__ in data:
        ret = data[mod.__name__]
        return ret
    else:
        return None

def cache_script_result(sn,data,ret):
    mod = inspect.getmodule(inspect.stack()[1][0])
    if len(mod.__name__) > 0:
        data[mod.__name__] = ret

cache_data = {}
def set_cache_data(data):
    cache_data = data

def get_cache_data():
    return cache_data

def get_tsar_path(data=None):
    if data == None:
        data = get_cache_data()
    if data == None:
        if os.path.exists('/usr/local/bin/tsar2'):
            return '/usr/local/bin/tsar2'
        elif os.path.exists('/usr/bin/tsar'):
            return '/usr/bin/tsar'
        else:
            return ''

    if 'path' not in data:
        data['path']={}
    if 'tsar' in data['path']:
        return data['path']['tsar']
    if os.path.exists('/usr/local/bin/tsar2'):
        data['path']['tsar']='/usr/local/bin/tsar2'
    elif os.path.exists('/usr/bin/tsar'):
        return '/usr/bin/tsar'
    else:
        data['path']['tsar']=''
    return data['path']['tsar']


class Logger(object):
    def __init__(self, filename="/var/log/sysak/ossre.log"):
        if not os.path.exists("/var/log/sysak"):
            os.mkdir("/var/log/sysak",0755);
        self.log = open(filename, "w+")

    def write(self, message):
        self.log.write(message)
        self.log.flush()

    def flush(self):
        pass

print_logger = None

def get_logger():
    global print_logger
    if not print_logger:
        print_logger = Logger()
    return print_logger

