# -*- coding: utf-8 -*-
# @Author: shiyan

import os
import sys
import datetime,time
import subprocess
import re
import socket
import json
import loadcheck,semcheck,rwsemcheck,mutexcheck,alidiagnose,perf
from time import sleep

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append("%s/../"%(os.path.dirname(os.path.abspath(__file__))))
import utils
import collect_data
import ossre

if sys.version[0] == '2':
    reload(sys)
    sys.setdefaultencoding('utf8')

def main():

    ret = {}
    ret['success'] = 'true'
    ret['status'] = 0
    ret['version'] = "1.1"
    ret['fields'] = {}
    ret['fields']['CONFIG'] = {}
    ret['fields']['CONFIG']['PARAM'] = {}
    ret['fields']['CONFIG']['PARAM']['SCHED'] = {}
    ret['fields']['CONFIG']['PARAM']['MEM'] = {}
    ret['fields']['CONFIG']['PARAM']['IO'] = {}
    ret['fields']['CONFIG']['PARAM']['NET'] = {}
    ret['fields']['CONFIG']['PARAM']['MISC'] = {}
    ret['fields']['CONFIG']['HOTFIX'] = {}
    ret['fields']['CONFIG']['summary'] = ""
    ret['fields']['cust'] = {}
    ret['fields']['cust']['CONFIG'] = {}
    ret['fields']["summary"] = ""

    try:
        ossre.check_sched_params(ret)
        ossre.check_mem_params(ret)
        ossre.check_io_params(ret)
        ossre.check_net_params(ret)
        ossre.check_misc_params(ret)

        print ret['fields']['CONFIG']['summary'] 

        f = open("/tmp/configcheck.log", "w+")
        f.write(json.dumps(ret,ensure_ascii=False))
        f.close()
    except:
        ret['fields']["summary"] += "%s\n解析异常！\n"%summary
        f = open("/tmp/configcheck.log", "w+")
        f.write(json.dumps(ret,ensure_ascii=False))
        f.close()
        import traceback
        traceback.print_exc()
        print "configcheck exception!"

if __name__ == "__main__":
    if os.path.isfile("/tmp/configcheck.log"):
        cmd = 'echo "" > /tmp/configcheck.log'
        output = os.popen(cmd)
        output.close()
        print "/tmp/configcheck.log exist"
    else:
        print "/tmp/configcheck.log not exist"
    main()
            
