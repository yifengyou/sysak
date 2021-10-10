# -*- coding: utf-8 -*-

import os
import sys
import time
import subprocess
import re

if sys.version[0] == '2':
    reload(sys)
    sys.setdefaultencoding('utf8')

"""
Check following features
[30411947.512175] WARNING: at lib/list_debug.c:53 __list_del_entry+0x63/0xd0()
......
[30411947.676255] Call Trace:
......
[30411947.726550]  [<ffffffff8152f11a>] dst_destroy+0x2a/0xd0

"""
line_pattern = re.compile(r'.+[0-9]+\]\s+\[<[0-9a-f]+>\][? ]* (\S+)\+0x')
def fixup_issue_status(column, ret=None):
    result = False

    if (column['dmesg'].find('] dst_destroy+') > 0 and
          column['dmesg'].find('WARNING: at lib/list_debug.c') > 0 and
          column['vertype'] == 310):       
        prev_warning = 0
        prev_calltrace = 0
        lines = column['dmesg'].split('\n')
        for r in lines:
            if r.find("WARNING: at lib/list_debug.c") > 0:
                prev_warning = 1
                continue
            if r.find("Call Trace:") > 0 and prev_warning == 1:
                prev_calltrace = 1
                continue
            m = line_pattern.match(r)
            if m:
                if m.group(1) == 'dst_destroy' and prev_calltrace == 1:
                    print( "%s match %s"%(column['name'],__name__))
                    column['commitid'] = ('https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=5037e9ef9454917b047f9f3a19b4dd179fbf7cd4')
                    column['status'] = 4
                    result = True
                    break
    return result


