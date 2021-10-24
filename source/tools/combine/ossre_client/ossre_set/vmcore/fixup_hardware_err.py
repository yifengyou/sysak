# -*- coding: utf-8 -*-

import os
import sys
import time
import subprocess
import re
import vmcore_const

if sys.version[0] == '2':
    reload(sys)
    sys.setdefaultencoding('utf8')

def fixup_issue_status(column, ret=None):
    result = False

    if (column['dmesg'].find("[Hardware Error]") >= 0 and
        column['dmesg'].find("Internal error: synchronous external abort") >= 0):
        result = True
        column['status'] = vmcore_const.STATUS_HWERROR

    return result
