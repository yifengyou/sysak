# -*- coding: utf-8 -*-

import os
import sys
import time
import subprocess
import re
import sqlite3

if sys.version[0] == '2':
    reload(sys)
    sys.setdefaultencoding('utf8')

def fixup_issue_status(column, ret=None):
    result = False
    value = ()
    if column['crashkey'].find("gup_pte_range") >= 0  and column['vertype'] == 310:
        print( "%s match %s"%(column['name'],__name__))
        result = True
        column['commitid'] = 'cbef8478bee55775ac312a574aad48af7bb9cf9f'
        column['status'] = 4
    return result
