# -*- coding: utf-8 -*-

import os
import sys
import time
import subprocess
import re
import sqlite3
import vmcore_const

if sys.version[0] == '2':
    reload(sys)
    sys.setdefaultencoding('utf8')

def fixup_issue_status(column, ret=None):
    result = False
    #if xxx:
    #print( "%s match %s"%(column['name'],__name__))
    #    result = True
    return result


