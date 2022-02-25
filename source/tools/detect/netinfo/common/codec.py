# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     codec
   Description :
   Author :       liaozhaoyan
   date：          2022/1/17
-------------------------------------------------
   Change Activity:
                   2022/1/17:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'
import base64

rotateN = 7


def encodeWord(word):
    r = base64.b64encode(word)[::-1]
    return r[rotateN:] + r[:rotateN]


def decodeWord(word):
    w = word[-rotateN:] + word[:-rotateN]
    return base64.b64decode(w[::-1]).decode()


decodeList = ("user", "pass")


def decodeArgs(qDict, arg, val):
    if arg in decodeList:
        qDict[arg] = decodeWord(val)
    else:
        qDict[arg] = val

if __name__ == "__main__":
    pass
