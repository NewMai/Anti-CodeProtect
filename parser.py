

# import ida_kernwin
# How to run script:  ALT + F7

# Ref: https://blog.csdn.net/qq_35056292/article/details/89421793

import os
import sys

import idc
import idautils
import idaapi



def testFunc():
    ea = ScreenEA()
    print "EA:" , hex(ea)
    size = ItemSize(ea)
    line = "0xCC"
    line = GetDisasm(ea)
    print line
    res = Assemble(ea + size, {"nop"})
    print res

def main():
    print ""
    print "Starting my script..."

    testFunc()

    print "End my script."
    print ""

main()

