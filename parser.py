

# import ida_kernwin
# How to run script in ida pro:  ALT + F7

# Ref: https://blog.csdn.net/qq_35056292/article/details/89421793

import os
import sys

import idc
import idautils
import idaapi
# import ida_bytes


def testFunc():
    ea = ScreenEA()
    print "EA:" , hex(ea)
    size = ItemSize(ea)
    line = "0xCC"
    line = GetDisasm(ea)
    print line
    res = Assemble(ea + size, {"nop"})
    print res
    byte = 0x90
    # patch_byte(ea, byte)  # apply in IDA 7.0 and later
    PatchByte(ea, byte)
    print "patched"

def getAddressAndMachineCode(line):
    addr = None
    mcode = None
    len1 = len(line)
    arr = line.split("|")
    len2 = len(arr)
    while True:
        if len1 < 16 or "|" not in line:
            break
        if len2  < 2:
            break
        ta = arr[0]   # The first one is the address
        tb = arr[-1]  # The last one is the machine code
        addr = int(ta.strip(), 16)
        mcode = bytearray.fromhex(tb)  # Covert "aabb0011" to '\xaa\xbb\x00\x11'
        break
    return (addr, mcode)


def rewriteToBinaryFile(srcFile):
    addr = None
    mcode = None
    i = 0
    j = 0
    ea = 0
    byte = 0
    with open(srcFile, "r") as fr:
        for line in fr:
            line = line.strip()
            (addr, mcode) = getAddressAndMachineCode(line)
            if addr == None:
                continue
            print "[%d]Patching address 0x%08X" % (j, addr)
            j += 1
            for i in range(0, len(mcode)):
                byte = mcode[i]
                # print "[%d]Patching address 0x%08X by 0x%02x" % (i, addr, byte)
                PatchByte(ea + i, byte)
            (addr, mcode) = None, None
            # if j > 3:
            #     break  # Debug
        pass
    pass


def main():

    srcFile = "bblInstEx.log"
    print ""
    print "Patching..."

    # testFunc()
    rewriteToBinaryFile(srcFile)

    print "Finished."
    print ""

main()

