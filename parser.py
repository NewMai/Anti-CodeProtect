

# import ida_kernwin
# How to run script in ida pro:  ALT + F7

# Ref: https://blog.csdn.net/qq_35056292/article/details/89421793

import os
import sys

import idc
import idautils
import idaapi
# import ida_bytes


# Segment operation examples: https://www.programcreek.com/python/example/88326/idautils.Segments

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


class SegmInfo():
    def __init__(self):
        self.m_name = ""
        self.m_startAddr = 0
        self.m_endAddr = 0
        self.m_className = ""

def getAllSegments():
    segs = list()
    si = SegmInfo()
    i = 0
    for ea in idautils.Segments():
        seg = idaapi.getseg(ea)
        si.m_name = idc.SegName(ea)
        si.m_startAddr = int(idc.SegStart(ea))
        si.m_endAddr = int(idc.SegEnd(ea))
        si.m_className = idaapi.get_segm_class(seg)
        segs.append(si)
        print "[%d]" % (i)
        print "Segment name: %s" % (si.m_name)
        print "Segment start address: 0x%08x" % (si.m_startAddr)
        print "Segment end address: 0x%08x" % (si.m_endAddr)
        print "Segment class name: %s" % (si.m_className)
        i += 1
    return segs


def addSegmentAtLast(segs, segSize):
    si = SegmInfo()
    si.m_startAddr = segs[-1].m_endAddr
    si.m_endAddr = si.m_startAddr + segSize
    si.m_name = ".MySeg"
    si.m_className = "CODE"

    # https://www.hex-rays.com/products/ida/support/idapython_docs/
    # startea - linear address of the start of the segment
    # endea - linear address of the end of the segment this address will not belong to the segment 'endea' should be higher than 'startea'
    # base - base paragraph or selector of the segment. a paragraph is 16byte memory chunk. If a selector value is specified, the selector should be already defined.
    # use32 - 0: 16bit segment, 1: 32bit segment, 2: 64bit segment
    # align - segment alignment. see below for alignment values
    # comb - segment combination. see below for combination values.
    ret = idc.AddSeg(si.m_startAddr, si.m_endAddr, 0, 2, 0, 0)
    if ret == False:
        print "Create segment failed"
        return None

    # Reset this segment
    byte = 0x90
    for ea in range(si.m_startAddr, si.m_endAddr, 1):
        PatchByte(ea, byte)

    # Set segment's attribute
    # https://reverseengineering.stackexchange.com/questions/2394/how-can-i-change-the-read-write-execute-flags-on-a-segment-in-ida
    # idc.SetSegmentAttr(si.m_startAddr, idc.SEGATTR_PERM, idc.SEGPERM_EXEC | idc.SEGPERM_WRITE | idc.SEGPERM_READ)
    idc.SetSegmentAttr(si.m_startAddr, idc.SEGATTR_PERM, 1 | 2 | 4)

    return si

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


def rewriteToBinaryFile(srcFile, baseAddr):
    addr = None
    mcode = None
    i = 0
    j = 0
    ea = 0
    byte = 0
    offset = 0
    isFirstOne = True
    with open(srcFile, "r") as fr:
        for line in fr:
            line = line.strip()
            (addr, mcode) = getAddressAndMachineCode(line)
            if addr == None:
                continue
            if isFirstOne == True:
                offset = baseAddr - addr
                isFirstOne = False
            addr += offset
            print "[%d]Patching address 0x%08X" % (j, addr)
            j += 1
            for i in range(0, len(mcode)):
                byte = mcode[i]
                ea = addr + i
                # print "[%d]Patching address 0x%08X by 0x%02x" % (i, ea, byte)
                ret = PatchByte(ea, byte)
                if ret == False:
                    x = Byte(ea)
                    if x == byte:  # The same byte will patch failed
                        continue
                    print "Error when patching at address 0x%08X with byte 0x%02x" % (ea, byte)
                    return None
            (addr, mcode) = None, None
            # if j > 30:
            #     break  # Debug
        pass
    pass


def main():

    srcFile = "bblInstEx.log"
    baseAddr = 0
    print ""
    print "Patching..."

    # testFunc()



    segs = getAllSegments()
    si = addSegmentAtLast(segs, 0x10000)
    baseAddr = si.m_startAddr


    rewriteToBinaryFile(srcFile, baseAddr)

    print "Finished."
    print ""

main()

