

# import ida_kernwin
# How to run script in ida pro:  ALT + F7

# Ref: https://blog.csdn.net/qq_35056292/article/details/89421793

import os
import sys

import idc
import idautils
import idaapi
# import ida_bytes

# One FunctionInfo represents a function
class FunctionInfo():
    def __init__(self):
        self.m_funcName = ""
        self.m_startAddr = 0
        self.m_endAddr = 0
        self.m_inss = list()  # instructions



g_ErrFile = open("error.log", "a+")
g_ErrFile.write("\r\n")


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

# Load one function from file
def loadOneFunc(fr):
    fi = FunctionInfo()
    line = ""
    while True:
        line = fr.readline()
        if line == "":  # End of file
            break
        line = line.strip()
        if len(line) < 6:
            continue
        if line.startswith("loc_"):
            continue  # Ignore label
        if line.startswith("sub_"):
            if line.endswith("PUBLIC"):
                fi.m_funcName = line.split(" ")[0]
            else:
                break  # End a function
            continue
        # print "Append a line: %s" % (line)
        fi.m_inss.append(line)
    # try:
    #     print "Function size: %d" % (len(fi.m_inss))
    #     line = fi.m_inss[0]
    #     print "Start address at line: %s" % (line)
    #     addr = line.split("|")[0]
    #     print "Address : %s" % (addr)
    #     fi.m_startAddr = int(addr, 16)
    #     line = fi.m_inss[-1]
    #     print "End address at line: %s" % (line)
    #     addr = line.split("|")[0]
    #     print "Address : %s" % (addr)
    #     fi.m_endAddr = int(addr, 16)
    #     print "Complete conversion!"
    # except Exception as e:
    #     print line
    #     print "Original Error:%s" % str(e)
    #     raise ValueError("Convert error!")
    if len(fi.m_inss) > 0:
        fi.m_startAddr = int(fi.m_inss[0].split("|")[0], 16)
        fi.m_endAddr = int(fi.m_inss[-1].split("|")[0], 16)
    return fi

# Load all function from file
def loadAllFuncs(funcFile):
    funcs = list()
    func = FunctionInfo()
    with open(funcFile, "r") as fr:
        while True:
            func = loadOneFunc(fr)
            if len(func.m_inss) == 0:
                break
            funcs.append(func)
    print "%d functions loaded!" % (len(funcs))
    return funcs


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
        # ret = MakeCode(ea)
        # if ret == 0:
        #     print "Make code failed at this section"
        #     return 0

    # Set segment's attribute
    # https://reverseengineering.stackexchange.com/questions/2394/how-can-i-change-the-read-write-execute-flags-on-a-segment-in-ida
    # idc.SetSegmentAttr(si.m_startAddr, idc.SEGATTR_PERM, idc.SEGPERM_EXEC | idc.SEGPERM_WRITE | idc.SEGPERM_READ)
    ret = idc.SetSegmentAttr(si.m_startAddr, idc.SEGATTR_PERM, 1 | 2 | 4)
    if ret == 0:
        print "Set segment attribute failed"
    ret = idc.SetSegClass(si.m_startAddr, si.m_className)
    if ret == 0:
        print "Set segment class failed"
    ret = idc.SetSegmentType(si.m_startAddr,  idc.SEG_CODE)
    if ret == 0:
        print "Set segment type to code failed"

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
        if len2  != 3:
            break
        ta = arr[0]   # The first one is the address
        tb = arr[-1]  # The last one is the machine code
        addr = int(ta.strip(), 16)
        mcode = bytearray.fromhex(tb)  # Covert "aabb0011" to '\xaa\xbb\x00\x11'
        break
    return (addr, mcode)


# Re-make all functions
def makeFuncForAllPatchedFunction(funcs, offset):
    for k in range(0, len(funcs)):
        func = funcs[k]

        startAddr = func.m_startAddr + offset
        endAddr = func.m_endAddr + offset

        ea = startAddr

        print "[%d] function: sub_%x" % (k, ea)
        while ea < endAddr:
            ret = MakeCode(ea)
            if ret == 0:
                ea += 1
            else:
                ea += ret

        ret = DelFunction(startAddr)
        if ret == 0:
            print "Delete function failed at 0x%08X, original address 0x%08X" % (startAddr, func.m_startAddr)
            # return False
        ret = MakeFunction(startAddr, endAddr)
        if ret == 0:
            print "Make function failed at 0x%08X, original address 0x%08X" % (startAddr, func.m_startAddr)
            # return False
        else:
            print "Make function success at 0x%08X, original address 0x%08X" % (startAddr, func.m_startAddr)
            print "    Function size 0x%x, end address 0x%08X" % (func.m_endAddr - func.m_startAddr, endAddr)
    return True


def rewriteToBinaryFile(funcs, baseAddr):
    addr = None
    mcode = None
    i = 0
    j = 0
    k = 0
    ea = 0
    byte = 0
    offset = 0
    mcodeLen = 0
    isFirstOne = True
    func = FunctionInfo()
    offset = baseAddr - funcs[0].m_startAddr

    for k in range(0, len(funcs)):
        func = funcs[k]
        print "Patching function: %s, new address: 0x%08x" % (func.m_funcName, func.m_startAddr + offset)
        for j in range(0, len(func.m_inss)):
            line = func.m_inss[j]
            (addr, mcode) = getAddressAndMachineCode(line)
            
            addr2 = addr + offset
            # print "[%d]Patching address 0x%08X, original address 0x%08X" % (j, addr2, addr)

            mcodeLen = len(mcode)
            for i in range(0, mcodeLen):
                byte = mcode[i]
                ea = addr2 + i
                # print "[%d]Patching address 0x%08X by 0x%02x" % (i, ea, byte)
                ret = PatchByte(ea, byte)
                if ret == False:
                    x = Byte(ea)
                    if x == byte:  # The same byte will patch failed
                        continue
                    print "Error when patching address 0x%08X with byte 0x%02x" % (ea, byte)
                    return None
        pass
    # Re-make all functions
    ret = makeFuncForAllPatchedFunction(funcs, offset)
    pass

# Load address range config from file
def loadConfigFromFile(cfgFile):
    lowAddr = 0
    highAddr = 0
    global g_ErrFile
    with open(cfgFile, "r") as fr:
        try:
            line = fr.readline()
            line = line.strip()
            arr = line.split(":")
            lowAddr = int(arr[1].strip(), 16)
            line = fr.readline()
            line = line.strip()
            arr = line.split(":")
            highAddr = int(arr[1].strip(), 16)

            print "Load config from file:"
            print "Lowest address: 0x%016X" % (lowAddr)
            print "Highest address: 0x%016X" % (highAddr)
        except:
            g_ErrFile.write("Load config file failed!\r\n")
    return (lowAddr, highAddr)

# Make code for this new sigment
def makeCodeAgain(si):
    ea = si.m_startAddr
    while ea < si.m_endAddr:
        ret = MakeCode(ea)
        if ret == 0:
            ea += 1
        else:
            ea += ret
    pass

# Prepare
def prepareForWritor(srcFile):

    funcs = loadAllFuncs(srcFile)

    lowAddr = funcs[0].m_startAddr
    highAddr = funcs[-1].m_endAddr

    codeSize = highAddr - lowAddr + 0x20000
    segs = getAllSegments()

    # codeSize = 0x1000 # Debug
    si = addSegmentAtLast(segs, codeSize)
    baseAddr = si.m_startAddr + lowAddr % 0x10000

    return (funcs, baseAddr, si)

def main():

    srcFile = "funcsEx.asm"
    cfgFile = "addressRange.cfg"
    baseAddr = 0
    print ""
    print "Patching..."

    # testFunc()

    # Prepare
    (funcs, baseAddr, si) = prepareForWritor(srcFile)

    rewriteToBinaryFile(funcs, baseAddr)
    makeCodeAgain(si)

    print "Finished."
    print ""

main()

