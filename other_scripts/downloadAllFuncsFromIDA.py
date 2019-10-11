
import os
import sys

import idc
import idautils
import idaapi



# Including all info of a basic function
class FunctionInfo():
    def __init__(self):    # private function
        self.m_startAddr = 0
        self.m_endAddr = 0
        self.m_ins = list()
        self.m_insCount = 0
        self.m_funcName = ""

def downloadFuncs():
    funcs = list()
    func = FunctionInfo()
    i = 0
    j = 0
    k = 0
    line = ""
    startEA, endEA = 0, 0
    for segEA in idautils.Segments():
        print "[%d] Segment EA : %016x" % (i, segEA)
        i += 1 
        j = 0
        for fnEA in idautils.Functions(segEA, SegEnd(segEA)):
            print "[%d] Function EA : %016x" % (j, fnEA) 
            j += 1
            fnName = idc.GetFunctionName(fnEA)
            func = FunctionInfo()
            func.m_startAddr = fnEA
            func.m_funcName = fnName
            k = 0
            for (startEA, endEA) in idautils.Chunks(fnEA):
                print "[%d] Chunks" % (k)
                k += 1
                for head in idautils.Heads(startEA, endEA):
                    # s = "%s : %x : %s" % (fnName, head, GetDisasm(head))
                    # print s
                    line = "%016x|%s" % (head, GetDisasm(head))
                    func.m_ins.append(line)
            func.m_endAddr = endEA
            funcs.append(func)
    return funcs

# Output functions to file
def outputFuncs(outFile, funcs):
    i = 0
    j = 0
    s = ""
    line = ""
    func = FunctionInfo()
    with open(outFile, "w") as fw:
        s = "Total functions count %d" % (len(funcs))
        fw.write(s + "\n")
        for i in range(0, len(funcs)):
            func = funcs[i]
            s = "----Trace:%s----" % (func.m_funcName)
            fw.write(s + "\n")
            for j in range(0, len(func.m_ins)):
                line = func.m_ins[j]
                fw.write(line + "\n")
            s = "----"
            fw.write(s + "\n")
    pass


#
# Download functions from IAD Pro
#
# ALT + F7 in IDA Pro: downloadAllFuncsFromIDA.py
#

def main():
    prefix = ""
    outFile = prefix + "funcsFromIDA.asm"


    print "Starting..."
    funcs = downloadFuncs()
    outputFuncs(outFile, funcs)
    print "Total function count %d" % (len(funcs))
    print "Finished!"


main()

