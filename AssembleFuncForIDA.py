
import sys
import os


g_ErrFile = open("error.log", "a+")
g_ErrFile.write("\r\n")

# Including all info of a basic block
class BlockInfo():
    def __init__(self):    # private function
        self.m_isFunc = False
        self.m_isLoc = False
        self.m_startAddr = 0
        self.m_endAddr = 0
        self.m_block = list()
        self.m_label = ""

# One FunctionInfo represents a function
class FunctionInfo():
    def __init__(self):
        self.m_funcName = ""
        self.m_bis = list()  # BlockInfos


# Get opcode from a line
# E.g. 0000000000401010|sub rsp, 0x28
def getOpCode(line):
    x = line.split("|")
    y = x[1].split(" ")
    opcode = y[0]
    return opcode

# Judge whether this is a function prologue
def isFuncPrologue(block):
    # Need to implement

    if len(block) == 0:
        return False
    opcode = getOpCode(block[0])
    if opcode == "sub" or opcode == "push":
        return True

    return False

# Whether is a normal function call
# E.g.  call 0x401000
def isExplicitFuncCall(line):
    if "call" not in line:
        return False
    if "syscall" in line:
        return False
    x = line.split("|")
    try:
        y = x[1]
        arr = y.split(" ")
        if len(arr) != 2:
            return False
        if "0x" != arr[1][0:2]:
            return False
        return True
    except:
        pass
    return False

# Whether is a branch instruction
# E.g.  jz, jmp, jnz etc.
def isExplicitBranch(line):
    try:
        ins = line.split("|")[1]
        arr = ins.split(" ")
        if len(arr) != 2:
            return False
        opCode = arr[0].lower()
        if "j" != opCode[0:1]:
            return False
        if "0x" != arr[1][0:2]:
            return False
        return True
    except:
        pass
    return False

# Recode hex from 0x123 to 0123h
def recodeHex(line):
    arr = line.split("|")
    if len(arr) < 2:
        return line  # Nothing to do
    addr = arr[0]
    ins = arr[1].lower()
    while True:
        idx = ins.find("0x")
        if idx < 0:
            line = "%s|%s" % (addr, ins)
            return line  # Nothing to do
        i = idx + 2
        while i < len(ins):
            if (ins[i] >= '0' and ins[i] <= '9') or (ins[i] >= 'a' and ins[i] <= 'f'):
                i += 1
            else:
                break
        left = ins[0:idx]
        right = ins[i:]
        mid = ins[idx+2:i]
        ins = "%s0%sh%s" % (left, mid, right)
    return line


# Get one block from file pointer : f 
# Return a class of the block's info
def getOneBlock(f):
    isFirstInst = 1
    bi = BlockInfo()
    addr = ""
    while True:
        line = f.readline()
        if line == "":         # Reached the file end
            break
        if "Trace:" in line:   # Omit block's header
            continue
        if "----" in line:     # Reached the end of one block
            break
        addr = line[0:16]      # Get the start address of this block
        if isFirstInst == 1:
            bi.m_startAddr = int(addr, 16)
            isFirstInst = 0
        line2 = line[0:-1]
        # line2 = recodeHex(line[0:-1]) # omit '\n'
        bi.m_block.append(line2) 
        bi.m_endAddr = int(addr, 16)
    bi.m_label = "loc_%x" % (bi.m_startAddr)   # Default as a label
    # if True == isFuncPrologue(bi.m_block):
    #     # We can infer this is a function
    #     bi.m_label = "sub_%x PROC PUBLIC" % (bi.m_startAddr)
    #     bi.m_isFunc = True
    return bi


# Get all block from file
# Return a block list, each item comtains a basic block and its starting address
def getBlocksFromFile(bblInst_file):
    #fileName = "bblInst.log"
    fileName = bblInst_file
    blocks = list()

    blkSet = set()  # For remove redundency block
    i = 0
    bi = BlockInfo()
    with open(fileName, "r") as f1:
        while True:
            bi = getOneBlock(f1)
            if len(bi.m_block) <= 0 or bi.m_startAddr == "":    # Reached the end
                break
            if bi.m_startAddr in blkSet:
                continue   # Ignore this repeated block
            blkSet.add(bi.m_startAddr)
            blocks.append(bi)
    # print "Read [%s] complited!" % fileName
    return blocks


def addAsmFileHeader():
    # For VC++ ml.exe compiler
    print ".CODE"
    print ""

def addAsmFileEnder():
    # For VC++ ml.exe compiler
    print "END"
    print ""

# Collect functions calls from ida log file
def collectFuncCallsFromIdaFile():
    calls = set()
    idaFile = "ida.log"
    if os.path.exists(idaFile) == True:
        with open(idaFile, "r") as fr:
            for line in fr:
                line = line.strip() # Remove "\r\n"
                arr = line.split(":")
                t = arr[1].strip()
                arr = t.split(" ")
                for addr in arr:
                    x = int(addr.strip(), 16)
                    calls.add(x)
    return calls

# Collect all the function in this bblInst.log file from call instructions
# Return a set of the functions' address
def collectFuncCalls(blocks):
    global g_ErrFile
    calls = set()
    calls = collectFuncCallsFromIdaFile()
    line = ""
    data = BlockInfo()
    arrs = list()
    addr = 0
    for blocki in blocks:
        block = blocki.m_block
        for line in block:
            if "call" in line and "syscall" not in line:
                try:
                    data = line.split("|")[1]
                    arrs = data.split(" ")
                    if len(arrs) == 2:
                        addr = arrs[1]
                        addr = int(addr, 16)
                        calls.add(addr)
                except:
                    errInfo = "%s  : NOT a normal function call.\n" % (line)
                    g_ErrFile.write(errInfo)
    return calls

# Collect all the labels in this bblInst.log file
# Return a set of the labels' address
def collectLabels(blocks, calls):
    lbls = set()
    for bi in blocks:
        if bi.m_startAddr not in calls:
            lbls.add(bi.m_startAddr)
    return lbls

# Normalize the function calls and labels
# And return a set of functions
def processFuncCallAndLabels(blocks):
    addr = 0
    len1 = len(blocks)
    funcs = list()
    isFirstFunc = True
    funcStatus = 0
    func = FunctionInfo()
    line = ""
    len2 = 0
    calls = collectFuncCalls(blocks)
    lbls = collectLabels(blocks, calls)
    for i in range(0, len1):
        len2 = len(blocks[i].m_block)
        addr = blocks[i].m_startAddr;
        if addr in calls or isFirstFunc == True:
            if isFirstFunc == True:
                pass
            else:
                funcs.append(func)
            func = FunctionInfo()  # Clear previous block, start a new function
            func.m_funcName = "sub_%x" % (addr)
            funcStatus = 1  # Function start
            isFirstFunc = False
            blocks[i].m_isFunc = True
            blocks[i].m_label = "sub_%x PROC PUBLIC" % (addr)
        else:
            funcStatus = 2  # Function body
        # for j in range(0, len2):
        #     line = blocks[i].m_block[j]
        #     if True == isExplicitFuncCall(line):
        #         arr1 = line.split("|")
        #         arr2 = arr1[1].split(" ")
        #         t = int(arr2[1].strip(), 16)
        #         x = "%s|%s sub_%x" % (arr1[0], arr2[0], t)
        #         blocks[i].m_block[j] = x
        #     elif True == isExplicitBranch(line):
        #         arr1 = line.split("|")
        #         arr2 = arr1[1].split(" ")
        #         t = int(arr2[1].strip(), 16)
        #         x = "%s|%s loc_%x" % (arr1[0], arr2[0], t)
        #         blocks[i].m_block[j] = x
        func.m_bis.append(blocks[i])
    return funcs

# Recode all the instructions
def recodeInstructions(blocks):
    len1 = len(blocks)
    line = ""
    len2 = 0
    for i in range(0, len1):
        len2 = len(blocks[i].m_block)
        for j in range(0, len2):
            blocks[i].m_block[j] = recodeHex(blocks[i].m_block[j])
    pass


def assembleFunc(fileName):
    blocks = list()
    arrs = None
    line = ""
    tline = ""
    i = 0
    j = 0
    preFuncName = ""

    # Get all block from files
    blocks = getBlocksFromFile(fileName)
    
    # Sort by address of the block
    blocks.sort(key = lambda b:b.m_startAddr)

    # Normalize function call
    funcs = processFuncCallAndLabels(blocks)

    # Recode address in instructions
    # recodeInstructions(blocks)

    addAsmFileHeader()
    for i in range(0, len(funcs)):
        func = funcs[i]
        print "%s PROC PUBLIC" % (func.m_funcName)
        for j in range(0, len(func.m_bis)):
            bi = func.m_bis[j]
            block = bi.m_block
            if j > 0:
                 print "%s:" % (bi.m_label)
            for k in range(0, len(block)):
                line = block[k]
                ins = line

                # if "|" in line:
                #     ins = "    %s" % (line.split("|")[1])
                # else:
                #     ins = "    %s" % (line)
                # print ins

                print "    %s" % (ins)
        print "%s ENDP" % (func.m_funcName)
        print ""
    addAsmFileEnder()
    pass

#
# 
# python AssembleFuncForIDA.py > funcs.asm
#
def main(): 
    fileName = "bblInst.log"
    # print "Starting..."
    assembleFunc(fileName)
    # print "Finished!"

main()


