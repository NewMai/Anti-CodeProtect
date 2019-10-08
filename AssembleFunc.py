
import sys
import os
import pwn
pwn.context.arch = "x86_64"  # For 64-bit architecture


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
        line = line.strip()
        addr = line[0:16]      # Get the start address of this block
        if isFirstInst == 1:
            bi.m_startAddr = int(addr, 16)
            isFirstInst = 0
        bi.m_block.append(line) 
        bi.m_endAddr = int(addr, 16)
    bi.m_label = "loc_%x" % (bi.m_startAddr)   # Default as a label
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


def addAsmFileHeader(fw):
    # For VC++ ml.exe compiler
    fw.write(".CODE\n")
    fw.write("\n")


def addAsmFileEnder(fw):
    # For VC++ ml.exe compiler
    fw.write("END\n")
    fw.write("\n")

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
    # calls = collectFuncCallsFromIdaFile()
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

# Add ptr prefix, e.g. dword, qword, byte
def dealwithPtr(ins):
    if "ptr" not in ins:
        return ins
    oprand1 = ""
    arr = ins.split(",")
    if len(arr) > 1 and "ptr" in arr[1]:
        if "word" not in arr[1] and "byte" not in arr[1]:
            oprand1 = arr[0].split(" ")[-1]
            if "r" == oprand1[0:1]:
                arr[1] = arr[1].replace("ptr", "qword ptr")
            elif "e" == oprand1[0:1]:
                arr[1] = arr[1].replace("ptr", "dword ptr")
            else:
                pass
        else:
            pass
        ins = "%s,%s" % (arr[0], arr[1])
        return ins
    else:
        # Need to do
        return ins

# Get instruction's size
def getInsSize(ins):
    # Use pwn module in linux
    mcode = pwn.asm(ins)
    ret = len(mcode)
    return ret

# Remove rip addressing by $ addressing
def dealwithRIP(line):
    global g_ErrFile
    if "rip" not in line:
        return line
    arr = line.split("|")
    if len(arr) != 2:
        return line
    ins = arr[1]
    try:

        # e.g. ins : mov qword ptr [rip+0xc059], rax
        arr1 = ins.split("[")
        arr2 = arr1[1].split("]")
        expr = arr2[0]
        opcode = expr[3:4]
        value = expr[4:]
        if opcode == "+":
            # rip+0xc059 = $+0xc059+insSize
            insSize = getInsSize(ins)
            value = int(value, 16)
            value += insSize
            expr2 = "[$+0x%x]" % (value)
            ins = "%s%s%s" % (arr1[0], expr2, arr2[1])
            line = "%s|%s" % (arr[0], ins)
        elif opcode == "-":
            # rip-0xc059 = $-(0xc059-insSize)
            insSize = getInsSize(ins)
            value = int(value, 16)
            value -= insSize
            expr2 = "[$-0x%x]" % (value)
            ins = "%s%s%s" % (arr1[0], expr2, arr2[1])
            line = "%s|%s" % (arr[0], ins)
        else:
            errMsg = "Invalide opcode in expression: %s" % (line)
            g_ErrFile.write(errMsg)
    except Exception as e:
        errMsg = "Deal with RIP failed, orginal error message: %s" % (str(e))
        g_ErrFile.write(errMsg)
    return line


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
        for j in range(0, len2):
            line = blocks[i].m_block[j]
            arr1 = line.split("|")
            ins = arr1[1]
            ins = dealwithPtr(ins)
            line = "%s|%s" % (arr1[0], ins)
            if True == isExplicitFuncCall(line):
                arr1 = line.split("|")
                arr2 = arr1[1].split(" ")
                t = int(arr2[1].strip(), 16)
                x = "%s|%s sub_%x" % (arr1[0], arr2[0], t)
                line = x
            elif True == isExplicitBranch(line):
                arr1 = line.split("|")
                arr2 = arr1[1].split(" ")
                t = int(arr2[1].strip(), 16)
                x = "%s|%s loc_%x" % (arr1[0], arr2[0], t)
                line = x
            # Remove rip addressing by $ addressing
            blocks[i].m_block[j] = dealwithRIP(line)
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

# Process all nop instructions
def processNopInstructions(blocks):
    len1 = len(blocks)
    line = ""
    len2 = 0
    for i in range(0, len1):
        len2 = len(blocks[i].m_block)
        for j in range(0, len2):
            line = blocks[i].m_block[j]
            if "nop" in line:
                arr = line.split("|")
                blocks[i].m_block[j] = "%s|nop" % (arr[0])
    pass

# Collect local label in a function
def collectLocalLabels(func):
    lbls = set()
    bis = func.m_bis
    for bi in bis:
        lbls.add(bi.m_label)
    return lbls


def assembleFunc(fileName, outFile):
    blocks = list()
    arrs = None
    line = ""
    tline = ""
    i = 0
    j = 0
    lbls = set()
    preFuncName = ""

    # Get all block from files
    blocks = getBlocksFromFile(fileName)
    
    # Sort by address of the block
    blocks.sort(key = lambda b:b.m_startAddr)

    # Normalize function call
    funcs = processFuncCallAndLabels(blocks)

    # Recode address in instructions
    recodeInstructions(blocks)

    # Process all nop instructions
    processNopInstructions(blocks)

    with open(outFile, "w") as fw:
        addAsmFileHeader(fw)
        for i in range(0, len(funcs)):
            func = funcs[i]
            resBI = list()
            s = "%s PROC PUBLIC" % (func.m_funcName)
            fw.write(s + "\n")
            lbls = collectLocalLabels(func)
            for j in range(0, len(func.m_bis)):
                bi = func.m_bis[j]
                block = bi.m_block
                if j > 0:
                    s = "%s:" % (bi.m_label)
                    fw.write(s+ "\n")
                for k in range(0, len(block)):
                    line = block[k]
                    if "loc_" in line:
                        lbl = line.split("|")[1].split(" ")[1]
                        if lbl not in lbls:
                            lbls.add(lbl)
                            bi = BlockInfo()
                            bi.m_label = lbl
                            bi.m_block.append("ret")
                            resBI.append(bi)
                    ins = line
                    if "|" in line:
                        ins = "    %s" % (line.split("|")[1])
                    else:
                        ins = "    %s" % (line)
                    fw.write(ins + "\n")
                    # s = "    %s" % (ins)
                    # fw.write(s + "\n")
            if len(resBI) > 0:
                # Dealwith unknown labels
                for k in range(0, len(resBI)):
                    s = "%s:" % (resBI[k].m_label)
                    fw.write(s + "\n")
                    fw.write("    ret\n")
            s = "%s ENDP" % (func.m_funcName)
            fw.write(s + "\n")
            fw.write("\n")
        addAsmFileEnder(fw)
    pass


# 
# Run in linux with pwntool installed.
# python AssembleFunc.py
#
def main(): 
    fileName = "bblInst.log"
    outFile = "funcsForML.asm"
    # print "Starting..."
    assembleFunc(fileName, outFile)
    # print "Finished!"

main()


