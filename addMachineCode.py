
# This file is used to run in Linux x64 system with pwntools installed.
# And you need to change the base address variable (g_baseAddr) before using it.

import pwn
pwn.context.arch = "x86_64"  # For 64-bit architecture
g_baseAddr = 0x400000
g_ErrLog = open("error.log", "a+")
g_ErrLog.write("\r\n")



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


def dealwithBranch(curAddr, ins):
    global g_ErrLog
    curInsSize = 2
    additionInsSize = 4
    arr = ins.split(" ")
    if len(arr) != 2 or "j" != ins[0:1]:
        return ins
    destAddr = arr[1]
    if "0x" != destAddr[0:2]:
        return ins
    curAddr = int(curAddr, 16)
    destAddr = int(destAddr, 16)
    offset = destAddr - curAddr - curInsSize
    offset2 = destAddr - curAddr
    if offset < 0x80 and offset > (-0x80): # short jmp,  2 bytes of machine code
        if offset > 0:
            ins = "%s $+%d" % (arr[0], offset2) # $ represents the address of current instruction, not the rip
        else: # offset < 0:
            ins = "%s $+%d" % (arr[0], offset2) # e.g.  jz $+-0x11 ==> jz $-0x11
    else:   # long jmp,  2+4 bytes of machine code
        offset -= additionInsSize
        if offset > 0:
            ins = "%s $+%d" % (arr[0], offset2)
        else: # offset < 0:
            ins = "%s $+%d" % (arr[0], offset2)
    return ins


def dealwithCall(curAddr, ins):
    global g_ErrLog
    curInsSize = 5
    arr = ins.split(" ")
    if len(arr) != 2 or "call" != ins[0:4]:
        return ins
    destAddr = arr[1]
    if "0x" != destAddr[0:2]:
        return ins
    curAddr = int(curAddr, 16)
    destAddr = int(destAddr, 16)
    offset = destAddr - curAddr - curInsSize
    offset2 = destAddr - curAddr
    if offset > 0:
        ins = "%s $+%d" % (arr[0], offset2)
    else: # offset < 0
        ins = "%s $+%d" % (arr[0], offset2)
    return ins


def getMachineCode(line):
    global g_baseAddr
    arr = line.split("|")
    addr = arr[0]
    ins = arr[1].lower()
    ins = dealwithPtr(ins)
    ins = dealwithBranch(addr, ins)
    ins = dealwithCall(addr, ins)
    try:
        # mcode = pwn.asm(ins, vma=g_baseAddr)
        if "nop" in ins and len(ins) > 3:
            # Unknown instruction, e.g. nop dword ptr [rax], eax
            # For the reason that we initialize all code into nop instruction at 
            #    the creation of a section
            mcode = b'\90'
        else:
            mcode = pwn.asm(ins)
    except:
        raise RuntimeError("Unknow instruction for: %s" % ins)
    ret = ""
    for i in range(0, len(mcode)):
        x = mcode[i]
        s = "%02x" % (ord(x))
        ret += s
    # Corresponding : bytes.fromhex('7370616d')
    return ret


# Get all machine code of each instruction
def getMachineCodeOfIns(bblInst_file, fileNameOut):
    #fileName = "bblInst.log"
    fileName = bblInst_file
    addr = ""
    ins = ""
    mcode = ""
    arr = list()
    i = 0
    with open(fileNameOut, "w") as fw:
        with open(fileName, "r") as f1:
            for line in f1:
                i += 1
                if i % 100 == 0:
                    print i

                # line = line[0:-2]  # for linux
                line = line.strip()

                if len(line) <= 16 or "|" not in line:    # Nothing to do
                    # print line
                    fw.write(line+ "\r\n")
                else:
                    mcode = getMachineCode(line)
                    line = "%s|%s" % (line, mcode)
                    # print line
                    fw.write(line+ "\r\n")
        pass


# python addMachineCode.py 
def main():
    fileName = "funcs.asm"
    fileNameOut = "funcsEx.asm"
    print "Starting..."
    getMachineCodeOfIns(fileName, fileNameOut)
    print "Finished!"


main()



