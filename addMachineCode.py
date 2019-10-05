
# This file is used to run in Linux x64 system with pwntools installed.
# And you need to change the base address variable (g_baseAddr) before using it.

import pwn
pwn.context.arch = "x86_64"  # For 64-bit architecture
g_baseAddr = 0x400000


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


def getMachineCode(line):
    global g_baseAddr
    arr = line.split("|")
    addr = arr[0]
    ins = arr[1].lower()
    ins = dealwithPtr(ins)
    try:
        mcode = pwn.asm(ins, vma=g_baseAddr)
    except:
        if "nop" in ins and len(ins) > 3:
            mcode = b'\90'
        else:
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
                line = line[0:-2]  # for linux
                if len(line) <= 16 or "|" not in line:    # Nothing to do
                    # print line
                    fw.write(line+ "\r\n")
                else:
                    mcode = getMachineCode(line)
                    line = "%s|%s" % (line, mcode)
                    # print line
                    fw.write(line+ "\r\n")
        pass



def main():
    fileName = "bblInst.log"
    fileNameOut = "bblInstEx.log"
    print "Starting..."
    getMachineCodeOfIns(fileName, fileNameOut)
    print "Finished!"


main()



