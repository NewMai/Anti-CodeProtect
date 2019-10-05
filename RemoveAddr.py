
import sys
import os


def removeAddr(fileName):
    ins = ""
    with open(fileName, "r") as f1:
        for line in f1:
            line = line[0:-1]
            if len(line) < 16:
                print line
            else:
                try:
                    ins = line.split("|")[1]
                    print ins
                except:
                    print line


#
# 
# python RemoveAddr.py > asm2.asm
#
def main(): 
    fileName = "asm.asm"
    # print "Starting..."
    removeAddr(fileName)
    # print "Finished!"

main()


