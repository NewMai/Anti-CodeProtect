
import os
import sys

# Including all info of a basic block
class BlockInfo():
    def __init__(self):    # private function
        self.m_blkCount = 0
        self.m_block = list()
        self.m_insStr = ""

# Get one block from file pointer : fr 
# Return a class of the block's info
def getOneBlock(fr):
    isFirstInst = 1
    bi = BlockInfo()
    addr = ""
    while True:
        line = fr.readline()
        if line == "":         # Reached the file end
            break
        if "Trace:" in line:   # Omit block's header
            continue
        if "----" in line:     # Reached the end of one block
            break
        line = line.strip()
        bi.m_block.append(line)
        bi.m_insStr += "|%s" % (line)
    bi.m_blkCount = len(bi.m_block)
    return bi

# Get all block from file
# Return a block list, each item comtains a basic block info
def getBlocksFromFile(bblInst_file):
    blocks = list()
    i = 0
    bi = BlockInfo()
    with open(bblInst_file, "r") as fr:
        while True:
            bi = getOneBlock(fr)
            if len(bi.m_block) <= 0 :    # Reached the end
                break
            blocks.append(bi)
    print "Read [%s] complited!" % bblInst_file
    return blocks


#Filter block according to the instruction count of block
def filterBlockByCount(bblInst_file, minCount):
    i = 0
    blocks = getBlocksFromFile(bblInst_file)
    remBlocks = list()

    for i in range(0, len(blocks)):
        if blocks[i].m_blkCount >= minCount:
            remBlocks.append(blocks[i])
    return remBlocks

# Output the remaind blocks to file
def outputBlocks(outFile, remBlocks):
    i = 0
    j = 0
    s = ""
    line = ""
    bbl = BlockInfo()
    with open(outFile, "w") as fw:
        s = "Total block count %d" % (len(remBlocks))
        fw.write(s + "\n")
        for i in range(0, len(remBlocks)):
            bbl = remBlocks[i]
            s = "----Trace:----"
            fw.write(s + "\n")
            for j in range(0, len(bbl.m_block)):
                line = bbl.m_block[j]
                fw.write(line + "\n")
            s = "----"
            fw.write(s + "\n")
    pass


#
# Filter blocks which instruction count larger than 50
#
# Pyhon filterBlockByCnt.py 50
#

def main():
    prefix = "../"
    bblInst_file = prefix + "bblInst.log"
    outFile = prefix + "filterBlockByCount.log"
    minCount = 15
    remBlocks = list()

    if len(sys.argv) > 1:
        t = sys.argv[1]
        minCount = int(t)

    print "Starting..."
    remBlocks = filterBlockByCount(bblInst_file, minCount)
    outputBlocks(outFile, remBlocks)
    print "Total block count %d" % (len(remBlocks))
    print "Finished!"


main()

