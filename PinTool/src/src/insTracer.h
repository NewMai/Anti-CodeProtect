#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <set>
#include "pin.h"
#include "kscope.h"

static ConfigReader Config;
static FileManager FpCodePool("./data/insTracer.log", "w");

static FILE* fw = NULL;

static int g_instrument_flag = 0;
static int g_record_flag = 0;
static std::map<ADDRINT, std::string> insDict;



static VOID print_ins(ADDRINT addr)
{
	if (addr == Config.get_codeStartAddr())
	{
		g_record_flag = 1;
	}

	if (g_record_flag == 1)
	{
		fprintf(FpCodePool.fp(), "%016llx|%s\r\n", addr, insDict[addr].c_str());
	}
	
	if (addr == Config.get_codeEndAddr())
	{
		g_record_flag = 0;
	}
}

// Pin calls this function every time a new instruction is encountered
static VOID instrumentor(INS ins, VOID *v)
{
	ADDRINT pc = INS_Address (ins);

	if (pc == Config.get_codeStartAddr())
	{
		g_instrument_flag = 1;
	}

	if (g_instrument_flag == 1)
	{
		insDict[pc] = INS_Disassemble(ins);
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)print_ins, IARG_INST_PTR, IARG_END);
	}

	if (pc == Config.get_codeEndAddr())
	{
		g_instrument_flag = 0;
	}
}

static VOID ImageLoad(IMG img, VOID *v)
{
	char buf[100];
	int len = 0;
	static int i = 0;
	
	fprintf(fw, "Index: %02d\r\n", i++);
	fprintf(fw, "IMG_StartAddress = 0x%016llX\r\n", IMG_StartAddress(img));
	fprintf(fw, "IMG_Name = %s\r\n", IMG_Name(img).c_str());
	fprintf(fw, "IMG_Id = 0x%016llX\r\n", IMG_Id(img));
	fprintf(fw, "IMG_EntryAddress = 0x%016llX\r\n", IMG_EntryAddress(img));
	fprintf(fw, "IMG_Entry = 0x%016llX\r\n", IMG_Entry(img));
	fprintf(fw, "IMG_LoadOffset = 0x%016llX\r\n", IMG_LoadOffset(img));
	fprintf(fw, "IMG_LowAddress = 0x%016llX\r\n", IMG_LowAddress(img));
	fprintf(fw, "IMG_HighAddress = 0x%016llX\r\n", IMG_HighAddress(img));
	fprintf(fw, "\r\n");

}

static VOID Fini(INT32 code, VOID *v)
{
	fclose(fw);
	fw = NULL;
}

int main(int argc, char *argv[])
{
    if( PIN_Init(argc,argv) )
        return 1;

	fw = fopen("data/dll_info.log", "w");

    //TRACE_AddInstrumentFunction(bbl_print, 0);

    INS_AddInstrumentFunction(instrumentor, 0);

	//PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddFiniFunction(Fini, 0);

	// Register ImageLoad to be called when an image is loaded
	IMG_AddInstrumentFunction(ImageLoad, 0);

    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
