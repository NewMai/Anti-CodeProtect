#include <stdio.h>
#include <map>
#include <set>
#include <ctime>
#include <vector>

#include "pin.H"
#include "kscope.h"

using namespace std;
/* =================================================== */
static ADDRINT CodeStartAddr;
static ADDRINT CodeEndAddr;
static size_t instID = 0;
static size_t Frames[0x10000] = {0};
static size_t FrameCounter = 0;

/* =================================================== */
static FILE * FpTrace;

static map<ADDRINT, size_t> MemDic;
static map<ADDRINT, size_t> RefDic;

static const ADDRINT Init_InstID = 0xFFFFFFFF;
/* =================================================== */
static bool init()
{
	init_code_section( CodeStartAddr, CodeEndAddr );

	FpTrace = fopen("data/memCitation.log", "w");
	if ( FpTrace == NULL )
	{
		puts("Failed to open memCitation file\n");
		return false;
	}

	RefDic[Init_InstID] = 0;
	return true;
}


static void write_back()
{
	for ( map<ADDRINT, size_t>::const_iterator it = RefDic.begin(); it != RefDic.end(); ++it )
	{
		if ( it->second > 0 )
			fprintf( FpTrace, "addr %08x (produced by func: %08x) -- cited times: %d\n", it->first, MemDic[it->first], it->second );
	}
	RefDic.clear();
	RefDic[Init_InstID] = 0;
}


static VOID call_probe( ADDRINT pc )
{
	if ( pc < CodeStartAddr || pc > CodeEndAddr )
		return;

	fprintf( FpTrace, "call %08x from %08x\n", pc, Frames[FrameCounter] );
	Frames[++FrameCounter] = pc;
}

static VOID return_probe()
{
	--FrameCounter;
	write_back();
	fprintf( FpTrace, "return to %08x\n\n", Frames[FrameCounter] );
}


// Record a memory read record
static VOID profile_mem_read( ADDRINT addr )
{
	if ( MemDic.find(addr) == MemDic.end() )
	{
		MemDic[addr] = Init_InstID; // read the initial memory content
	}

	if ( MemDic[addr] != Frames[FrameCounter] )
	{
		if ( RefDic.find(addr) == RefDic.end() )
		{
			RefDic[addr] = 1;
		}
		else
		{
			++RefDic[ addr ];
		}
	}
}

// Record a memory write record
static VOID profile_mem_write( ADDRINT pc, ADDRINT addr )
{

	// if an address is overwritten, the reference should be first recorded.
	if ( MemDic.find(addr) != MemDic.end() && RefDic.find(addr) != RefDic.end() )
	{
		// used to record intraprocedural reference
		// comment it to only record intraprocedural reference.
		fprintf( FpTrace, "addr %08x (produced by func: %08x) -- cited times: %d\n", addr, MemDic[addr], RefDic[addr] );
	}

	// add a label for each memory writing so that when this memory is read, we can know the origin.
	// the label can be the original instruction or the original function that writes that address.
	MemDic[addr] = Frames[FrameCounter];
	RefDic.erase(addr);
}

static VOID ins_probe( ADDRINT pc )
{
	++instID;
}

// Pin calls this function every time a new instruction is encountered
static VOID Inst(INS ins, VOID *v)
{
	ADDRINT pc = INS_Address (ins);
	if ( pc <= CodeEndAddr && pc >= CodeStartAddr )
	{
		if ( INS_IsCall(ins) )
		{
			INS_InsertCall(	ins, IPOINT_TAKEN_BRANCH, AFUNPTR(call_probe), IARG_BRANCH_TARGET_ADDR, IARG_END );
		}
		if ( INS_IsRet( ins ) )
		{
			INS_InsertCall(	ins, IPOINT_TAKEN_BRANCH, AFUNPTR(return_probe), IARG_BRANCH_TARGET_ADDR, IARG_END );
		}

		if (INS_IsMemoryWrite(ins))
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(profile_mem_write), IARG_INST_PTR, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);
	
		if ( INS_HasMemoryRead2(ins) )
			INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(profile_mem_read), IARG_MEMORYREAD2_EA, IARG_MEMORYREAD_SIZE, IARG_END);

		if ( INS_IsMemoryRead(ins) )
			INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(profile_mem_read), IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_END);
	}
}


// This function is called when the application exits
static VOID Finish(INT32 code, VOID *v)
{
	write_back();
	fclose( FpTrace );
	
	puts("--FINI--\n");
}


int cite_analyzer(int argc, char * argv[])
{
    // Initialize pin
    if ( PIN_Init(argc, argv) )
		return -1;

	if ( false == init() )
		return -1;

    // Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction( Inst, 0 );

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction( Finish, 0 );
    
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
