#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include <ctime>
#include <vector>

#include "pin.H"
#include "kscope.h"

using namespace std;

static FILE * FpTrace;
static FILE * InsTrace;

static size_t InstID = 0;
static size_t TotalMemRead = 0;
static size_t TotalMemWrite = 0;
static size_t NovelMemRead = 0;
static set<size_t> NovelMemWrite;


static size_t Interval = 0;
static ADDRINT CodeStartAddr;
static ADDRINT CodeEndAddr;

static map<size_t, size_t> MemDic;
static vector<size_t> CodeUseDic;




static VOID ins_probe( ADDRINT pc )
{
	++CodeUseDic[pc - CodeStartAddr];
	fprintf( InsTrace, "%08x\n", pc );

	if ( ++InstID % Interval == 0 )
	{
		fprintf( InsTrace, "--Phase: %d--\n", InstID / Interval + 1 );
		fprintf( FpTrace, "--Phase: %d--\n", InstID / Interval );

		fprintf( FpTrace, "%d: %d-%d %d-%d\n", Interval,
			TotalMemRead, NovelMemRead, TotalMemWrite, NovelMemWrite.size() );

		TotalMemRead = TotalMemWrite = NovelMemRead = 0;
		NovelMemWrite.clear();
		CodeUseDic.assign( CodeUseDic.size(), 0 );
	}
	
}



// Record a memory read record
static VOID profile_mem_read( ADDRINT addr )
{
	if ( MemDic.find(addr) == MemDic.end() )
		MemDic[addr] = 0;

	if ( MemDic[addr]++ == 0 )
		++NovelMemRead;
	++TotalMemRead;
}

// Record a memory write record
static VOID profile_mem_write( ADDRINT addr )
{
	MemDic[addr] = 0;
	++TotalMemWrite;
	NovelMemWrite.insert(addr);
}


// Pin calls this function every time a new instruction is encountered
static VOID Inst(INS ins, VOID *v)
{
	ADDRINT pc = INS_Address (ins);
	if ( pc <= CodeEndAddr && pc >= CodeStartAddr )
	{
		if (INS_IsMemoryWrite(ins))
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(profile_mem_write), IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);
	
		if ( INS_HasMemoryRead2(ins) )
			INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(profile_mem_read), IARG_MEMORYREAD2_EA, IARG_MEMORYREAD_SIZE, IARG_END);

		if ( INS_IsMemoryRead(ins) )
			INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(profile_mem_read), IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_END);

		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)ins_probe, IARG_INST_PTR, IARG_END );
	}
}


// This function is called when the application exits
static VOID Finish(INT32 code, VOID *v)
{
	fprintf( FpTrace, "--Phase: %d--\n", InstID / Interval + 1 );

	fprintf( FpTrace, "%d: %d-%d %d-%d\n", Interval,
		TotalMemRead, NovelMemRead, TotalMemWrite, NovelMemWrite.size() );

	fprintf( FpTrace, "--FINI--\n" );

	fclose( FpTrace );

	fclose(InsTrace);
}



static bool Init( char * binFilename )
{
	if ( init_Interval(Interval) == false )
	{
		std::cerr << "Fail to init phaseInterval\n";
		return false;
	}

	if ( false == init_code_section( CodeStartAddr, CodeEndAddr ) )
	{
		std::cerr << "Fail to init codeSection\n";
		return false;
	}

	InsTrace = fopen("data/insTrace.log", "w");
	if ( InsTrace == NULL )
	{
		std::cerr << "Fail to open insTrace.log\n";
		return false;
	}
	fprintf( InsTrace, "--Phase: 1--\n" );

	FpTrace = fopen("data/phase.log", "w");
	if ( FpTrace == NULL )
	{
		std::cerr << "Fail to open phase.log\n";
		return false;
	}

	CodeUseDic = vector<size_t>(CodeEndAddr - CodeStartAddr);

	return true;
}


int mem_phase(int argc, char * argv[])
{
    // Initialize pin
    if ( PIN_Init(argc, argv) )
		return -1;

	// exe filename
	Init( argv[6] );

    // Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Inst, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Finish, 0);
    
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
