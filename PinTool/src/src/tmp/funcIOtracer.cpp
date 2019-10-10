#include <iostream>
#include <fstream>
#include <map>
#include <set>

#include "pin.H"
#include "kscope.h"

/*
 * The lock for I/O.
 */
static PIN_LOCK fileLock;

static ADDRINT SwitchOnAddr = 0xFFFFFFFF;
static ADDRINT SwitchOffAddr = 0xFFFFFFFF;
static bool SWITCH;

static MemOP WriteBuffer; // put this into stack for multi threads!
static FILE * LogFile;

static bool init_config()
{
	SWITCH = false;
	if ( !init_switch( SwitchOnAddr, SwitchOffAddr ) )
	{
		puts("Failed to init code section\n");
		return false;
	}

	LogFile = fopen("data\\funcIO.log.txt", "w");
	return LogFile != NULL;
}

// Record a memory read record
static VOID rec_mem_read( ADDRINT addr, UINT32 len )
{
	if ( len > 4 ) // ignore this one!
		return;

	static unsigned char content[4];
	for ( size_t i = 0; i < len; ++i )
	{
		PIN_SafeCopy(content + i, reinterpret_cast<UINT8*>(addr + i), 1);
		fprintf( LogFile, "R:[%08x]=%02x\n", addr + i, content[i]);
	}
	fflush(LogFile);
}

static VOID func_analyzer( const CONTEXT * const ctxt )
{
	ADDRINT esp = PIN_GetContextReg( ctxt, REG_ESP );
	for ( size_t i = 1; i < 5; ++i )
		fprintf(LogFile, "Param%d: %08x\n", i, ((ADDRINT *)esp)[i] );
}


// Record a memory write record
static VOID rec_mem_write( ADDRINT addr, UINT32 len )
{
	if ( len > 4 ) // ignore this one!
		return;

	static size_t oldLen = 0;
	static ADDRINT oldAddr = 0;

	// notice that here we write back the data of last memory modification!
	// because PIN does not support to insert memory writing monitoring instruction after a memory modification operation
	// we just record last time modification's address and when a new memory modification happens, we record the last time operation's value.
	static unsigned char content[4];

	if ( oldLen != 0 && oldAddr != 0 )
	{
		for ( size_t i = 0; i < oldLen; ++i )
		{
			PIN_SafeCopy(content + i, reinterpret_cast<UINT8*>(oldAddr + i), 1);
			fprintf( LogFile, "W:[%08x]=%02x\n", oldAddr + i, content[i]);
		}
		fflush(LogFile);
	}
	oldLen = len;
	oldAddr = addr;
}


static VOID insert_mem_trace(INS ins)
{
    if (INS_IsMemoryWrite(ins))
		INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(rec_mem_write), IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);
	
    if ( INS_HasMemoryRead2(ins) )
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(rec_mem_read), IARG_MEMORYREAD2_EA, IARG_MEMORYREAD_SIZE, IARG_END);

	if ( INS_IsMemoryRead(ins) )
		INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(rec_mem_read), IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_END);

}

// Pin calls this function every time a new instruction is encountered
static VOID Instruction(INS ins, VOID *v)
{
	ADDRINT pc = INS_Address (ins);

	if ( pc == SwitchOnAddr  )
	{
		SWITCH = true;
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)func_analyzer, IARG_CONST_CONTEXT, IARG_END );
	}
	if ( pc == SwitchOffAddr  )
		SWITCH = false;
	if ( SWITCH == false  )
		return;

	if ( pc < 0x500000 )
	{
		insert_mem_trace(ins);
	}
}


// This function is called when the application exits
static VOID Fini(INT32 code, VOID *v)
{
	fclose(LogFile);

	puts("--FINI--\n");
}




int func_io_tracer(int argc, char * argv[])
{
    // Step 0: Initialize pin
    if ( PIN_Init(argc, argv) )
		return Usage();

	if ( !init_config() )
	{
		puts("Init record file fails\n");
		return -1;
	}
	
	
	// Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);

    // Callback functions to invoke before
    // Pin releases control of the application
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
