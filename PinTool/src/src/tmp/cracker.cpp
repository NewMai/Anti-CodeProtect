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

static FILE * trace;

static ADDRINT CodeStartAddr;
static ADDRINT CodeEndAddr;

static VOID a( const CONTEXT * const ctxt )
{
	unsigned int edx = PIN_GetContextReg( ctxt, REG_EDX );
	fprintf( trace, "%08x\n", edx );
}

static VOID b( const CONTEXT * const ctxt )
{
	unsigned int ecx = PIN_GetContextReg( ctxt, REG_ECX );
	unsigned int eax = PIN_GetContextReg( ctxt, REG_EAX );
	fprintf( trace, "%08x\n", eax+ecx*2-0x30 );
}

static VOID c( const CONTEXT * const ctxt )
{
	unsigned int eax = PIN_GetContextReg( ctxt, REG_EAX );
	fprintf( trace, "%c\n", eax & 0xff );
}

static VOID printip( const CONTEXT * const ctxt )
{
	unsigned int ecx = PIN_GetContextReg( ctxt, REG_ECX );
	unsigned int ebx = PIN_GetContextReg( ctxt, REG_EBX );
	fprintf( trace, "%08x %08x\n", ebx, ecx );
}


// Pin calls this function every time a new instruction is encountered
static VOID Instruction(INS ins, VOID *v)
{
	ADDRINT pc = INS_Address (ins);

	if ( pc == 0x00402290 )
	{
		// Insert a call to printip before every instruction, and pass it the IP
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)printip, IARG_CONST_CONTEXT, IARG_END );
	}
	if ( pc == 0x00401fa9 )
	{
		// Insert a call to printip before every instruction, and pass it the IP
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)a, IARG_CONST_CONTEXT, IARG_END );
	}
	if ( pc == 0x004021ae )
	{
		// Insert a call to printip before every instruction, and pass it the IP
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)b, IARG_CONST_CONTEXT, IARG_END );
	}
	if ( pc == 0x004021aa )
	{
		// Insert a call to printip before every instruction, and pass it the IP
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)c, IARG_CONST_CONTEXT, IARG_END );
	}
}


// This function is called when the application exits
static VOID Fini(INT32 code, VOID *v)
{
	fclose( trace );
	puts("--FINI--\n");
}



/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

static INT32 Usage()
{
    PIN_ERROR("This Pintool prints the IPs of every instruction executed\n" 
              + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}



int cracker(int argc, char * argv[])
{
    // Initialize pin
    if ( PIN_Init(argc, argv) )
		return Usage();
	trace = fopen("data/cracker.log", "w");

	// Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);

    // Register Fini to be called when the application exits
    // PIN_AddFiniFunction(Fini, 0);
    
    // Callback functions to invoke before
    // Pin releases control of the application
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
