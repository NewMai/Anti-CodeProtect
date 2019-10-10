#include <iostream>
#include <fstream>
#include <vector>
#include <map>

#include "pin.h"
#include "kscope.h"

using std::map;
using std::vector;

extern ConfigReader Config;

/* ================================================================== */
// Global variables 
/* ================================================================== */

static size_t InsCount = 0;        //number of dynamically executed instructions
static PIN_LOCK Sherlock;
static Switch swtch;
static FileManager Logger("data/ktrace.dll.log", "w");
static FileManager KsTracer("data/ktrace.bin", "wb");
static KsRecord * RecentItem;

static size_t InstRecordThreshold = 0;
static THREADID ThreadToMonitor = 0;
static ADDRINT ThreadEntryToMonitor = 0;

static CodeMap ThreadsRecords;

// Record a memory read record
static VOID rec_mem_read( ADDRINT pc, VOID * addr, UINT32 len )
{
	if ( !swtch.is_on() || RecentItem == NULL || len > 4 ) // ignore this one!
		return;

	if ( RecentItem->memOpMask & MEM_READ_MASK )
		return;

	RecentItem->memOpMask |= MEM_READ_MASK;
	RecentItem->Rlen = len;
	RecentItem->memRaddr = reinterpret_cast<ADDRINT>(addr);

	PIN_SafeCopy(&(RecentItem->memRcontent), static_cast<UINT8*>(addr), len);
}

// Record a memory write record
static VOID rec_mem_write( ADDRINT pc, VOID * addr, UINT32 len )
{
	if ( !swtch.is_on() || RecentItem == NULL || len > 4 )
		return;

	if ( RecentItem->memOpMask & MEM_WRITE_MASK )
		return;

	RecentItem->memOpMask |= MEM_WRITE_MASK;
	RecentItem->Wlen = len;
	RecentItem->memWaddr = reinterpret_cast<ADDRINT>(addr);

	// since we only care about the content that will be read after writing
	// we do not need to record the write content acutally.
	// RecentItem->memWcontent = 0xFACECAFE;
}

static VOID inst_recorder( const CONTEXT * const ctxt )
{
	if ( RecentItem != NULL )
	{
		PIN_GetLock(&Sherlock, 1);
		fwrite( RecentItem, sizeof(KsRecord), 1, KsTracer.fp() );
		PIN_ReleaseLock(&Sherlock);
	}

	if ( !swtch.is_on() || PIN_ThreadId() != ThreadToMonitor )
	{
		return;
	}

	ADDRINT ip = PIN_GetContextReg( ctxt, REG_INST_PTR );
	if ( ThreadsRecords.inst_record_num(ip) + 1 >= InstRecordThreshold )
	{
		RecentItem = NULL;
		return;
	}

	KsRecord * k = ThreadsRecords.record_ptr(ip);
	k->ip = ip;
	k->eax = PIN_GetContextReg( ctxt, REG_EAX );
	k->ebx = PIN_GetContextReg( ctxt, REG_EBX );
	k->ecx = PIN_GetContextReg( ctxt, REG_ECX );
	k->edx = PIN_GetContextReg( ctxt, REG_EDX );
	k->edi = PIN_GetContextReg( ctxt, REG_EDI );
	k->esi = PIN_GetContextReg( ctxt, REG_ESI );
	k->ebp = PIN_GetContextReg( ctxt, REG_EBP );
	k->esp = PIN_GetContextReg( ctxt, REG_ESP );
	k->insNum = InsCount++;
	k->memOpMask &= 0;
	// k->tid = ThreadToMonitor;

	RecentItem = k;
	
	ThreadsRecords.add_record(ip);
}

// Pin calls this function every time a new instruction is encountered
static VOID instrumentor(INS ins, VOID *v)
{
	ADDRINT pc = INS_Address (ins);

	if ( pc == Config.get_switchOnAddr() )
		swtch.set_sw(true);
	if ( pc == Config.get_switchOffAddr() )
		swtch.set_sw(false);

	if ( Config.in_addr_set(pc) )
	{
		// Insert a call to inst_recorder before every instruction, and pass it the IP
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)inst_recorder, IARG_CONST_CONTEXT, IARG_END );

	    if (INS_IsMemoryWrite(ins))
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(rec_mem_write), IARG_INST_PTR, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);
	
		if ( INS_HasMemoryRead2(ins) )
			INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(rec_mem_read), IARG_INST_PTR, IARG_MEMORYREAD2_EA, IARG_MEMORYREAD_SIZE, IARG_END);

		if ( INS_IsMemoryRead(ins) )
			INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(rec_mem_read), IARG_INST_PTR, IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_END);
	}
}



// Pin calls this function every time a new basic block is encountered
// It inserts a call to docount
static VOID bbl_print(TRACE trace, VOID *v)
{
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
		ADDRINT pc = BBL_Address(bbl);

		if ( Config.in_addr_range(pc) )
		{
			for ( INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
			{
				fprintf( FpCodePool.fp(), "%08x|%s\n", INS_Address (ins), INS_Disassemble(ins).c_str() );
			}
			fprintf( FpCodePool.fp(), "----\n" );
		}
	}
}


static VOID Fini(INT32 code, VOID *v)
{
	fprintf( Logger.fp(), "kTrace.bin -- InsCount :%d\n", InsCount );
}


int main(int argc, char *argv[])
{
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid 
    if( PIN_Init(argc,argv) )
    {
        return 1;
    }
 
	ThreadsRecords.init( Config.get_codeStartAddr(), Config.get_codeEndAddr() - Config.get_codeStartAddr() );

	InstRecordThreshold = Config.get_instRecNum();
	ThreadEntry = Config.get_threadToMonitor();

    TRACE_AddInstrumentFunction(bbl_print, 0);
    INS_AddInstrumentFunction(instrumentor, 0);

	//PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
