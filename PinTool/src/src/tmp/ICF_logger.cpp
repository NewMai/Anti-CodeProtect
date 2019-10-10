#include "pin.H"
#include <iostream>
#include <fstream>
#include <set>
#include <map>
#include "kscope.h"
#include "minilzo.H"

static ADDRINT CodeStartAddr = 0;
static ADDRINT CodeEndAddr = 0;
static FILE * fpCodePool;

/*
 * The lock for I/O.
 */
static PIN_LOCK fileLock;

static Compressor trace;
static Compressor memReadTrace;
static Compressor memWriteTrace;

static ADDRINT SwitchOnAddr = 0xFFFFFFFF;
static ADDRINT SwitchOffAddr = 0xFFFFFFFF;
static bool SWITCH;

static const int MaxThreads = 256;

static size_t ThreadUid[MaxThreads]; // index every instructions
static unsigned char ThreadIDs[256] = {0};

static MemOP WriteBuffer; // put this into stack for multi threads!


/* ================================================================== */
// Global variables 
/* ================================================================== */

static UINT64 insCount = 0;        //number of dynamically executed instructions
static UINT64 bblCount = 0;        //number of dynamically executed basic blocks


static FILE *ICFlogFile;

static ADDRINT main_img_lower, main_img_upper;
static std::map<ADDRINT, std::string> addr2str;

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */
static VOID log_ICF(ADDRINT pc, ADDRINT target)
{
	//cout << "*************" << hex << pc << "***************" << endl;
	if (addr2str.find(pc) != addr2str.end())
		fprintf(ICFlogFile, "[%08x -> %08x] %s#%d\n", pc, target, addr2str[pc].c_str(), ( PIN_ThreadId() & 0xFFFF ));
	else
		printf("unknown pc %08x\n", pc);
	fflush(ICFlogFile);
}


// Pin calls this function every time a new basic block is encountered
// It inserts a call to docount
static VOID bbl_trace(TRACE trace, VOID *v)
{
	// Visit every basic block in the trace
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
		// Insert a call to docount for every bbl, passing the number of instructions.
        // IPOINT_ANYWHERE allows Pin to schedule the call anywhere in the bbl to obtain best performance.
        // Use a fast linkage for the call.
		ADDRINT pc = BBL_Address(bbl);

		if ( pc >= CodeStartAddr && pc <= CodeEndAddr )
		{
			for ( INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
			{
				fprintf( fpCodePool, "%08x|%s\n", INS_Address (ins), INS_Disassemble(ins).c_str() );
			}
			fprintf( fpCodePool, "----\n" );
		}
	}
}


// Record a memory read record
static VOID rec_mem_read( VOID * addr, UINT32 len )
{
	if ( len > 4 ) // ignore this one!
		return;

	static MemOP ReadBuffer;
	ReadBuffer.len = len;
	ReadBuffer.tid = ( PIN_ThreadId() & 0xFFFF );
	ReadBuffer.addr = addr;
	ReadBuffer.type = 'R';
	ReadBuffer.uid = ThreadUid[ReadBuffer.tid];

	if ( len == 1 )
		PIN_SafeCopy(&(ReadBuffer.content), static_cast<UINT8*>(addr), 1);
	else if ( len == 2 )
		PIN_SafeCopy(&(ReadBuffer.content), static_cast<UINT16*>(addr), 2);
	else
		PIN_SafeCopy(&(ReadBuffer.content), static_cast<UINT32*>(addr), 4);

	/*
	if ( 1 != fwrite( &ReadBuffer, sizeof(MemOP), 1, memReadTrace ) )
	{
		puts("write mem error\n");
		exit(0);
	}
	*/

	memReadTrace.save_data( &ReadBuffer, sizeof(MemOP) );

}

// Record a memory write record
static VOID rec_mem_write( VOID * addr, UINT32 len )
{
	if ( len > 4 ) // ignore this one!
		return;

	// notice that here we write back the data of last memory modification!
	// because PIN does not support to insert memory writing monitoring instruction after a memory modification operation
	// we just record last time modification's address and when a new memory modification happens, we record the last time operation's value.
	if ( WriteBuffer.addr != 0 )
	{
		if ( WriteBuffer.len == 1 )
			PIN_SafeCopy(&(WriteBuffer.content), static_cast<UINT8*>(WriteBuffer.addr), 1);
		else if ( WriteBuffer.len == 2 )
			PIN_SafeCopy(&(WriteBuffer.content), static_cast<UINT16*>(WriteBuffer.addr), 2);
		else if ( WriteBuffer.len == 4 )
			PIN_SafeCopy(&(WriteBuffer.content), static_cast<UINT32*>(WriteBuffer.addr), 4);
		
		/*
		if ( 1 != fwrite( &WriteBuffer, sizeof(MemOP), 1, memWriteTrace ) )
		{
			puts("write mem error\n");
			exit(0);
		}
		*/
		memWriteTrace.save_data( &WriteBuffer, sizeof(MemOP) );
	}

	// Finally, we record the current memory modification operation
	THREADID tid = ( PIN_ThreadId() & 0xFFFF );
	WriteBuffer.addr = addr;
	WriteBuffer.tid = tid;
	WriteBuffer.len = len;
	WriteBuffer.type = 'W';
	WriteBuffer.uid = ThreadUid[WriteBuffer.tid];
}

static VOID printip( const CONTEXT * const ctxt )
{
	static RegS IpBuffer;

	IpBuffer.eax = PIN_GetContextReg( ctxt, REG_EAX );
	IpBuffer.ebx = PIN_GetContextReg( ctxt, REG_EBX );
	IpBuffer.ecx = PIN_GetContextReg( ctxt, REG_ECX );
	IpBuffer.edx = PIN_GetContextReg( ctxt, REG_EDX );
	IpBuffer.edi = PIN_GetContextReg( ctxt, REG_EDI );
	IpBuffer.esi = PIN_GetContextReg( ctxt, REG_ESI );
	IpBuffer.ebp = PIN_GetContextReg( ctxt, REG_EBP );
	IpBuffer.esp = PIN_GetContextReg( ctxt, REG_ESP );
	IpBuffer.ip = PIN_GetContextReg( ctxt, REG_INST_PTR );
	IpBuffer.id = PIN_ThreadId();
	ThreadIDs[IpBuffer.id] = 1;

	++ThreadUid[IpBuffer.id];
	IpBuffer.uid = ThreadUid[IpBuffer.id];
	
	/*
	if ( 1 != fwrite( &IpBuffer, sizeof(RegS), 1, trace ) )
	{
		puts("write ip error\n");
		exit(0); 
	}
	*/
	trace.save_data( &IpBuffer, sizeof(RegS) );
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
static VOID instrumentor(INS ins, VOID *v)
{
	ADDRINT pc = INS_Address (ins);

	if ( pc == SwitchOnAddr  )
		SWITCH = true;
	if ( pc == SwitchOffAddr  )
		SWITCH = false;
	if ( SWITCH == false  )
		return;

	if ( pc >= CodeStartAddr && pc <= CodeEndAddr )
	{
		// Insert a call to printip before every instruction, and pass it the IP
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)printip, IARG_CONST_CONTEXT, IARG_END );

		insert_mem_trace(ins);

		if (INS_IsIndirectBranchOrCall(ins))
		{		
			if (addr2str.find(pc) == addr2str.end())
			{
				addr2str[pc] = INS_Disassemble(ins);
			}
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(log_ICF), IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_END);
		}

	}
}


static VOID Fini(INT32 code, VOID *v)
{
	if ( WriteBuffer.addr != 0 )
	{
		if ( WriteBuffer.len == 1 )
			PIN_SafeCopy(&(WriteBuffer.content), static_cast<UINT8*>(WriteBuffer.addr), 1);
		else if ( WriteBuffer.len == 2 )
			PIN_SafeCopy(&(WriteBuffer.content), static_cast<UINT16*>(WriteBuffer.addr), 2);
		else if ( WriteBuffer.len == 4 )
			PIN_SafeCopy(&(WriteBuffer.content), static_cast<UINT32*>(WriteBuffer.addr), 4);
		
		memWriteTrace.save_data( &WriteBuffer, sizeof(MemOP) );
	}

	FILE * fp = fopen("data/ksThreads.log", "w");
	for ( size_t i = 0; i < sizeof(ThreadIDs); ++i )
		if (ThreadIDs[i] != 0)
			fprintf( fp, "%d ", i );
	fclose(fp);

	fclose(ICFlogFile);
	fclose(fpCodePool);
	puts("---------------- XHJ is done ----------------");
}


static bool init()
{
	if ( !init_code_section( CodeStartAddr, CodeEndAddr ) )
	{
		puts("Failed to init code section\n");
		return false;
	}

	ICFlogFile = fopen("./data/icf.log", "w");
	if ( ICFlogFile == NULL )
	{
		puts("init icf log file failed\n");
		return false;
	}

	fpCodePool = fopen( "data/bblInst.log", "w" );
	if ( fpCodePool == NULL )
	{
		puts("init bblInst file failed\n");
		return false;
	}
	//printf("codestart: %08x\ncodeend: %08x\nswitchon: %08x\nswitchoff: %08x\n", CodeStartAddr, CodeEndAddr, SwitchOnAddr, SwitchOffAddr);
	memset( ThreadUid, 0, sizeof(ThreadUid) );


	SWITCH = false;
	if ( !init_switch( SwitchOnAddr, SwitchOffAddr ) )
	{
		puts("Failed to init switch address\n");
		return false;
	}

	//printf("codestart: %08x\ncodeend: %08x\nswitchon: %08x\nswitchoff: %08x\n", CodeStartAddr, CodeEndAddr, SwitchOnAddr, SwitchOffAddr);

	if ( trace.set_trace_file("data/ksTrace.lzo") == false )
		return false;
	if ( memReadTrace.set_trace_file("data/ksMemReadTrace.lzo") == false )
		return false;
	if ( memWriteTrace.set_trace_file("data/ksMemWriteTrace.lzo") == false )
		return false;

	/*
	* initialize the LZO library
	*/
    if ( lzo_init() != LZO_E_OK )
    {
        printf("internal error - lzo_init() failed !!!\n");
        printf("(this usually indicates a compiler bug - try recompiling\nwithout optimizations, and enable '-DLZO_DEBUG' for diagnostics)\n");
        return false;
    }



	return true;
}

int ICF_logger(int argc, char *argv[])
{
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid 
    if( PIN_Init(argc,argv) )
    {
        return 1;
    }
    
	if ( !init() )
		return -1;


    TRACE_AddInstrumentFunction(bbl_trace, 0);
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
