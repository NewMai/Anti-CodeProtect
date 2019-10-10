#ifndef _KSCOPE_H_
#define _KSCOPE_H_

#include "pin.H"

struct MemOP
{
	UINT32 uid;
	VOID * addr;
	UINT32 content;
	unsigned char type;
	unsigned char len;
	unsigned short tid;
};

struct BBLInfo
{
	ADDRINT addr;
	UINT32 size;
	THREADID tid;
};


struct RegS
{
	ADDRINT ip;
	THREADID id;
	ADDRINT eax;
	ADDRINT ebx;
	ADDRINT ecx;
	ADDRINT edx;
	ADDRINT edi;
	ADDRINT esi;
	ADDRINT ebp;
	ADDRINT esp;
	unsigned int uid;
};

typedef struct _IMAGE_SECTION_HEADER {
    unsigned char    Name[8];
    union {
            unsigned long   PhysicalAddress;
            unsigned long   VirtualSize;
    } Misc;
    unsigned long   VirtualAddress;
    unsigned long   SizeOfRawData;
    unsigned long   PointerToRawData;
    unsigned long   PointerToRelocations;
    unsigned long   PointerToLinenumbers;
    unsigned short    NumberOfRelocations;
    unsigned short    NumberOfLinenumbers;
    unsigned long   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

struct Slot
{
	unsigned int d[256];
};

double shannon( const Slot & slot );

bool GetCodeSegBound(char* peName, ADDRINT& upBound, ADDRINT& lowBound);

int get_argv_exe_index(int argc, char* argv[]);


int kaleidoscope( int argc, char * argv[] );
//int data_profiler( int argc, char * argv[] );
//int call_trace( int argc, char * argv[] );
int entropy( int argc, char * argv[] );
int bbl_tracer( int argc, char * argv[] );
int bbl_profiler(int argc, char * argv[]);
int memuse(int argc, char * argv[]);
int u1301(int argc, char * argv[]);
int test_rtn(int argc, char * argv[]);
int test_rtn2(int argc, char * argv[]);
int test_memLog(int argc, char * argv[]) ;
int find_call(int argc, char * argv[]) ;
int diff_mem(int argc, char * argv[]) ;
int slow_data_profiler( int argc, char * argv[] );
//int func_data_profiler( int argc, char * argv[] );
int func_entropy( int argc, char * argv[] );
int ins_count(int argc, char* argv[]);
int func_ins_profiler(int argc, char* argv[]);
int ins_kscope(int argc, char* argv[]);
int access_addrs(int argc, char *argv[]);
int func_ins_entropy(int argc, char *argv[]);
int dcache(int argc, char *argv[]);
int func_addrs(int argc, char *argv[]);
int essemble_tools(int argc, char *argv[]);
int FuncMemAccessAnalysis(int argc,char *argv[]);

int MemoryAccessAnalysis(int argc, char *argv[]);


#endif
