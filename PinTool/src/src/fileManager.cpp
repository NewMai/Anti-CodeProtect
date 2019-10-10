#include <iostream>
#include "kscope.h"
#include<stdexcept>
using namespace std;

FileManager::FileManager( const char * const fileName, const char * const mode )
{
	file_ = fopen( fileName, mode );
	if (NULL == file_)
		//throw ("cannot open file");
		cout << "cannot open file" << endl;
		//exit(0);
	fclose(file_);
	file_ = fopen( fileName, mode );
}
	
FileManager::~FileManager()
{
	fclose(file_);
}

FILE * FileManager::fp()
{
	return file_; 
}
