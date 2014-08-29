/*******************************************************************************
* Copyright 2001 – 2010 Intel Corporation. All Rights Reserved.
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
* Redistributions of source code must retain the above copyright notice,
* this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice,
* this list of conditions and the following disclaimer in the documentation
* and/or other materials provided with the distribution.
* Neither the name Intel Corporation nor the names of its contributors may
* be used to endorse or promote products derived from this software without
* specific prior written permission.
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
* THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED.IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
* CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
* OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*******************************************************************************/
// PE-Parse.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
// #include <stdlib.h>
// #include <process.h>

#define _WIN32_WINNT 0x0501
#define END_OF_RANGE(__address, __bytes) ((UINT64)(__address) | ((__bytes) - 1))
#define MakePtr(cast, ptr, addValue)(cast)((UINT64)(ptr) + (UINT64)(addValue))

#define TEST_APP_PATH  L"c:\\Users\\snagar6\\Desktop\\ring3_poc_latest\\ring3_poc\\test_app\\x64\\Debug\\test_app.exe"
#define METRO_APP_PATH L"c:\\Users\\intel\\Appxlayouts\\1272bfd4-2a99-4300-a871-f158ff2be44cVS.Debug.Win32.intel\\metrotestapp.exe" 

int ListProcessModules(DWORD dwPID);

UINT64 processBaseAddr = 0;

UINT64 rvaDataSectionStart = 0;
UINT64 rvaDataSectionEnd = 0;

UINT64 rvaCodeSectionStart = 0;
UINT64 rvaCodeSectionEnd = 0;

UINT64 rvaIDataSectionStart = 0;
UINT64 rvaIDataSectionEnd = 0;

wchar_t *
iba_wcscpy(wchar_t * __restrict s1, const wchar_t * __restrict s2)
{
	wchar_t *cp;

	cp = s1;
	while ((*cp++ = *s2++) != L'\0')
		;

	return (s1);
}


int doFilePEParsing (wchar_t *filename)
{
    HANDLE hFile;
    HANDLE hFileMapping;
    LPVOID lpFileBase;
    PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS ntHeader;
	PIMAGE_SECTION_HEADER secHeader;
	int i;
	DWORD lastErr = 0;
	LPCWSTR tempFile = (LPCWSTR)(filename);

    
    hFile = CreateFile(tempFile, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    
	lastErr = GetLastError();

    if ( hFile == INVALID_HANDLE_VALUE )
    {   printf("Couldn't open file with CreateFile(): %d \n", lastErr);
        return 2; 
	}
    
    hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if ( hFileMapping == 0 )
    {   CloseHandle(hFile);
        printf("Couldn't open file mapping with CreateFileMapping()\n");
        return 2; 
	}
    
    lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if ( lpFileBase == 0 )
    {
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        printf("Couldn't map view of file with MapViewOfFile()\n");
        return 2;
    }

    dosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
    if ( dosHeader->e_magic == IMAGE_DOS_SIGNATURE )
    { 
		ntHeader = MakePtr(PIMAGE_NT_HEADERS, dosHeader, dosHeader->e_lfanew);
		secHeader = MakePtr(PIMAGE_SECTION_HEADER, ntHeader, sizeof(*ntHeader));

		printf("\nPE PARSING: dosHeader address: %x", dosHeader);
		printf("\nNum Sections = %d \n", ntHeader->FileHeader.NumberOfSections);

		for (i=0; i<ntHeader->FileHeader.NumberOfSections; i++, secHeader++) 
		{
		    printf("\n Sections %d, Name=%s VA=%x, Size=%d ", i, secHeader->Name, secHeader->VirtualAddress, secHeader->SizeOfRawData );

			if ( (memcmp(secHeader->Name, ".text", 5) == 0) || (memcmp(secHeader->Name, ".code", 5) == 0) )
			{
				rvaCodeSectionStart = processBaseAddr + (UINT64)(secHeader->VirtualAddress);
				rvaCodeSectionEnd = processBaseAddr + (UINT64)(secHeader->VirtualAddress) + (UINT64)(secHeader->SizeOfRawData);
				printf("\nPE PARSING: [TEXT] Section: Start = %x  End = %x", rvaCodeSectionStart, rvaCodeSectionEnd);
			}
			
			if ( memcmp(secHeader->Name, ".data", 5) == 0 )
			{
				rvaDataSectionStart = processBaseAddr + (UINT64)(secHeader->VirtualAddress);
				rvaDataSectionEnd = processBaseAddr + (UINT64)(secHeader->VirtualAddress) + (UINT64)(secHeader->SizeOfRawData);
				printf("\nPE PARSING: [DATA] Section: Start = %x  End = %x", rvaDataSectionStart, rvaDataSectionEnd);
			}
			
			if ( memcmp(secHeader->Name, ".idata", 5) == 0 )
			{
				rvaIDataSectionStart = processBaseAddr + (UINT64)(secHeader->VirtualAddress);
				rvaIDataSectionEnd = processBaseAddr + (UINT64)(secHeader->VirtualAddress) + (UINT64)(secHeader->SizeOfRawData);
				printf("\nPE PARSING: [IDATA] Section: Start = %x  End = %x", rvaIDataSectionStart, rvaIDataSectionEnd);
			}
		}
		
		printf("\n\nPE Parsing Done of the Image Done! "); 
	}

	UnmapViewOfFile(lpFileBase);
    CloseHandle(hFileMapping);
    CloseHandle(hFile);

	return 0;
}



int ListProcessModules(DWORD dwPID)
{
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;
	UINT64 procBaseAddr = 0;
	static int firstModule = 0;
	wchar_t *filename = NULL;

	system("ls");

	//  Take a snapshot of all modules in the specified process.
   hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);

   if(hModuleSnap == INVALID_HANDLE_VALUE)
   {
		printf("Error: CreateToolhelp32Snapshot()");
		return (-1); 
   }

   //  Set the size of the structure before using it.
   me32.dwSize = sizeof(MODULEENTRY32);

   //  Retrieve information about the first module, and exit if unsuccessful
   printf("\n******************************************\n");
   printf("*   List of module for current process   *\n");
   printf("******************************************");

   if(!Module32First(hModuleSnap, &me32))
   {
	    printf("Error: Module32First()");  // Show cause of failure 
		CloseHandle(hModuleSnap);       // Must clean up the snapshot object 
		return (-1); 
    }

   //  Now walk the module list of the process, and display information about each module
   do
   {
		printf("\n\n   MODULE NAME: |%ws| ",           me32.szModule);
		printf("\n     executable     = |%ws| ",         me32.szExePath);
		printf("\n     process ID     = 0x%08X",         me32.th32ProcessID);
		printf("\n     base address   = %I64x", (UINT64) me32.modBaseAddr);
		printf("\n     base size      = %d\n",           me32.modBaseSize);

		if(firstModule == 0)
		{
			processBaseAddr = (UINT64)(me32.modBaseAddr);
			// doFilePEParsing(L"c:\\Users\\snagar6\\Desktop\\ring3_poc_latest\\ring3_poc\\test_app\\x64\\Debug\\test_app.exe");
			firstModule = 1;
		}

	} while (Module32Next(hModuleSnap, &me32));

    if (processBaseAddr)
	{
		doFilePEParsing (METRO_APP_PATH);
	}

	// Do not forget to clean up the snapshot object.
	CloseHandle(hModuleSnap);
	return (1);
}


int _tmain(int argc, _TCHAR* argv[])
{

	if (argc != 2)
	{
		printf("\n USAGE: PE-Parser.exe <PID> \n");
		getchar();
		return 0;
	}

	 // Specifying "0" as the arg for this routine would mean ... current process, this program...
     ListProcessModules(_ttoi(argv[1]));
	  
	getchar();
	return(0);   
}

