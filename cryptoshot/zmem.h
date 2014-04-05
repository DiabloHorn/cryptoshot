/*
	DiabloHorn http://diablohorn.wordpress.com
*/
#ifndef ZMEM_H
#define ZMEM_H
#include <Windows.h>


/* http://illmatics.com/Understanding_the_LFH.pdf */
/* http://msdn.microsoft.com/en-us/library/windows/desktop/aa366781(v=vs.85).aspx */

void zfree(void *memblock);
HGLOBAL WINAPI zGlobalFree(HGLOBAL hMem);
HLOCAL WINAPI zLocalFree(HLOCAL hMem);
BOOL WINAPI zHeapFree(HANDLE hHeap,DWORD dwFlags,LPVOID lpMem);
//BOOL WINAPI zVirtualFree(LPVOID lpAddress,SIZE_T dwSize,DWORD dwFreeType);
//BOOL WINAPI zVirtualFreeEx(HANDLE hProcess,LPVOID lpAddress,SIZE_T dwSize,DWORD dwFreeType);
#endif