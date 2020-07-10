
#include "precompiled.h"

#include "opcode_ext.h"

#include "assembler.h"

///
/// https://www.amd.com/system/files/TechDocs/24594.pdf
/// 

// notes:

/// operand sizing
// Table 1 - 3. Address - Size Overrides

//// rex
/// 1.2.7 REX Prefix
/// Table 1-9. Instructions Not Requiring REX Prefix in 64-Bit Mode

/// 1.4 ModRM and SIB Bytes

// Table 1-10. ModRM.reg and .r/m Field Encodings
// Table 1-13. SIB.base encodings for ModRM.r/m = 100b

/// +rb, +rw, +rd, +rq
// Table 2-2. +rb, +rw, +rd, and +rq Register Value

// 2.5.2 Opcode Syntax

namespace cgengine
{
    namespace assembler
    {
#define __ms__(x) #x
#define __ms(x) __ms__(x)

        void* mem = nullptr;


        /*
        memcmp
                                        push rsi
                                        push rdi
                                        push rcx
                                        push ebx
                                        cld
                                        mov rsi, ecx
                                        mov rdi, edx
                                        mov rcx, 62500000
                                        repe cmpsq
                                        mov eax, 0
                                        mov ebx, 1
                                        cmovz eax, ebx

                                        pop ebx
                                        pop rcx
                                        pop rdi
                                        pop rsi
                                        ret
        */
        /*
    memcmp2
                                        push rsi
                                        push rdi
                                        push rcx
                                        push rbx

                                        mov rsi, rcx
                                        mov rdi, rdx
                                        mov ecx, 62500000

                                        sub rsi,8
                                        sub rdi,8
                                        :
                                            add rsi,8
                                            add rdi,8
                                            mov rax,[rsi]
                                            cmp rax,[rdi]
                                            loopz

                                        mov eax, 0
                                        mov ebx, 1
                                        cmovz eax, ebx

                                        pop rbx
                                        pop rcx
                                        pop rdi
                                        pop rsi
                                        ret
    */
        error main() noexcept
        {
            assembler::asmexe assembly;
            buffer<uint8_t> data;
            __checkedinto(data, file::read_all(R"(C:\Users\gianc\source\repos\amd64assembler\test.asm)"));
            __checkedinto(assembly, assemble(data));

            mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);


            printf("Has ADX: %s\n", cpuid_queries()["ADX"].execute() == 1 ? "true" : "false");
            printf("Has BMI1: %s\n", cpuid_queries()["BMI1"].execute() == 1 ? "true" : "false");
            printf("Has BMI2: %s\n", cpuid_queries()["BMI2"].execute() == 1 ? "true" : "false");
            printf("Has TBM: %s\n", cpuid_queries()["TBM"].execute() == 1 ? "true" : "false");
            printf("Has CLFSH: %s\n", cpuid_queries()["CLFSH"].execute() == 1 ? "true" : "false");
            printf("Has CLFLOPT: %s\n", cpuid_queries()["CLFLOPT"].execute() == 1 ? "true" : "false");
            printf("ClFlush: %u\n", cpuid_queries()["CLFlush"].execute().value());
            printf("Has CLWB: %s\n", cpuid_queries()["CLWB"].execute() == 1 ? "true" : "false");
            printf("Has CLZERO: %s\n", cpuid_queries()["CLZERO"].execute() == 1 ? "true" : "false");
            printf("Has CMOV: %s\n", cpuid_queries()["CMOV"].execute() == 1 ? "true" : "false");
            printf("Has LahfSahf: %s\n", cpuid_queries()["LahfSahf"].execute() == 1 ? "true" : "false");
            printf("Has CMPXCHG16B: %s\n", cpuid_queries()["CMPXCHG16B"].execute() == 1 ? "true" : "false");
            printf("Has SSE42: %s\n", cpuid_queries()["SSE4.2"].execute() == 1 ? "true" : "false");
            printf("Has LWP: %s\n", cpuid_queries()["LWP"].execute() == 1 ? "true" : "false");
            printf("Has ABM: %s\n", cpuid_queries()["ABM"].execute() == 1 ? "true" : "false");
            printf("Has MCOMMMIT: %s\n", cpuid_queries()["MCOMMMIT"].execute() == 1 ? "true" : "false");
            printf("Has MONITORX: %s\n", cpuid_queries()["MONITORX"].execute() == 1 ? "true" : "false");
            printf("Has MOVBE: %s\n", cpuid_queries()["MOVBE"].execute() == 1 ? "true" : "false");
            printf("Has MMX: %s\n", cpuid_queries()["MMX"].execute() == 1 ? "true" : "false");
            printf("Has POPCNT: %s\n", cpuid_queries()["POPCNT"].execute() == 1 ? "true" : "false");
            printf("Has RDRAND: %s\n", cpuid_queries()["RDRAND"].execute() == 1 ? "true" : "false");
            printf("Has SVM: %s\n", cpuid_queries()["SVM"].execute() == 1 ? "true" : "false");
            printf("Has PerfCtrExtCore: %s\n", cpuid_queries()["PerfCtrExtCore"].execute() == 1 ? "true" : "false");
            printf("Has TSC: %s\n", cpuid_queries()["TSC"].execute() == 1 ? "true" : "false");
            printf("Has TscInvariant: %s\n", cpuid_queries()["TscInvariant"].execute() == 1 ? "true" : "false");
            printf("Has SysCallSysRet: %s\n", cpuid_queries()["SysCallSysRet"].execute() == 1 ? "true" : "false");

            //uint32_t v1 = cpuid_queries()["L1DcSize"].execute();
            //uint32_t v2 = cpuid_queries()["L1IcSize"].execute();
            //uint32_t v3 = cpuid_queries()["L1DcLinesPerTag"].execute();
            //uint32_t v4 = cpuid_queries()["L1DcLineSize"].execute();

  /*          memcpy(mem, assembly.ptr, assembly.size);
            using cd = int(*)();

            timer tk, tk2;
            volatile int b = 0;

            double a = 20;
            a *= 10;
            for (int i = 0; i < 10; ++i)
            {
                a *= 10;
            }

            tk.start();
            b = ((cd)mem)();
            tk.stop();*/


            return error();
        }
    }
}




int32_t main()
{
    if (auto e = cgengine::assembler::main(); !e.success())
    {
        printf("%s\n", e.to_string().c_str());
    }
}






