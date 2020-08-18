
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


        int x = 32345;
        int y = 4234523;
        int a = 1, b = 1, c = 1, d = 1, e = 1, g = 1, h = 1;

        __declspec(noinline) int f() noexcept
        {
            return b;
        }
        __declspec(noinline) int f2() noexcept
        {
            return y;
        }
        __declspec(noinline) int f3() noexcept
        {
            return 0;
        }

        volatile int e1 = 0;
        volatile int e2 = 0;
        volatile int e3 = 0;

        uint64_t* pdata;

        __declspec(noinline) void f5(volatile int* pv) noexcept
        {
            *pv = 6;
        }

        __declspec(noinline) void f4(int a, int b, int c, int d, int* e, int* f) noexcept
        {
            int t1 = a - 10000;
            int t2 = *e;

            while (t1 < 0)
            {
                t2 += b;
                t1 += c;
            }

            *e = t2;
        }

        error main() noexcept
        {
            assembler::asmexe assembly;
            buffer<uint8_t> data;
            //__checkedinto(data, file::read_all(R"(C:\Users\gianc\source\repos\amd64assembler\test.asm)"));
            data = to_buffer(s(R"(


__export __proc test:

mov r10,[rsp+40]
mov eax,[r10]
_looplabel1:
cmp ecx,0
jle _looplabel1.else
  _looplabel1.if:
  add eax,1
  sub ecx,1
jmp _looplabel1
_looplabel1.else:
mov [r10],eax

ret








__export __proc main:

mov  rax,1083388723
movd xmm0,rax

ret


__uint8[8] aaa
__uint8[8] a1
__uint8[8] b1
__uint8[8] c1
__uint8[8] d1

__export __proc getaddr:

lea rax,[aaa]

ret


__export __proc setupaddr:

lea rax,[aaa]

ret





__export __proc setupaddrr14:

lea r11,[aaa]

ret



__export __proc test2:

mov rax,0
mov [a1],rax
mov [b1],rax
mov [c1],rax

ret
)"));
            __checkedinto(assembly, assemble(data));


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
            printf("Has RDTSCP: %s\n", cpuid_queries()["RDTSCP"].execute() == 1 ? "true" : "false");
            printf("Has TscInvariant: %s\n", cpuid_queries()["TscInvariant"].execute() == 1 ? "true" : "false");
            printf("Has SysCallSysRet: %s\n", cpuid_queries()["SysCallSysRet"].execute() == 1 ? "true" : "false");

            float a = 4.6f;

            using cf = float(*)();
            using cf2 = void(*)(int a, int b, int c, int d, int* e, int* g);
            using getaddrf = uint64_t * (*)();

            cf c = ((cf)assembly[s("main")]);

            float test = c();

            cf2 c2 = ((cf2)assembly[s("test")]);
            getaddrf getaddr = ((getaddrf)assembly[s("getaddr")]);

            uint64_t f = c();

            uint64_t f2 = c();

            pdata = getaddr();

            int icount = 6 * 10000;
            int* tdata = new int[icount];
            for (int i = 0; i < icount; ++i)
            {
                tdata[i] = i;
            }

            timer tk;

            uint64_t min = std::numeric_limits<uint64_t>::max();

            // 98700
            for (int i = 0; i < 10; ++i)
            {
                tk.start();

                for (int j = 0; j < icount; j+=6)
                {
                    f4( tdata[j],
                        tdata[j + 1],
                        tdata[j + 2],
                        tdata[j + 3],
                        &tdata[j + 4],
                        &tdata[j + 5]
                        );
                }
                tk.stop();
                if (tk.nanoseconds() < min) min = tk.nanoseconds();
            }
            printf("msvc %llu\n", min );

            min = std::numeric_limits<uint64_t>::max();
            for (int i = 0; i < 1000; ++i)
            {
                tk.start();
                for (int j = 0; j < icount; j += 6)
                {
                    c2(tdata[j],
                        tdata[j + 1],
                        tdata[j + 2],
                        tdata[j + 3],
                        &tdata[j + 4],
                        &tdata[j + 5]
                    );
                }
                tk.stop();
                if (tk.nanoseconds() < min) min = tk.nanoseconds();
            }
            printf("asm  %llu\n", min);

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






