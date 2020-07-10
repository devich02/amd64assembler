#pragma once

#include <inc.h>
#include <error.h>
#include <containers/umap>
#include <parse.h>

namespace cgengine
{

    namespace errors
    {
        namespace assembler
        {
            _inline error invalid_instruction(error_scope::cgengine, 120000, "InvalidInstruction");
            _inline error invalid_argument(error_scope::cgengine, 120001, "InvalidArgument");
            _inline error unexpected_end_of_statment(error_scope::cgengine, 120002, "UnexpectedEndOfStatement");
            _inline error invalid_indirect_address_scheme(error_scope::cgengine, 120003, "InvalidIndirectAddressScheme");
            _inline error instruction_overload_not_found(error_scope::cgengine, 120003, "InstructionOverloadNotFound");
            _inline error instruction_incomplete(error_scope::cgengine, 120004, "InstructionIncomplete");
        }
    }

    namespace assembler
    {
        /// <summary>
        /// Register names
        /// </summary>
        struct register_t
        {
            enum vt
            {
                AH, BH, CH, DH,
                AL, BL, CL, DL,

                SIL, DIL, BPL, SPL,

                // 8 bit
                R8B, R9B, R10B, R11B, R12B, R13B, R14B, R15B,
                // 16 bit 
                R8W, R9W, R10W, R11W, R12W, R13W, R14W, R15W,
                // 32 bit
                R8D, R9D, R10D, R11D, R12D, R13D, R14D, R15D,
                // 64 bit
                R8, R9, R10, R11, R12, R13, R14, R15,

                // ControlRegister
                CR__n_,
                // CodeSegment
                CS,

                // 16 bit 
                AX, BX, CX, DX, DI, SI, BP, SP, SS,
                // 32 bit
                EAX, EBX, ECX, EDX, EDI, ESI, EBP, ESP,
                // 64 bit
                RAX, RBX, RCX, RDX, RDI, RSI, RBP, RSP,

                // extended features enable register
                EFER,

                // instruction pointer
                IP, EIP, RIP,

                // flags register
                FLAGS, EFLAGS, RFLAGS,

                // Global descriptor table register
                GDTR,

                // Interrupt descriptor table register
                IDTR,

                // Local descriptor table register
                LDTR,

                // Model-specific register
                MSR,

                // task priority register
                TPR,
                // task register
                TR,

                MMX0, MMX1, MMX2, MMX3, MMX4, MMX5, MMX6, MMX7,
                XMM0, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6, XMM7, XMM8, XMM9, XMM10, XMM11, XMM12, XMM13, XMM14, XMM15,

                YMM0, YMM1, YMM2, YMM3, YMM4, YMM5, YMM6, YMM7, YMM8, YMM9, YMM10, YMM11, YMM12, YMM13, YMM14, YMM15,

                none,
                invalid
            } value;

            register_t(const string& name) noexcept :
                value(invalid)
            {
                if (name == s("AH")) value = AH;
                else if (name == s("BH")) value = BH;
                else if (name == s("CH")) value = CH;
                else if (name == s("DH")) value = DH;
                else if (name == s("AL")) value = AL;
                else if (name == s("BL")) value = BL;
                else if (name == s("CL")) value = CL;
                else if (name == s("DL")) value = DL;
                else if (name == s("SIL")) value = SIL;
                else if (name == s("DIL")) value = DIL;
                else if (name == s("BPL")) value = BPL;
                else if (name == s("SPL")) value = SPL;
                else if (name == s("R8B")) value = R8B;
                else if (name == s("R9B")) value = R9B;
                else if (name == s("R10B")) value = R10B;
                else if (name == s("R11B")) value = R11B;
                else if (name == s("R12B")) value = R12B;
                else if (name == s("R13B")) value = R13B;
                else if (name == s("R14B")) value = R14B;
                else if (name == s("R15B")) value = R15B;
                else if (name == s("R8W")) value = R8W;
                else if (name == s("R9W")) value = R9W;
                else if (name == s("R10W")) value = R10W;
                else if (name == s("R11W")) value = R11W;
                else if (name == s("R12W")) value = R12W;
                else if (name == s("R13W")) value = R13W;
                else if (name == s("R14W")) value = R14W;
                else if (name == s("R15W")) value = R15W;
                else if (name == s("R8D")) value = R8D;
                else if (name == s("R9D")) value = R9D;
                else if (name == s("R10D")) value = R10D;
                else if (name == s("R11D")) value = R11D;
                else if (name == s("R12D")) value = R12D;
                else if (name == s("R13D")) value = R13D;
                else if (name == s("R14D")) value = R14D;
                else if (name == s("R15D")) value = R15D;
                else if (name == s("R8")) value = R8;
                else if (name == s("R9")) value = R9;
                else if (name == s("R10")) value = R10;
                else if (name == s("R11")) value = R11;
                else if (name == s("R12")) value = R12;
                else if (name == s("R13")) value = R13;
                else if (name == s("R14")) value = R14;
                else if (name == s("R15")) value = R15;
                else if (name == s("AX")) value = AX;
                else if (name == s("BX")) value = BX;
                else if (name == s("CX")) value = CX;
                else if (name == s("DX")) value = DX;
                else if (name == s("DI")) value = DI;
                else if (name == s("SI")) value = SI;
                else if (name == s("BP")) value = BP;
                else if (name == s("SP")) value = SP;
                else if (name == s("IP")) value = IP;
                else if (name == s("SS")) value = SS;
                else if (name == s("EAX")) value = EAX;
                else if (name == s("EBX")) value = EBX;
                else if (name == s("ECX")) value = ECX;
                else if (name == s("EDX")) value = EDX;
                else if (name == s("EDI")) value = EDI;
                else if (name == s("ESI")) value = ESI;
                else if (name == s("EBP")) value = EBP;
                else if (name == s("ESP")) value = ESP;
                else if (name == s("EIP")) value = EIP;
                else if (name == s("RAX")) value = RAX;
                else if (name == s("RBX")) value = RBX;
                else if (name == s("RCX")) value = RCX;
                else if (name == s("RDX")) value = RDX;
                else if (name == s("RDI")) value = RDI;
                else if (name == s("RSI")) value = RSI;
                else if (name == s("RBP")) value = RBP;
                else if (name == s("RSP")) value = RSP;
                else if (name == s("RIP")) value = RIP;
                else if (name == s("EFER")) value = EFER;
                else if (name == s("FLAGS")) value = FLAGS;
                else if (name == s("EFLAGS")) value = EFLAGS;
                else if (name == s("RFLAGS")) value = RFLAGS;
                else if (name == s("GDTR")) value = GDTR;
                else if (name == s("IDTR")) value = IDTR;
                else if (name == s("LDTR")) value = LDTR;
                else if (name == s("MSR")) value = MSR;
                else if (name == s("TPR")) value = TPR;
                else if (name == s("TR")) value = TR;

                if (name == s("MMX0")) value = MMX0;
                else if (name == s("MMX1")) value = MMX1;
                else if (name == s("MMX2")) value = MMX2;
                else if (name == s("MMX3")) value = MMX3;
                else if (name == s("MMX4")) value = MMX4;
                else if (name == s("MMX5")) value = MMX5;
                else if (name == s("MMX6")) value = MMX6;
                else if (name == s("MMX7")) value = MMX7;

                else if (name == s("XMM0")) value = XMM0;
                else if (name == s("XMM1")) value = XMM1;
                else if (name == s("XMM2")) value = XMM2;
                else if (name == s("XMM3")) value = XMM3;
                else if (name == s("XMM4")) value = XMM4;
                else if (name == s("XMM5")) value = XMM5;
                else if (name == s("XMM6")) value = XMM6;
                else if (name == s("XMM7")) value = XMM7;
                else if (name == s("XMM8")) value = XMM8;
                else if (name == s("XMM9")) value = XMM9;
                else if (name == s("XMM10")) value = XMM10;
                else if (name == s("XMM11")) value = XMM11;
                else if (name == s("XMM12")) value = XMM12;
                else if (name == s("XMM13")) value = XMM13;
                else if (name == s("XMM14")) value = XMM14;
                else if (name == s("XMM15")) value = XMM15;

                else if (name == s("YMM0")) value = YMM0;
                else if (name == s("YMM1")) value = YMM1;
                else if (name == s("YMM2")) value = YMM2;
                else if (name == s("YMM3")) value = YMM3;
                else if (name == s("YMM4")) value = YMM4;
                else if (name == s("YMM5")) value = YMM5;
                else if (name == s("YMM6")) value = YMM6;
                else if (name == s("YMM7")) value = YMM7;
                else if (name == s("YMM8"))  value = YMM8;
                else if (name == s("YMM9"))  value = YMM9;
                else if (name == s("YMM10")) value = YMM10;
                else if (name == s("YMM11")) value = YMM11;
                else if (name == s("YMM12")) value = YMM12;
                else if (name == s("YMM13")) value = YMM13;
                else if (name == s("YMM14")) value = YMM14;
                else if (name == s("YMM15")) value = YMM15;
            }
            register_t(const buffer<char>& name) noexcept :
                value(invalid)
            {
                if (name == ("AH") || name == ("ah")) value = AH;
                else if (name == ("BH") || name == ("bh")) value = BH;
                else if (name == ("CH") || name == ("ch")) value = CH;
                else if (name == ("DH") || name == ("dh")) value = DH;
                else if (name == ("AL") || name == ("al")) value = AL;
                else if (name == ("BL") || name == ("bl")) value = BL;
                else if (name == ("CL") || name == ("cl")) value = CL;
                else if (name == ("DL") || name == ("dl")) value = DL;
                else if (name == ("SIL") || name == ("sil")) value = SIL;
                else if (name == ("DIL") || name == ("dil")) value = DIL;
                else if (name == ("BPL") || name == ("bpl")) value = BPL;
                else if (name == ("SPL") || name == ("spl")) value = SPL;
                else if (name == ("R8B") || name == ("r8b")) value = R8B;
                else if (name == ("R9B") || name == ("r9b")) value = R9B;
                else if (name == ("R10B") || name == ("r10b")) value = R10B;
                else if (name == ("R11B") || name == ("r11b")) value = R11B;
                else if (name == ("R12B") || name == ("r12b")) value = R12B;
                else if (name == ("R13B") || name == ("r13b")) value = R13B;
                else if (name == ("R14B") || name == ("r14b")) value = R14B;
                else if (name == ("R15B") || name == ("r15b")) value = R15B;
                else if (name == ("R8W") || name == ("r8w")) value = R8W;
                else if (name == ("R9W") || name == ("r9w")) value = R9W;
                else if (name == ("R10W") || name == ("r10w")) value = R10W;
                else if (name == ("R11W") || name == ("r11w")) value = R11W;
                else if (name == ("R12W") || name == ("r12w")) value = R12W;
                else if (name == ("R13W") || name == ("r13w")) value = R13W;
                else if (name == ("R14W") || name == ("r14w")) value = R14W;
                else if (name == ("R15W") || name == ("r15w")) value = R15W;
                else if (name == ("R8D") || name == ("r8d")) value = R8D;
                else if (name == ("R9D") || name == ("r9d")) value = R9D;
                else if (name == ("R10D") || name == ("r10d")) value = R10D;
                else if (name == ("R11D") || name == ("r11d")) value = R11D;
                else if (name == ("R12D") || name == ("r12d")) value = R12D;
                else if (name == ("R13D") || name == ("r13d")) value = R13D;
                else if (name == ("R14D") || name == ("r14d")) value = R14D;
                else if (name == ("R15D") || name == ("r15d")) value = R15D;
                else if (name == ("R8") || name == ("r8")) value = R8;
                else if (name == ("R9") || name == ("r9")) value = R9;
                else if (name == ("R10") || name == ("r10")) value = R10;
                else if (name == ("R11") || name == ("r11")) value = R11;
                else if (name == ("R12") || name == ("r12")) value = R12;
                else if (name == ("R13") || name == ("r13")) value = R13;
                else if (name == ("R14") || name == ("r14")) value = R14;
                else if (name == ("R15") || name == ("r15")) value = R15;
                else if (name == ("AX") || name == ("ax")) value = AX;
                else if (name == ("BX") || name == ("bx")) value = BX;
                else if (name == ("CX") || name == ("cx")) value = CX;
                else if (name == ("DX") || name == ("dx")) value = DX;
                else if (name == ("DI") || name == ("di")) value = DI;
                else if (name == ("SI") || name == ("si")) value = SI;
                else if (name == ("BP") || name == ("bp")) value = BP;
                else if (name == ("SP") || name == ("sp")) value = SP;
                else if (name == ("IP") || name == ("ip")) value = IP;
                else if (name == ("SS") || name == ("ss")) value = SS;
                else if (name == ("EAX") || name == ("eax")) value = EAX;
                else if (name == ("EBX") || name == ("ebx")) value = EBX;
                else if (name == ("ECX") || name == ("ecx")) value = ECX;
                else if (name == ("EDX") || name == ("edx")) value = EDX;
                else if (name == ("EDI") || name == ("edi")) value = EDI;
                else if (name == ("ESI") || name == ("esi")) value = ESI;
                else if (name == ("EBP") || name == ("ebp")) value = EBP;
                else if (name == ("ESP") || name == ("esp")) value = ESP;
                else if (name == ("EIP") || name == ("eip")) value = EIP;
                else if (name == ("RAX") || name == ("rax")) value = RAX;
                else if (name == ("RBX") || name == ("rbx")) value = RBX;
                else if (name == ("RCX") || name == ("rcx")) value = RCX;
                else if (name == ("RDX") || name == ("rdx")) value = RDX;
                else if (name == ("RDI") || name == ("rdi")) value = RDI;
                else if (name == ("RSI") || name == ("rsi")) value = RSI;
                else if (name == ("RBP") || name == ("rbp")) value = RBP;
                else if (name == ("RSP") || name == ("rsp")) value = RSP;
                else if (name == ("RIP") || name == ("rip")) value = RIP;
                else if (name == ("EFER") || name == ("efer")) value = EFER;
                else if (name == ("FLAGS") || name == ("flags")) value = FLAGS;
                else if (name == ("EFLAGS") || name == ("eflags")) value = EFLAGS;
                else if (name == ("RFLAGS") || name == ("rflags")) value = RFLAGS;
                else if (name == ("GDTR") || name == ("gdtr")) value = GDTR;
                else if (name == ("IDTR") || name == ("idtr")) value = IDTR;
                else if (name == ("LDTR") || name == ("ldtr")) value = LDTR;
                else if (name == ("MSR") || name == ("msr")) value = MSR;
                else if (name == ("TPR") || name == ("tpr")) value = TPR;
                else if (name == ("TR") || name == ("tr")) value = TR;

                if (name == ("MMX0") || name == ("mmx0")) value = MMX0;
                else if (name == ("MMX1") || name == ("mmx1")) value = MMX1;
                else if (name == ("MMX2") || name == ("mmx2")) value = MMX2;
                else if (name == ("MMX3") || name == ("mmx3")) value = MMX3;
                else if (name == ("MMX4") || name == ("mmx4")) value = MMX4;
                else if (name == ("MMX5") || name == ("mmx5")) value = MMX5;
                else if (name == ("MMX6") || name == ("mmx6")) value = MMX6;
                else if (name == ("MMX7") || name == ("mmx7")) value = MMX7;

                else if (name == ("XMM0") || name == ("xmm0")) value = XMM0;
                else if (name == ("XMM1") || name == ("xmm1")) value = XMM1;
                else if (name == ("XMM2") || name == ("xmm2")) value = XMM2;
                else if (name == ("XMM3") || name == ("xmm3")) value = XMM3;
                else if (name == ("XMM4") || name == ("xmm4")) value = XMM4;
                else if (name == ("XMM5") || name == ("xmm5")) value = XMM5;
                else if (name == ("XMM6") || name == ("xmm6")) value = XMM6;
                else if (name == ("XMM7") || name == ("xmm7")) value = XMM7;
                else if (name == ("XMM8") || name == ("xmm8")) value = XMM8;
                else if (name == ("XMM9") || name == ("xmm9")) value = XMM9;
                else if (name == ("XMM10") || name == ("xmm10")) value = XMM10;
                else if (name == ("XMM11") || name == ("xmm11")) value = XMM11;
                else if (name == ("XMM12") || name == ("xmm12")) value = XMM12;
                else if (name == ("XMM13") || name == ("xmm13")) value = XMM13;
                else if (name == ("XMM14") || name == ("xmm14")) value = XMM14;
                else if (name == ("XMM15") || name == ("xmm15")) value = XMM15;

                else if (name == ("YMM0") || name == ("ymm0")) value = YMM0;
                else if (name == ("YMM1") || name == ("ymm1")) value = YMM1;
                else if (name == ("YMM2") || name == ("ymm2")) value = YMM2;
                else if (name == ("YMM3") || name == ("ymm3")) value = YMM3;
                else if (name == ("YMM4") || name == ("ymm4")) value = YMM4;
                else if (name == ("YMM5") || name == ("ymm5")) value = YMM5;
                else if (name == ("YMM6") || name == ("ymm6")) value = YMM6;
                else if (name == ("YMM7") || name == ("ymm7")) value = YMM7;
                else if (name == ("YMM8") || name == ("ymm8"))  value = YMM8;
                else if (name == ("YMM9") || name == ("ymm9"))  value = YMM9;
                else if (name == ("YMM10") || name == ("ymm10")) value = YMM10;
                else if (name == ("YMM11") || name == ("ymm11")) value = YMM11;
                else if (name == ("YMM12") || name == ("ymm12")) value = YMM12;
                else if (name == ("YMM13") || name == ("ymm13")) value = YMM13;
                else if (name == ("YMM14") || name == ("ymm14")) value = YMM14;
                else if (name == ("YMM15") || name == ("ymm15")) value = YMM15;
            }

            __enum(register_t);
            __enumtostring(register_t);

            const string& to_string() const noexcept
            {
                switch (value)
                {
                case AH: return s("AH");
                case BH: return s("BH");
                case CH: return s("CH");
                case DH: return s("DH");
                case AL: return s("AL");
                case BL: return s("BL");
                case CL: return s("CL");
                case DL: return s("DL");

                case SIL: return s("SIL");
                case DIL: return s("DIL");
                case BPL: return s("BPL");
                case SPL: return s("SPL");

                case R8B:  return s("R8B");
                case R9B:  return s("R9B");
                case R10B: return s("R10B");
                case R11B: return s("R11B");
                case R12B: return s("R12B");
                case R13B: return s("R13B");
                case R14B: return s("R14B");
                case R15B: return s("R15B");

                case  R8W:  return s("R8W");
                case  R9W:  return s("R9W");
                case R10W: return s("R10W");
                case R11W: return s("R11W");
                case R12W: return s("R12W");
                case R13W: return s("R13W");
                case R14W: return s("R14W");
                case R15W: return s("R15W");

                case  R8D:  return s("R8D");
                case  R9D:  return s("R9D");
                case R10D: return s("R10D");
                case R11D: return s("R11D");
                case R12D: return s("R12D");
                case R13D: return s("R13D");
                case R14D: return s("R14D");
                case R15D: return s("R15D");

                case  R8:  return s("R8");
                case  R9:  return s("R9");
                case R10: return s("R10");
                case R11: return s("R11");
                case R12: return s("R12");
                case R13: return s("R13");
                case R14: return s("R14");
                case R15: return s("R15");


                case AX: return s("AX");
                case BX: return s("BX");
                case CX: return s("CX");
                case DX: return s("DX");
                case DI: return s("DI");
                case SI: return s("SI");
                case BP: return s("BP");
                case SP: return s("SP");
                case IP: return s("IP");
                case SS: return s("SS");

                case EAX: return s("EAX");
                case EBX: return s("EBX");
                case ECX: return s("ECX");
                case EDX: return s("EDX");
                case EDI: return s("EDI");
                case ESI: return s("ESI");
                case EBP: return s("EBP");
                case ESP: return s("ESP");
                case EIP: return s("EIP");

                case RAX: return s("RAX");
                case RBX: return s("RBX");
                case RCX: return s("RCX");
                case RDX: return s("RDX");
                case RDI: return s("RDI");
                case RSI: return s("RSI");
                case RBP: return s("RBP");
                case RSP: return s("RSP");
                case RIP: return s("RIP");

                case EFER: return s("EFER");
                case FLAGS: return s("FLAGS");
                case EFLAGS: return s("EFLAGS");
                case RFLAGS: return s("rFLAGS");

                case GDTR: return s("GDTR");
                case IDTR: return s("IDTR");
                case LDTR: return s("LDTR");
                case MSR: return s("MSR");

                case TPR: return s("TPR");
                case TR: return s("TR");

                case MMX0: return s("MMX0");
                case MMX1: return s("MMX1");
                case MMX2: return s("MMX2");
                case MMX3: return s("MMX3");
                case MMX4: return s("MMX4");
                case MMX5: return s("MMX5");
                case MMX6: return s("MMX6");
                case MMX7: return s("MMX7");

                case XMM0: return s("XMM0");
                case XMM1: return s("XMM1");
                case XMM2: return s("XMM2");
                case XMM3: return s("XMM3");
                case XMM4: return s("XMM4");
                case XMM5: return s("XMM5");
                case XMM6: return s("XMM6");
                case XMM7: return s("XMM7");

                case YMM0: return s("YMM0");
                case YMM1: return s("YMM1");
                case YMM2: return s("YMM2");
                case YMM3: return s("YMM3");
                case YMM4: return s("YMM4");
                case YMM5: return s("YMM5");
                case YMM6: return s("YMM6");
                case YMM7: return s("YMM7");
                }
                return s("<invalid>");
            }

            /// <summary>
            /// Size in bits
            /// </summary>
            /// <returns>The size of the register in bits</returns>
            uint32_t size() const noexcept
            {
                switch (value)
                {
                case R8B: case R9B: case R10B: case R11B: case R12B: case R13B: case R14B: case R15B: return 8;
                case R8W: case R9W: case R10W: case R11W: case R12W: case R13W: case R14W: case R15W: return 16;
                case R8D: case R9D: case R10D: case R11D: case R12D: case R13D: case R14D: case R15D: return 32;
                case R8: case R9: case R10: case R11: case R12: case R13: case R14: case R15: return 64;

                case AX: case BX: case CX: case DX: case DI: case SI: case BP: case SP: case SS: return 16;
                case EAX: case EBX: case ECX: case EDX: case EDI: case ESI: case EBP: case ESP: return 32;
                case RAX: case RBX: case RCX: case RDX: case RDI: case RSI: case RBP: case RSP: return 64;
                }
                return 0;
            }

            _executeinline bool is_extended() const noexcept
            {
                return (value >= register_t::R8B && value <= register_t::R15)
                    || (value >= register_t::XMM8 && value <= register_t::XMM15)
                    || (value >= register_t::YMM8 && value <= register_t::YMM15)
                    ;
            }
        };

        /// <summary>
        /// Opcode prefixes 
        /// </summary>
        struct prefix_t
        {
            enum vt
            {
                // changes operand size of memory or register operand
                opsize_override = 0x66,

                // changes address size of memory operand
                addrsize_override = 0x67,

                // forces use of <register> segments for memory operands
                // ignored in 64 bit
                segment_override_CS = 0x2E,
                segment_override_DS = 0x3E,
                segment_override_ES = 0x26,
                segment_override_SS = 0x36,

                // not ignored in 64 bit
                segment_override_FS = 0x64,
                segment_override_GS = 0x65,

                lock = 0xF0,

                repeat = 0xF3,
                repeatn = 0xF2,

                invalid = 0xFF
            } value;

            prefix_t(const string& name) noexcept :
                value(invalid)
            {
                if (name == s("CS")) value = segment_override_CS;
                else if (name == s("DS")) value = segment_override_DS;
                else if (name == s("ES")) value = segment_override_ES;
                else if (name == s("SS")) value = segment_override_SS;
                else if (name == s("FS")) value = segment_override_FS;
                else if (name == s("GS")) value = segment_override_GS;
                else if (name == s("LOCK")) value = lock;
                else if (name == s("REP") || name == s("REPE") || name == s("REPZ")) value = repeat;
                else if (name == s("REPNZ")) value = repeatn;
            }

            __enum(prefix_t);
            __enumtostring(prefix_t);
            const string& to_string() const noexcept
            {
                switch (value)
                {
                case opsize_override: return s("opsize_override");
                case addrsize_override: return s("addrsize_override");
                case segment_override_CS: return s("segment_override_CS");
                case segment_override_DS: return s("segment_override_DS");
                case segment_override_ES: return s("segment_override_ES");
                case segment_override_SS: return s("segment_override_SS");
                case segment_override_FS: return s("segment_override_FS");
                case segment_override_GS: return s("segment_override_GS");
                case lock: return s("lock");
                case repeat: return s("repeat");
                case repeatn: return s("repeatn");
                }
            }
        };



#pragma pack(push)
#pragma pack(1)
        struct register_code_t
        {
            enum vt
            {
                AX = 0b000,
                CX = 0b001,
                DX = 0b010,
                BX = 0b011,
                SP = 0b100,
                BP = 0b101,
                SI = 0b110,
                DI = 0b111,
                invalid
            } value;
            register_code_t(register_t reg) noexcept
            {
                switch (reg)
                {
                case register_t::XMM0: case register_t::XMM8:
                case register_t::R8: case register_t::R8D:
                case register_t::EAX:
                case register_t::RAX: value = AX; break;

                case register_t::XMM1: case register_t::XMM11:
                case register_t::R11: case register_t::R11D:
                case register_t::EBX:
                case register_t::RBX: value = BX; break;

                case register_t::XMM2: case register_t::XMM9:
                case register_t::R9: case register_t::R9D:
                case register_t::ECX:
                case register_t::RCX: value = CX; break;

                case register_t::XMM3: case register_t::XMM10:
                case register_t::R10: case register_t::R10D:
                case register_t::EDX:
                case register_t::RDX: value = DX; break;

                case register_t::XMM4: case register_t::XMM12:
                case register_t::R12: case register_t::R12D:
                case register_t::ESP:
                case register_t::RSP: value = SP; break;

                case register_t::XMM5: case register_t::XMM13:
                case register_t::R13: case register_t::R13D:
                case register_t::EBP:
                case register_t::RBP: value = BP; break;

                case register_t::XMM6: case register_t::XMM14:
                case register_t::R14: case register_t::R14D:
                case register_t::ESI:
                case register_t::RSI: value = SI; break;

                case register_t::XMM7: case register_t::XMM15:
                case register_t::R15: case register_t::R15D:
                case register_t::EDI:
                case register_t::RDI: value = DI; break;
                default: __assert(false);
                }
            }
            register_code_t(int v) : value((vt)v) {}
            __enum(register_code_t);
        };

        struct rex_t
        {
            // 1-bit (msb) extension of the ModRM r/m
            // field1, SIB base field1, or opcode reg field,
            // permitting access to 16 registers. 
            uint8_t b : 1 = 0;

            // 1-bit (msb) extension of the SIB index field1,
            // permitting access to 16 registers. 
            uint8_t x : 1 = 0;

            // 1-bit (msb) extension of the ModRM reg
            // field1, permitting access to 16 registers.
            uint8_t r : 1 = 0;

            // 0 = Default operand size
            // 1 = 64-bit operand size
            uint8_t w : 1 = 0;

            uint8_t _id_ : 4 = 4;

            _executeinline uint32_t flags() const noexcept { return (b << 3) | (x << 2) | (r << 1) | w; }
            _executeinline uint32_t operand_size() const noexcept { return w == 1 ? 64 : 32; }
        };
        struct modrm_t
        {
            uint8_t rm : 3 = 0;
            uint8_t reg : 3 = 0;
            uint8_t mod : 2 = 0;

            struct mode_t
            {
                enum vt
                {
                    register_direct = 0b11,

                    register_indirect = 0b00,
                    indirect_disp32 = 0b00,
                    indirect_rbp_disp8 = 0b01,
                    indirect_rbp_disp32 = 0b10
                } value;

                mode_t(uint8_t mode) noexcept : value((vt)mode) {}

                __enum(mode_t);
                __enumtostring(mode_t);
                const string& to_string() const noexcept
                {
                    switch (value)
                    {
                    case register_direct: return s("register_direct");
                    }
                    return s("<invalid>");
                }
            };
        };
        struct sib_t
        {
            uint8_t base : 3 = 0;
            uint8_t index : 3 = 0;
            uint8_t scale : 2 = 0;
        };

        // vex
        struct vex0_t
        {
            enum vt : uint8_t {
                VEX_2byte = 0xC5,
                VEX_3byte = 0xC4,
                XOP = 0x8F
            } value;
        };
        struct vex1_t
        {
            // Opcode map select
            /*
            The five-bit map_select field is used to select an alternate
            opcode map. The map_select encoding spaces for VEX and XOP are disjoint. Table 1-19 below lists
            the encodings for VEX.map_select and Table 1-20 lists the encodings for XOP.map_select.
            */
            uint8_t   map_select : 5 = 0;

            // Inverted one-bit extension, r/m field or SIB base field
            /*
            The bit-inverted equivalent of the REX.B bit, available only in the 3-byte prefix
            format. A one-bit extension of either the ModRM.r/m field, to specify a GPR or XMM register, or of
            the SIB base field, to specify a GPR. This permits access to all 16 GPR and YMM/XMM registers. In
            32-bit protected and compatibility modes, this bit is ignored.
            */
            uint8_t   b : 1 = 1;

            // Inverted one-bit extension of SIB index field
            /*
            The bit-inverted equivalent of the REX.X bit. A one-bit extension of the
            SIB.index field in 64-bit mode, permitting access to 16 YMM/XMM and GPR registers. In 32-bit
            protected and compatibility modes, this value must be 1.
            */
            uint8_t   x : 1 = 1;

            // Inverted one-bit extension of ModRM reg field
            /*
            The bit-inverted equivalent of the REX.R bit. A one-bit extension of the
            ModRM.reg field in 64-bit mode, permitting access to 16 YMM/XMM and GPR registers. In 32-bit
            protected and compatibility modes, the value must be 1.
            */
            uint8_t   r : 1 = 1;
        };
        struct vex1_2byte_t
        {

            //  Implied 66, F2, or F3 opcode extension
            /*
            Specifies an implied 66h, F2h, or F3h opcode extension which is used in a
            way analogous to the legacy instruction encodings to extend the opcode encoding space. The
            correspondence between the encoding of the VEX/XOP.pp field and its function as an opcode modifier
            is shown in Table 1-22. The legacy prefixes 66h, F2h, and F3h are not allowed in the encoding of
            extended instructions.

            Binary Value Implied Prefix
            00           None
            01           66h
            10           F3h
            11           F2h
            */
            uint8_t pp : 2;

            //  Vector length specifier
            /*
            L = 0 specifies 128-bit vector length (XMM registers/128-bit memory
                locations). L=1 specifies 256-bit vector length (YMM registers/256-bit memory locations). For SSE or
                XOP instructions with scalar operands, the L bit is ignored. Some vector SSE instructions support only
                the 128 bit vector size. For these instructions, L is cleared to 0.
            */
            uint8_t L : 1;

            // Source or destination register selector, in ones’ complement format
            /*
            Used to specify an additional operand for three and four operand
            instructions. Encodes an XMM or YMM register in inverted ones’ complement form, as shown in
            Table 1-21.

            Binary Value Register
            0000         XMM15/YMM15
            0001         XMM14/YMM14
            0010         XMM13/YMM13
            0011         XMM12/YMM12
            0100         XMM11/YMM11
            0101         XMM10/YMM10
            0110         XMM09/YMM09
            0111         XMM08/YMM08
            1000         XMM07/YMM07
            1001         XMM06/YMM06
            1010         XMM05/YMM05
            1011         XMM04/YMM04
            1100         XMM03/YMM03
            1101         XMM02/YMM02
            1110         XMM01/YMM01
            1111         XMM00/YMM00
            */
            uint8_t vvvv : 4;


            // Inverted one-bit extension of ModRM reg field
            /*
            The bit-inverted equivalent of the REX.R bit. A one-bit extension of the
            ModRM.reg field in 64-bit mode, permitting access to 16 YMM/XMM and GPR registers. In 32-bit
            protected and compatibility modes, the value must be 1.
            */
            uint8_t   r : 1 = 1;
        };
        struct vex2_t
        {
            //  Implied 66, F2, or F3 opcode extension
            /*
            Specifies an implied 66h, F2h, or F3h opcode extension which is used in a
            way analogous to the legacy instruction encodings to extend the opcode encoding space. The
            correspondence between the encoding of the VEX/XOP.pp field and its function as an opcode modifier
            is shown in Table 1-22. The legacy prefixes 66h, F2h, and F3h are not allowed in the encoding of
            extended instructions.

            Binary Value Implied Prefix
            00           None
            01           66h
            10           F3h
            11           F2h
            */
            uint8_t pp : 2;

            //  Vector length specifier
            /*
            L = 0 specifies 128-bit vector length (XMM registers/128-bit memory
                locations). L=1 specifies 256-bit vector length (YMM registers/256-bit memory locations). For SSE or
                XOP instructions with scalar operands, the L bit is ignored. Some vector SSE instructions support only
                the 128 bit vector size. For these instructions, L is cleared to 0.
            */
            uint8_t L : 1;

            // Source or destination register selector, in ones’ complement format
            /*
            Used to specify an additional operand for three and four operand
            instructions. Encodes an XMM or YMM register in inverted ones’ complement form, as shown in
            Table 1-21.

            Binary Value Register
            0000         XMM15/YMM15
            0001         XMM14/YMM14
            0010         XMM13/YMM13
            0011         XMM12/YMM12
            0100         XMM11/YMM11
            0101         XMM10/YMM10
            0110         XMM09/YMM09
            0111         XMM08/YMM08
            1000         XMM07/YMM07
            1001         XMM06/YMM06
            1010         XMM05/YMM05
            1011         XMM04/YMM04
            1100         XMM03/YMM03
            1101         XMM02/YMM02
            1110         XMM01/YMM01
            1111         XMM00/YMM00
            */
            uint8_t vvvv : 4;

            // Default operand size override for a general
            // purpose register to 64 - bit size in 64 - bit mode;
            // operand configuration specifier for certain
            //     YMM / XMM - based operations.
            // Function is instruction-specific. The bit is often used to configure source
            // operand order.
            uint8_t w : 1;
        };
        struct prefix
        {
            enum vt : uint8_t
            {
                invalid = 0,
                OperandSizeOverride = 0x66,
                REPE = 0xF3,
                REPZ = REPE,
                REPNE = 0xF2,
                REPNZ = REPNE
            } value;

            __enum(prefix);
            prefix(const buffer<char>& name) noexcept :
                value(invalid)
            {
                if (name == "repe") value = REPE;
                else if (name == "repz") value = REPZ;
                else if (name == "repne") value = REPNE;
                else if (name == "repnz") value = REPNZ;
            }
            prefix(uint8_t opcode) noexcept :
                value(invalid)
            {
                if (opcode == OperandSizeOverride) value = OperandSizeOverride;
                else if (opcode == REPE) value = REPE;
                else if (opcode == REPNE) value = REPNE;
            }
        };

#pragma pack(pop)


        struct cpuq_t
        {
            struct regpos_t
            {
                enum vt : uint8_t
                {
                    EAX = 0,
                    EBX,
                    ECX,
                    EDX
                } value;
                __enum(regpos_t);
            };
            uint32_t fn;
            regpos_t regpos;
            uint8_t bit_start;
            uint8_t bit_end;
            const char* description;
            uint32_t subfn = 0;

            uint32_t mask(int32_t size)
            {
                if (size == 0) return 0;
                return (1 << (size - 1)) | mask(size - 1);
            }


            optional<uint32_t> execute();
            uint32_t execute(uint32_t subfn_override)
            {
                return 0;
            }
        };

        struct argtype_t
        {
            enum vt
            {
                unused = 0,
                EAX = 0b10000000,
                RAX = EAX + 1,
                reg32 = EAX + 2,
                reg64 = EAX + 3,
                mem32 = EAX + 4,
                mem64 = EAX + 5,
                regmem32 = EAX + 6,
                regmem64 = EAX + 7,
                imm8 = 0b00010000,
                imm16 = imm8 + 1,
                imm32 = imm8 + 2,
                imm64 = imm8 + 3
            } value;

            __enum(argtype_t);

            bool valid() const noexcept
            {
                switch (value)
                {
                case EAX:
                case RAX:
                case regmem32:
                case regmem64:
                case mem32:
                case mem64:
                case reg32:
                case reg64:
                case imm8:
                case imm16:
                case imm32:
                case imm64:
                    return true;
                }
                return false;
            }

            _executeinline uint32_t operand_size() const noexcept
            {
                if (value == imm8) return 8;
                if (value == EAX || value == regmem32 || value == mem32 || value == reg32 || value == imm32 || value == imm16) return 32;
                return 64;
            }

            _executeinline argtype_t& operator++() noexcept
            {
                value = (vt)(((int32_t)value) + 1);
                return *this;
            }

            _executeinline bool is_ax() const noexcept
            {
                return value == EAX || value == RAX;
            }
            _executeinline bool is_modrm() const noexcept
            {
                return value >= reg32 && value <= regmem64;
            }
            _executeinline bool is_immediate() const noexcept
            {
                return (((int32_t)value) & imm8) != 0;
            }
        };

        struct signature_t
        {
            char      label[16] = { 0 };
            argtype_t types[4] = { argtype_t::unused, argtype_t::unused, argtype_t::unused, argtype_t::unused };

            uint32_t operand_size() const noexcept
            {
                for (int i = 0; i < 4; ++i)
                    if (
                        types[i] == argtype_t::RAX
                        || types[i] == argtype_t::regmem64
                        || types[i] == argtype_t::reg64
                        || types[i] == argtype_t::imm64)
                    {
                        return 64;
                    }
                return 32;
            }

            _executeinline bool operator==(const signature_t& other) const noexcept
            {
                return memcmp(types, other.types, sizeof(types)) == 0
                    && buffer<char>::from_ptr(label, 16) == buffer<char>::from_ptr(other.label, 16);
            }
        };

        struct argument_t
        {
            // register direct
            register_t reg = register_t::none;

            // sib 
            modrm_t::mode_t mode;
            register_t base = register_t::RBP,  // These both default to the "unused" state for these flags
                index = register_t::RSP; // 
            uint32_t   scale = 0;
            uint32_t   disp = 0;

            // immediates
            uint64_t imm;

            _executeinline bool is_reg_ex() const noexcept
            {
                return reg.is_extended();
            }
            _executeinline bool is_index_ex() const noexcept
            {
                return mode != modrm_t::mode_t::register_direct && index.is_extended();
            }
            _executeinline bool is_base_ex() const noexcept
            {
                return mode != modrm_t::mode_t::register_direct && base.is_extended();
            }
        };

        struct opcode_flags_t
        {
            enum vt : uint8_t
            {
                none = 0,
                register_adjusted = 0b00000001,
                regopcode_ext = 0b00000010,
                multibyte_opcode = 0b00000100,
                requires_cpuid_lookup = 0b00001000,
                vex_extended = 0b00010000,
                operand64size_override = 0b00100000,
                legacy_prefixes = 0b01000000,
                label = 0b10000000,
            } value;
            __enum(opcode_flags_t);
            _executeinline bool has(vt v) noexcept
            {
                return (value & v) != 0;
            }

            static friend opcode_flags_t operator|(vt a, vt b) noexcept
            {
                return opcode_flags_t((vt)((int32_t)a | (int32_t)b));
            }
            opcode_flags_t& operator|=(vt b) noexcept
            {
                value = (value | b);
                return *this;
            }
        };

        struct opcode_t
        {
            uint8_t code = 0;
            const char* description = nullptr;
            opcode_flags_t flags = opcode_flags_t::none;

            struct
            {
                uint8_t _f_regopcode_ext = 0;

                uint8_t _f_opcode_count = 0;
                uint8_t _f_opcode_extra[4];

                uint8_t _f_cpuid_reqs = 0;
                cpuq_t* _f_cpuid_lookups[4];

                vex0_t       _f_vex0;
                vex1_2byte_t _f_vex1_2byte;
                vex1_t       _f_vex1;
                vex2_t       _f_vex2;
                uint8_t      _f_vex_vvvv_arg;

                uint8_t _f_legacy_prefix_count = 0;
                prefix  _f_legacy_prefixes[5];
            } flagvars;
        };


        //
        // [legacy-prefix <= 5x] [rex-prefix] [opcode-map escape] opcode [modrm] [sib] [imm]
        //
        struct instruction_t
        {
            uint32_t    prefix_count = 0;
            prefix      prefixes[5];
            opcode_t    opcode;
            uint8_t     opcode_byte_count = 0;
            uint8_t     opcode_start = 0;
            uint8_t     opcode_bytes[15];
            argument_t  args[4];
            signature_t signature;
            int64_t     instruction_start;
            int64_t     instruction_length;

        private:
            bool compute_modrmsib(argtype_t type, argument_t arg, modrm_t& target_modrm, sib_t& target_sib, uint32_t* sibdisp)
            {
                if (!type.is_modrm()) return false;

                if (type == argtype_t::reg32 || type == argtype_t::reg64)
                {
                    if (opcode.flags.has(opcode_flags_t::regopcode_ext))
                    {
                        target_modrm.rm = register_code_t(arg.reg);
                    }
                    else
                    {
                        target_modrm.reg = register_code_t(arg.reg);
                    }
                    __assert(arg.mode == modrm_t::mode_t::register_direct);
                    return false;
                }
                else if (type == argtype_t::regmem32 || type == argtype_t::regmem64)
                {
                    target_modrm.mod = arg.mode;

                    if (arg.reg != register_t::none)
                    {
                        target_modrm.rm = register_code_t(arg.reg);

                        // sib indicator
                        if (target_modrm.mod != modrm_t::mode_t::register_direct
                            && target_modrm.rm == 0b100)
                        {
                            target_sib.base = 0b100; // rSP
                            target_sib.index = 0b100; // (none)
                            target_sib.scale = 0;     // *1
                            return true;
                        }
                    }
                    else
                    {
                        target_modrm.rm = 0b100;
                        *sibdisp = arg.disp;

                        // bp base
                        if (target_modrm.mod != modrm_t::mode_t::register_direct
                            && arg.base == register_t::RBP || arg.base == register_t::EBP)
                        {
                            target_modrm.rm = 0b101;
                            return false;
                        }
                        else
                            // sib indicator
                            if (target_modrm.mod != modrm_t::mode_t::register_direct)
                            {
                                target_sib.base = register_code_t(arg.base);
                                target_sib.index = register_code_t(arg.index);
                                target_sib.scale = arg.scale;
                                return true;
                            }
                    }

                    return false;
                }
                __assert(false);
                return false;
            }
            error apply_imm(buffervec<uint8_t>& assembly, argtype_t type, const argument_t& arg) noexcept
            {
                uint64_t imm = arg.imm;
                if (opcode.flags.has(opcode_flags_t::label))
                {
                    imm = (uint64_t)(((int64_t)arg.imm) - (assembly.size() - instruction_start) - (type.operand_size() >> 3));
                }

                if (type.is_immediate())
                {
                    if (type == argtype_t::imm8 && !assembly.push(*((uint8_t*)&imm))) return __error(errors::out_of_memory);
                    else if (type == argtype_t::imm16 && !assembly.push(*((uint16_t*)&imm))) return __error(errors::out_of_memory);
                    else if (type == argtype_t::imm32 && !assembly.push(*((uint32_t*)&imm))) return __error(errors::out_of_memory);
                    else if (type == argtype_t::imm64 && !assembly.push(imm)) return __error(errors::out_of_memory);
                }
                return error();
            }
            error apply_modrmsib(buffervec<uint8_t>& assembly, argtype_t type1, argtype_t type2, argument_t arg1, argument_t arg2)
            {
                modrm_t modrm;
                sib_t   sib;

                uint32_t sib_disp = 0;
                bool needs_sib = compute_modrmsib(type1, arg1, modrm, sib, &sib_disp)
                    || compute_modrmsib(type2, arg2, modrm, sib, &sib_disp);

                if (opcode.flags.has(opcode_flags_t::regopcode_ext))
                {
                    modrm.reg = opcode.flagvars._f_regopcode_ext;
                }

                if (!assembly.push(modrm)) return __error(errors::out_of_memory);
                if (needs_sib)
                {
                    if (!assembly.push(sib)) return __error(errors::out_of_memory);
                    if (sib.base == 0b101)
                    {
                        if (modrm.mod == 0b00 && !assembly.push(sib_disp)) return __error(errors::out_of_memory);
                        else if (modrm.mod == 0b01 && !assembly.push((uint8_t)sib_disp)) return __error(errors::out_of_memory);
                        else if (modrm.mod == 0b10 && !assembly.push(sib_disp)) return __error(errors::out_of_memory);
                    }
                }
                else if (modrm.mod != 0b11 && modrm.mod != 0b00 && modrm.rm == 0b101)
                {
                    // base + offset addressing, bp is the base
                    if (modrm.mod == 0b01 && !assembly.push((uint8_t)sib_disp)) return __error(errors::out_of_memory);
                    else if (modrm.mod == 0b10 && !assembly.push(sib_disp)) return __error(errors::out_of_memory);
                }

                return error();
            }
            error apply_opcode(buffervec<uint8_t>& assembly) noexcept
            {
                for (uint8_t i = opcode_start; i < opcode_byte_count; ++i)
                {
                    if (!assembly.push(opcode_bytes[i])) return __error(errors::out_of_memory);
                }

                return error();
            }
        public:

            error emit(buffervec<uint8_t>& assembly) noexcept
            {
                instruction_start = assembly.size();

                for (uint32_t i = 0; i < prefix_count; ++i)
                {
                    if (!assembly.push(prefixes[i])) return __error(errors::out_of_memory);
                }
                if (opcode.flags.has(opcode_flags_t::legacy_prefixes))
                {
                    for (uint32_t i = 0; i < opcode.flagvars._f_legacy_prefix_count; ++i)
                    {
                        if (!assembly.push(opcode.flagvars._f_legacy_prefixes[i])) return __error(errors::out_of_memory);
                    }
                }

                opcode_bytes[opcode_byte_count++] = opcode.code;
                if (opcode.flags.has(opcode_flags_t::multibyte_opcode))
                {
                    for (uint8_t i = 0; i < opcode.flagvars._f_opcode_count; ++i)
                    {
                        opcode_bytes[opcode_byte_count++] = opcode.flagvars._f_opcode_extra[i];
                    }
                }

                for (uint8_t i = 0; i < opcode_byte_count; ++i)
                {
                    if (auto pre = prefix(opcode_bytes[i]); pre != prefix::invalid)
                    {
                        if (!assembly.push(pre)) return __error(errors::out_of_memory);
                        ++opcode_start;
                    }
                    else
                    {
                        opcode_bytes[i] = opcode_bytes[i] + (opcode.flags.has(opcode_flags_t::register_adjusted) ? (uint8_t)register_code_t(args[0].reg) : 0);
                        break;
                    }
                }
                if (opcode_start == opcode_byte_count)
                {
                    return __error_msg(errors::assembler::instruction_incomplete, "Instruction contains only prefixes");
                }


                if (opcode.flags.has(opcode_flags_t::vex_extended))
                {
                    uint32_t regarg = (uint32_t)-1,
                        rmarg = (uint32_t)-1,
                        vvvvarg = (uint32_t)-1,
                        immarg = (uint32_t)-1;

                    for (uint32_t i = 0; i < 4; ++i)
                        if ((signature.types[i] == argtype_t::reg32 || signature.types[i] == argtype_t::reg64) && i != opcode.flagvars._f_vex_vvvv_arg)
                        {
                            regarg = i;
                        }
                        else if (signature.types[i] == argtype_t::regmem32 || signature.types[i] == argtype_t::regmem64)
                        {
                            rmarg = i;
                        }
                        else if (i == opcode.flagvars._f_vex_vvvv_arg)
                        {
                            vvvvarg = i;
                        }
                        else if (signature.types[i].is_immediate())
                        {
                            immarg = i;
                        }

                    if (!assembly.push(opcode.flagvars._f_vex0)) return __error(errors::out_of_memory);

                    if (regarg != (uint32_t)-1)
                        opcode.flagvars._f_vex1.r = (args[regarg].is_reg_ex() ? 0 : 1);

                    if (rmarg != (uint32_t)-1)
                        opcode.flagvars._f_vex1.x = (args[rmarg].is_index_ex() ? 0 : 1);
                    opcode.flagvars._f_vex1.b = (args[rmarg].is_base_ex() || args[rmarg].is_reg_ex() ? 0 : 1);

                    if (vvvvarg != (uint32_t)-1)
                        opcode.flagvars._f_vex2.vvvv = ~register_code_t(args[vvvvarg].reg);

                    if (!assembly.push(opcode.flagvars._f_vex1)) return __error(errors::out_of_memory);
                    if (!assembly.push(opcode.flagvars._f_vex2)) return __error(errors::out_of_memory);


                    __checked(apply_opcode(assembly));
                    if (regarg != (uint32_t)-1 || rmarg != (uint32_t)-1)
                        __checked(apply_modrmsib(assembly,
                            regarg == (uint32_t)-1 ? argtype_t::unused : signature.types[regarg].value,
                            rmarg == (uint32_t)-1 ? argtype_t::unused : signature.types[rmarg].value,
                            regarg == (uint32_t)-1 ? argument_t() : args[regarg],
                            rmarg == (uint32_t)-1 ? argument_t() : args[rmarg])
                        );
                }
                else
                {

                    rex_t rex{
                        .b = (uint8_t)((signature.types[0].is_modrm() && args[0].is_base_ex())
                                        || (args[0].is_reg_ex() && (signature.types[0] == argtype_t::regmem32 || signature.types[0] == argtype_t::regmem64))
                                        || (signature.types[1].is_modrm() && args[1].is_base_ex())
                                        || (args[1].is_reg_ex() && (signature.types[1] == argtype_t::regmem32 || signature.types[1] == argtype_t::regmem64))
                                        || ((args[0].is_reg_ex() && (signature.types[0] == argtype_t::reg32 || signature.types[0] == argtype_t::reg64) && opcode.flags.has(opcode_flags_t::register_adjusted))) ? 1 : 0),

                        .x = (uint8_t)((signature.types[0].is_modrm() && args[0].is_index_ex()) || (signature.types[1].is_modrm() && args[1].is_index_ex()) ? 1 : 0),

                        .r = (uint8_t)(((signature.types[0].is_modrm() && args[0].is_index_ex())
                                        || (args[0].is_reg_ex() && (signature.types[0] == argtype_t::reg32 || signature.types[0] == argtype_t::reg64))
                                        || (signature.types[1].is_modrm() && args[1].is_index_ex())
                                        || (args[1].is_reg_ex() && (signature.types[1] == argtype_t::reg32 || signature.types[1] == argtype_t::reg64)))
                                        && !((args[0].is_reg_ex() && (signature.types[0] == argtype_t::reg32 || signature.types[0] == argtype_t::reg64) && opcode.flags.has(opcode_flags_t::register_adjusted))) ? 1 : 0),

                        .w = (uint8_t)((signature.operand_size() == 32 ? 0 : 1) | (opcode.flags.has(opcode_flags_t::operand64size_override) ? 1 : 0))
                    };
                    if (rex.flags() != 0) if (!assembly.push(rex)) return __error(errors::out_of_memory);

                    __checked(apply_opcode(assembly));


                    /// if the instruction is "register-adjusted", it means that the register code of the 
                    /// register selected for argument 1 is added to the base opcode to form the final opcode
                    /// 
                    /// in that case, the argtype is still reg32 or reg64, but the argument is not a modrm
                    if ((!opcode.flags.has(opcode_flags_t::register_adjusted) && signature.types[0].is_modrm()) || signature.types[1].is_modrm())
                    {
                        __checked(apply_modrmsib(assembly, signature.types[0], signature.types[1], args[0], args[1]));
                    }
                }

                for (int i = 0; i < 4; ++i)
                    __checked(apply_imm(assembly, signature.types[i], args[i]));

                instruction_length = assembly.size() - instruction_start;

                return error();
            }
        };
    }
}