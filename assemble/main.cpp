
#include "precompiled.h"


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
            else if (name == ("XMM10")|| name == ("xmm10")) value = XMM10;
            else if (name == ("XMM11")|| name == ("xmm11")) value = XMM11;
            else if (name == ("XMM12")|| name == ("xmm12")) value = XMM12;
            else if (name == ("XMM13")|| name == ("xmm13")) value = XMM13;
            else if (name == ("XMM14")|| name == ("xmm14")) value = XMM14;
            else if (name == ("XMM15")|| name == ("xmm15")) value = XMM15;

            else if (name == ("YMM0") || name == ("ymm0")) value = YMM0;
            else if (name == ("YMM1") || name == ("ymm1")) value = YMM1;
            else if (name == ("YMM2") || name == ("ymm2")) value = YMM2;
            else if (name == ("YMM3") || name == ("ymm3")) value = YMM3;
            else if (name == ("YMM4") || name == ("ymm4")) value = YMM4;
            else if (name == ("YMM5") || name == ("ymm5")) value = YMM5;
            else if (name == ("YMM6") || name == ("ymm6")) value = YMM6;
            else if (name == ("YMM7") || name == ("ymm7")) value = YMM7;
            else if (name == ("YMM8")  || name == ("ymm8"))  value = YMM8;
            else if (name == ("YMM9")  || name == ("ymm9"))  value = YMM9;
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
        argtype_t types[4]  = { argtype_t::unused, argtype_t::unused, argtype_t::unused, argtype_t::unused };

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
            register_adjusted      = 0b00000001,
            regopcode_ext          = 0b00000010,
            multibyte_opcode       = 0b00000100,
            requires_cpuid_lookup  = 0b00001000,
            vex_extended           = 0b00010000,
            operand64size_override = 0b00100000,
            legacy_prefixes        = 0b01000000,
            label                  = 0b10000000,
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
                     if (type == argtype_t::imm8  && !assembly.push(*((uint8_t*)&imm ))) return __error(errors::out_of_memory);
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
                uint32_t regarg  = (uint32_t)-1, 
                         rmarg   = (uint32_t)-1, 
                         vvvvarg = (uint32_t)-1,
                         immarg  = (uint32_t)-1;

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

    umap<string, cpuq_t> cpu_queries = {
        { "ExtFamily",  { 1, cpuq_t::regpos_t::EAX, 20, 28, "Processor extended family. See above for definition of Family[7:0]. (APM3)"  } },
        { "ExtModel",   { 1, cpuq_t::regpos_t::EAX, 16, 20, "Processor extended model. See above for definition of Model[7:0]. (APM3)."  } },
        { "BaseFamily", { 1, cpuq_t::regpos_t::EAX, 8, 12,  "Base processor family. See above for definition of Family[7:0]. (APM3)."  } },
        { "BaseModel",  { 1, cpuq_t::regpos_t::EAX, 4, 8,   "Base processor model. See above for definition of Model[7:0]. (APM3)."  } },
        { "Stepping",   { 1, cpuq_t::regpos_t::EAX, 0, 4,   "Processor stepping. Processor stepping (revision) for a specific model. (APM3)."  } },

        { "LocalApicId",           { 1, cpuq_t::regpos_t::EBX, 24, 32, "Initial local APIC physical ID. The 8-bit value assigned to the local APIC physical ID register at power - up.Some of the bits of LocalApicId represent the core within a processor and other bits represent the processor ID.See the APIC20 \"APIC ID\" register in the processor BKDG or PPR for details."  } },
        { "LogicalProcessorCount", { 1, cpuq_t::regpos_t::EBX, 16, 24, "Logical processor count. If CPUID Fn0000_0001_EDX[HTT] = 1 then LogicalProcessorCount is the number of logic processors per package. If CPUID Fn0000_0001_EDX[HTT] = 0 then LogicalProcessorCount is reserved."}},
        { "CLFlush",               { 1, cpuq_t::regpos_t::EBX, 8, 16, "CLFLUSH size. Specifies the size of a cache line in quadwords flushed by  CLFLUSH instruction.See \"CLFLUSH\" in APM3" } },
        { "8BitBrandId",           { 1, cpuq_t::regpos_t::EBX, 0, 8, "8-bit brand ID. This field, in conjunction with CPUID Fn8000_0001_EBX[BrandId], is used by the system firmware to generate the processor name string.See the appropriate processor revision guide for how to program the processor name string." } },

        { "RAZ",     { 1, cpuq_t::regpos_t::ECX, 31, 32, "RAZ. Reserved for use by the hypervisor to indicate guest status" } },
        { "RDRAND",  { 1, cpuq_t::regpos_t::ECX, 30, 31, "RDRAND instruction support." } },
        { "F16C",    { 1, cpuq_t::regpos_t::ECX, 29, 30, "Half-precision convert instruction support. See \"Half - Precision Floating - Point Conversion\" in APM1 and listings for individual F16C instructions in APM5." } },
        { "AVX",     { 1, cpuq_t::regpos_t::ECX, 28, 29, "AVX instruction support. See APM4." } },
        { "OSXSAVE", { 1, cpuq_t::regpos_t::ECX, 27, 28, "XSAVE (and related) instructions are enabled. See \"OSXSAVE\" in APM2." } },
        { "XSAVE",   { 1, cpuq_t::regpos_t::ECX, 27, 28, "XSAVE (and related) instructions are supported by hardware. See \"XSAVE/XRSTOR Instructions\" in APM2. " } },
        { "XSAVE",   { 1, cpuq_t::regpos_t::ECX, 26, 27, "XSAVE (and related) instructions are supported by hardware. See \"XSAVE/XRSTOR Instructions\" in APM2. " } },
        { "AES",     { 1, cpuq_t::regpos_t::ECX, 25, 26, "AES instruction support. See \"AES Instructions\" in APM4." } },
        { "POPCNT",  { 1, cpuq_t::regpos_t::ECX, 23, 24, "" } },
        { "MOVBE",   { 1, cpuq_t::regpos_t::ECX, 22, 23, "" } },
        { "SSE4.2",  { 1, cpuq_t::regpos_t::ECX, 20, 21, "SSE4.2 instruction support. \"Determining Media and x87 Feature Support\" in APM2 and individual SSE4.2 instruction listings in APM4. " } },
        { "SSE4.1",  { 1, cpuq_t::regpos_t::ECX, 19, 20, "SSE4.1 instruction support. See individual instruction listings in APM4." } },
        { "CMPXCHG16B", { 1, cpuq_t::regpos_t::ECX, 13, 14, "" } },
        { "FMA",     { 1, cpuq_t::regpos_t::ECX, 12, 13, "" } },
        { "SSSE3",   { 1, cpuq_t::regpos_t::ECX, 9, 10, "" } },
        { "MONITOR", { 1, cpuq_t::regpos_t::ECX, 3, 4, "MONITOR/MWAIT instructions. See MONITOR and MWAIT in APM3" } },
        { "PCLMULQDQ", { 1, cpuq_t::regpos_t::ECX, 1, 2, "" } },
        { "SSE3",    { 1, cpuq_t::regpos_t::ECX, 0, 1, "" } },

        { "HTT",     { 1, cpuq_t::regpos_t::EDX, 28, 29, "Hyper-threading technology. Indicates either that there is more than one thread per core or more than one core per compute unit" } },
        { "SSE2",    { 1, cpuq_t::regpos_t::EDX, 26, 27, "" } },
        { "SSE",     { 1, cpuq_t::regpos_t::EDX, 25, 26, "" } },
        { "FXSR",    { 1, cpuq_t::regpos_t::EDX, 24, 25, "" } },
        { "MMX",     { 1, cpuq_t::regpos_t::EDX, 23, 24, "" } },
        { "CLFSH",   { 1, cpuq_t::regpos_t::EDX, 19, 20, "CLFLUSH support" } },
        { "PSE36",   { 1, cpuq_t::regpos_t::EDX, 17, 18, "Page-size extensions. The PDE[20:13] supplies physical address [39:32]. See \"Page Translation and Protection\" in APM2." } },
        { "PAT",     { 1, cpuq_t::regpos_t::EDX, 16, 17, "Page attribute table. See \"Page-Attribute Table Mechanism\" in APM2." } },
        { "CMOV",    { 1, cpuq_t::regpos_t::EDX, 15, 16, "Conditional move instructions, CMOV, FCMOV" } },
        { "MCA",     { 1, cpuq_t::regpos_t::EDX, 14, 15, "Machine check architecture. See \"Machine Check Mechanism\" in APM2." } },
        { "PGE",     { 1, cpuq_t::regpos_t::EDX, 13, 14, "Page global extension. See \"Page Translation and Protection\" in APM2." } },
        { "MTRR",    { 1, cpuq_t::regpos_t::EDX, 12, 13, "Memory-type range registers. See \"Page Translation and Protection\" in APM2" } },
        { "SysEnterSysExit",    { 1, cpuq_t::regpos_t::EDX, 11, 12, "SYSENTER and SYSEXIT instructions. See \"SYSENTER\", \"SYSEXIT\" in APM3." } },
        { "APIC",    { 1, cpuq_t::regpos_t::EDX, 9, 10, "Advanced programmable interrupt controller. Indicates APIC exists and is enabled. See \"Exceptions and Interrupts\" in APM2." } },
        { "CMPXCH8B",{ 1, cpuq_t::regpos_t::EDX, 8, 9, "" } },
        { "MCE",     { 1, cpuq_t::regpos_t::EDX, 7, 8, "Machine check exception. See \"Machine Check Mechanism\" in APM2" } },
        { "PAE",     { 1, cpuq_t::regpos_t::EDX, 6, 7, "Physical-address extensions. Indicates support for physical addresses 32b. Number of physical address bits above 32b is implementation specific.See \"Page Translation and Protection\" in APM2." } },
        { "MSR",     { 1, cpuq_t::regpos_t::EDX, 5, 6, "AMD model-specific registers. Indicates support for AMD model-specific registers (MSRs), with RDMSRand WRMSR instructions.See \"Model Specific Registers\" in APM2." } },
        { "TSC",     { 1, cpuq_t::regpos_t::EDX, 4, 5, "Time stamp counter. RDTSC and RDTSCP instruction support. See \"Debug and Performance Resources\" in APM2." } },
        { "PSE",     { 1, cpuq_t::regpos_t::EDX, 3, 4, "Page-size extensions. See \"Page Translation and Protection\" in APM2" } },
        { "DE",      { 1, cpuq_t::regpos_t::EDX, 2, 3, "Debugging extensions. See \"Debug and Performance Resources\" in APM2." } },
        { "VME",     { 1, cpuq_t::regpos_t::EDX, 1, 2, "Virtual-mode enhancements. CR4.VME, CR4.PVI, software interrupt indirection, expansion of the TSS with the software, indirection bitmap, EFLAGS.VIF, EFLAGS.VIP. See \"System Resources\" in APM2." } },
        { "FPU",     { 1, cpuq_t::regpos_t::EDX, 0, 1, "x87 floating point unit on-chip." } },



        { "MonLineSizeMin", { 5, cpuq_t::regpos_t::EAX, 0, 16, "Smallest monitor-line size in bytes"} },
        { "MonLineSizeMax", { 5, cpuq_t::regpos_t::EBX, 0, 16, "Largest monitor-line size in bytes"} },
        { "IBE", { 5, cpuq_t::regpos_t::ECX, 1, 2, "Interrupt break-event. Indicates MWAIT can use ECX bit 0 to allow interrupts to cause an exit from the monitor event pending state, even if EFLAGS.IF = 0. "} },
        { "EMX", { 5, cpuq_t::regpos_t::ECX, 0, 1, "Enumerate MONITOR/MWAIT extensions: Indicates enumeration MONITOR / MWAIT extensions are supported. "} },


        { "ARAT",    { 6, cpuq_t::regpos_t::EAX, 2, 3, "If set, indicates that the timebase for the local APIC timer is not affected by processor p-state." }},
        { "EffFreq", { 6, cpuq_t::regpos_t::ECX, 0, 1, "Effective frequency interface support. If set, indicates presence of MSR0000_00E7 (MPERF) and MSR0000_00E8(APERF)." }},


        { "MaxSubFn",  { 7, cpuq_t::regpos_t::EAX, 0,  32, "Returns the number of subfunctions supported" }},
        { "SHA",       { 7, cpuq_t::regpos_t::EBX, 29, 30, "SHA instruction extension" }},
        { "CLWB",      { 7, cpuq_t::regpos_t::EBX, 24, 25, "" }},
        { "CLFLUSHOPT",{ 7, cpuq_t::regpos_t::EBX, 23, 24, "" }},
        { "RDPID",     { 7, cpuq_t::regpos_t::EBX, 22, 23, "RDPID instruction and TSC_AUX MSR support." }},
        { "SMAP",      { 7, cpuq_t::regpos_t::EBX, 20, 21, "Supervisor mode access prevention" }},
        { "ADX",       { 7, cpuq_t::regpos_t::EBX, 19, 20, "ADCX, ADOX instruction support." }},
        { "RDSEED",    { 7, cpuq_t::regpos_t::EBX, 18, 19, "" }},
        { "BMI2",      { 7, cpuq_t::regpos_t::EBX, 8, 9,   "Bit manipulation group 2 support" }},
        { "SMEP",      { 7, cpuq_t::regpos_t::EBX, 7, 8,   "Supervisor mode execution prevention" }},
        { "AVX2",      { 7, cpuq_t::regpos_t::EBX, 5, 6,   "" }},
        { "BMI1",      { 7, cpuq_t::regpos_t::EBX, 3, 4,   "Bit manipulation group 1 support" }},
        { "UMIP",      { 7, cpuq_t::regpos_t::EBX, 2, 3,   "User mode instruction prevention support" }},
        { "FSGSBASE",  { 7, cpuq_t::regpos_t::EBX, 0, 1,   "FS and GS base read/write instruction support" }},

        { "VPCMULQDQ", { 7, cpuq_t::regpos_t::ECX, 10, 11, "" }},
        { "VAES",      { 7, cpuq_t::regpos_t::ECX, 9, 10, "" }},
        { "OSPKE",     { 7, cpuq_t::regpos_t::ECX, 4, 5, "OS has enabled Memory Protection Keys and use of the RDPKRU/WRPKRU instructions by setting CR4.PKE = 1. " }},
        { "PKU",       { 7, cpuq_t::regpos_t::ECX, 3, 4, "Memory protection keys supported" }},



        { "XFeatureSupportedMask_low",  { 0xD, cpuq_t::regpos_t::EAX, 0, 32, "Reports the valid bit positions for the lower 32 bits of the XFeatureEnabledMask register.If a bit is set, the corresponding feature is supported.See \"XSAVE / XRSTOR Instructions\" in APM2." }},
        { "XFeatureEnabledSizeMax",     { 0xD, cpuq_t::regpos_t::EBX, 0, 32, "Size in bytes of XSAVE/XRSTOR area for the currently enabled features in XCR0. " }},
        { "XFeatureSupportedSizeMax",   { 0xD, cpuq_t::regpos_t::ECX, 0, 32, "Size in bytes of XSAVE/XRSTOR area for all features that the logical processor supports.See XFeatureEnabledSizeMax. " }},
        { "XFeatureSupportedMask_high", { 0xD, cpuq_t::regpos_t::EDX, 0, 32, "Reports the valid bit positions for the upper 32 bits of the XFeatureEnabledMask register.If a bit is set, the corresponding feature is supported." }},


        { "XSAVEOPT",         { 0xD, cpuq_t::regpos_t::EAX, 0, 1, "" , 1} },
        { "YmmSaveStateSize",   { 0xD, cpuq_t::regpos_t::EAX, 0, 32, " YMM state save size. The state save area size in bytes for The YMM registers.", 2} },
        { "YmmSaveStateOffset", { 0xD, cpuq_t::regpos_t::EBX, 0, 32, " YMM state save offset. The offset in bytes from the base of the extended state save area of the YMM register state save area.", 2} },
        { "LwpSaveStateSize",   { 0xD, cpuq_t::regpos_t::EBX, 0, 32, " LWP state save area size. The size of the save area for LWP state in bytes. See \"Lightweight Profiling\" in APM2.", 3} },
        { "LwpSaveStateOffset", { 0xD, cpuq_t::regpos_t::EBX, 0, 32, " LWP state save byte offset. The offset in bytes from the base of the extended state save area of the state save area for LWP.See \"Lightweight Profiling\" in APM2", 3} },



        { "PkgType", { 0x80000001, cpuq_t::regpos_t::EBX, 28, 32, "Package type. If (Family[7:0] >= 10h), this field is valid. If (Family[7:0]<10h), this field is reserved. " } },
        { "BrandId", { 0x80000001, cpuq_t::regpos_t::EBX, 0,  16, "Brand ID. This field, in conjunction with CPUID Fn0000_0001_EBX[8BitBrandId], is used by system firmware to generate the processor name string.See your processor revision guide for how to program the processor name string. " }  },




        { "PerfTsc",                 { 0x80000001, cpuq_t::regpos_t::ECX, 27, 28, "Performance time-stamp counter. Indicates support for MSRC001_0280 [Performance Time Stamp Counter]. " } },
        { "DataBreakpointExtension", { 0x80000001, cpuq_t::regpos_t::ECX, 26, 27, "Data access breakpoint extension. Indicates support for MSRC001_1027 and MSRC001_101[B:9]." } },
        { "PerfCtrExtNB",            { 0x80000001, cpuq_t::regpos_t::ECX, 24, 25, "NB performance counter extensions support. Indicates support for MSRC001_024[6,4,2,0] and MSRC001_024[7,5,3,1]. " } },
        { "PerfCtrExtCore",          { 0x80000001, cpuq_t::regpos_t::ECX, 23, 24, "Processor performance counter extensions support. Indicates support for MSRC001_020[A,8,6,4,2,0] and MSRC001_020[B,9,7,5,3,1]. " } },
        { "TopologyExtension",       { 0x80000001, cpuq_t::regpos_t::ECX, 22, 23, "Topology extensions support. Indicates support for CPUID Fn8000_001D_EAX_x[N:0] - CPUID Fn8000_001E_EDX. " } },
        { "TBM",                     { 0x80000001, cpuq_t::regpos_t::ECX, 21, 22, "Trailing bit manipulation instruction support.  " } },
        { "FMA4",                    { 0x80000001, cpuq_t::regpos_t::ECX, 16, 17, "" } },
        { "LWP",                     { 0x80000001, cpuq_t::regpos_t::ECX, 15, 16, "Lightweight profiling support. See \"Lightweight Profiling\" in APM2 and reference pages for individual LWP instructions in APM3. " } },
        { "WDT",                     { 0x80000001, cpuq_t::regpos_t::ECX, 13, 14, "Watchdog timer support. See APM2 and APM3. Indicates support for MSRC001_0074.  " } },
        { "SKINIT",                  { 0x80000001, cpuq_t::regpos_t::ECX, 12, 13, "SKINIT and STGI are supported. Indicates support for SKINIT and STGI, independent of the value of MSRC000_0080[SVME].See APM2 and APM3. " } },
        { "XOP",                     { 0x80000001, cpuq_t::regpos_t::ECX, 11, 12, "Extended operation support." } },
        { "IBS",                     { 0x80000001, cpuq_t::regpos_t::ECX, 10, 11, "Instruction based sampling." } },
        { "OSVW",                    { 0x80000001, cpuq_t::regpos_t::ECX, 9,  10, "OS visible workaround. Indicates OS-visible workaround support. See \"OS Visible Work - around(OSVW) Information\" in APM2." } },
        { "3DNowPrefetch",           { 0x80000001, cpuq_t::regpos_t::ECX, 8,  9,  "PREFETCH and PREFETCHW instruction support. See \"PREFETCH\" and \"PREFETCHW\" in APM3. " } },
        { "MisAlignSse",             { 0x80000001, cpuq_t::regpos_t::ECX, 7,  8,  "Misaligned SSE mode. See \"Misaligned Access Support Added for SSE Instructions\" in APM1. " } },
        { "SSE4A",                   { 0x80000001, cpuq_t::regpos_t::ECX, 6, 7,  "EXTRQ, INSERTQ, MOVNTSS, and MOVNTSD instruction support. See \"EXTRQ\", \"INSERTQ\", \"MOVNTSS\",and \"MOVNTSD\" in APM4. " } },
        { "ABM",                     { 0x80000001, cpuq_t::regpos_t::ECX, 5, 6,  "Advanced bit manipulation. LZCNT instruction support. See \"LZCNT\" in APM3. " } },
        { "AltMovCr8",               { 0x80000001, cpuq_t::regpos_t::ECX, 4, 5,  "LOCK MOV CR0 means MOV CR8. See \"MOV(CRn)\" in APM3. " } },
        { "ExtApicSpace",            { 0x80000001, cpuq_t::regpos_t::ECX, 3, 4,  "Extended APIC space. This bit indicates the presence of extended APIC register space starting at offset 400h from the \"APIC Base Address Register,\" as specified in the BKDG. " } },
        { "SVM",                     { 0x80000001, cpuq_t::regpos_t::ECX, 2, 3,  "Secure virtual machine. See \"Secure Virtual Machine\" in APM2.  " } },
        { "CmpLegacy",               { 0x80000001, cpuq_t::regpos_t::ECX, 1, 2,  "Core multi-processing legacy mode. See \"Legacy Method\" on page 603." } },
        { "LahfSahf",                { 0x80000001, cpuq_t::regpos_t::ECX, 0, 1,  "LAHF and SAHF instruction support in 64-bit mode. See \"LAHF\" and \"SAHF\" in APM3. " } },



        { "3DNow",     { 0x80000001, cpuq_t::regpos_t::EDX, 31, 32, "3DNow! instructions. See Appendix D \"Instruction Subsets and CPUID Feature Sets\" in APM3." } },
        { "3DNowExt",  { 0x80000001, cpuq_t::regpos_t::EDX, 30, 31, "AMD extensions to 3DNow! instructions. See Appendix D \"Instruction Subsets and CPUID Feature Sets\" in APM3." } },
        { "LM",        { 0x80000001, cpuq_t::regpos_t::EDX, 29, 30, "Long mode. See \"Processor Initialization and Long-Mode Activation\" in APM2. " } },
        { "RDTSCP",    { 0x80000001, cpuq_t::regpos_t::EDX, 27, 28, "" } },
        { "Page1GB",   { 0x80000001, cpuq_t::regpos_t::EDX, 26, 27, "1-GB large page support. See \"1-GB Paging Support\" in APM2. " } },
        { "FFXSR",     { 0x80000001, cpuq_t::regpos_t::EDX, 25, 26, "FXSAVE and FXRSTOR instruction optimizations. See \"FXSAVE\" and \"FXRSTOR\" in APM5. " } },
        { "MmxExt",    { 0x80000001, cpuq_t::regpos_t::EDX, 22, 23, "AMD extensions to MMX instructions. See Appendix D \"Instruction Subsets and CPUID Feature Sets\" in APM3 and \"128 - Bit Media and Scientific Programming\" in APM1." } },
        { "NX",        { 0x80000001, cpuq_t::regpos_t::EDX, 20, 21, "No-execute page protection.  See \"Page Translation and Protection\" in APM2." } },
        { "SysCallSysRet", { 0x80000001, cpuq_t::regpos_t::EDX, 11, 12, "SYSCALL and SYSRET instructions. See \"SYSCALL\" and \"SYSRET\" in APM3. " } },


        { "ProcName0",  { 0x80000002, cpuq_t::regpos_t::EAX, 0, 32 } },
        { "ProcName4",  { 0x80000002, cpuq_t::regpos_t::EBX, 0, 32 } },
        { "ProcName8",  { 0x80000002, cpuq_t::regpos_t::ECX, 0, 32 } },
        { "ProcName12", { 0x80000002, cpuq_t::regpos_t::EDX, 0, 32 } },
        { "ProcName16", { 0x80000003, cpuq_t::regpos_t::EAX, 0, 32 } },
        { "ProcName20", { 0x80000003, cpuq_t::regpos_t::EBX, 0, 32 } },
        { "ProcName24", { 0x80000003, cpuq_t::regpos_t::ECX, 0, 32 } },
        { "ProcName28", { 0x80000003, cpuq_t::regpos_t::EDX, 0, 32 } },
        { "ProcName32", { 0x80000004, cpuq_t::regpos_t::EAX, 0, 32 } },
        { "ProcName36", { 0x80000004, cpuq_t::regpos_t::EBX, 0, 32 } },
        { "ProcName40", { 0x80000004, cpuq_t::regpos_t::ECX, 0, 32 } },
        { "ProcName44", { 0x80000004, cpuq_t::regpos_t::EDX, 0, 32 } },

        // L1 cache and TLB
        { "L1DTlb2and4MAssoc", { 0x80000005, cpuq_t::regpos_t::EAX, 24, 32, "Data TLB associativity for 2-MB and 4-MB pages. Encoding is per Table E-3 below." } },
        { "L1DTlb2and4MSize",  { 0x80000005, cpuq_t::regpos_t::EAX, 16, 24, "Data TLB number of entries for 2-MB and 4-MB pages. The value returned is for the number of entries available for the 2 - MB page size; 4 - MB pages require two 2 - MB entries, so the number of entries available for the 4 - MB page size is onehalf the returned value." } },
        { "L1ITlb2and4MAssoc", { 0x80000005, cpuq_t::regpos_t::EAX, 8,  16, "Instruction TLB associativity for 2-MB and 4-MB pages. Encoding is per Table E - 3 below" } },
        { "L1ITlb2and4MSize",  { 0x80000005, cpuq_t::regpos_t::EAX, 0,   8, "Instruction TLB number of entries for 2-MB and 4-MB pages. The value returned is for the number of entries available for the 2 - MB page size; 4 - MB pages require two 2 - MB entries, so the number of entries available for the 4 - MB page size is one - half the returned value." } },

        { "L1ITlb2and4MSize",  { 0x80000005, cpuq_t::regpos_t::EBX, 24, 32, "Data TLB associativity for 4 KB pages. Encoding is per Table E-3 above" } },
        { "L1DTlb4KSize",      { 0x80000005, cpuq_t::regpos_t::EBX, 16, 24, "Data TLB number of entries for 4 KB pages." } },
        { "L1ITlb4KAssoc",     { 0x80000005, cpuq_t::regpos_t::EBX, 8,  16, "Instruction TLB associativity for 4 KB pages. Encoding is per Table E-3 above." } },
        { "L1ITlb4KSize",      { 0x80000005, cpuq_t::regpos_t::EBX, 0,   8, "Instruction TLB number of entries for 4 KB pages." } },

        { "L1DcSize",        { 0x80000005, cpuq_t::regpos_t::ECX, 24, 32, "L1 data cache size in KB." } },
        { "L1DcAssoc",       { 0x80000005, cpuq_t::regpos_t::ECX, 16, 24, "L1 data cache associativity. Encoding is per Table E-3." } },
        { "L1DcLinesPerTag", { 0x80000005, cpuq_t::regpos_t::ECX, 8,  16, "L1 data cache lines per tag." } },
        { "L1DcLineSize",    { 0x80000005, cpuq_t::regpos_t::ECX, 0,   8, "L1 data cache line size in bytes." } },

        { "L1IcSize",        { 0x80000005, cpuq_t::regpos_t::EDX, 24, 32, "L1 instruction cache size in KB." } },
        { "L1IcAssoc",       { 0x80000005, cpuq_t::regpos_t::EDX, 16, 24, "L1 instruction cache associativity. Encoding is per Table E-3." } },
        { "L1IcLinesPerTag", { 0x80000005, cpuq_t::regpos_t::EDX, 8,  16, "L1 instruction cache lines per tag." } },
        { "L1IcLineSize",    { 0x80000005, cpuq_t::regpos_t::EDX, 0,   8, "L1 instruction cache line size in bytes." } },




        // L2, 3 cache and TLB

        { "L2DTlb2and4MAssoc", { 0x80000006, cpuq_t::regpos_t::EAX, 28, 32, "L2 data TLB associativity for 2-MB and 4-MB pages. Encoding is per Table E - 4 below." } },
        { "L2DTlb2and4MSize",  { 0x80000006, cpuq_t::regpos_t::EAX, 16, 28, "L2 data TLB number of entries for 2-MB and 4-MB pages. The value returned is for the number of entries available for the 2 MB page size; 4 MB pages require two 2 MB entries, so the number of entries available for the 4 MB page size is one - half the returned value" } },
        { "L2ITlb2and4MAssoc", { 0x80000006, cpuq_t::regpos_t::EAX, 12, 16, "L2 instruction TLB associativity for 2-MB and 4-MB pages. Encoding is per Table E - 4 below" } },
        { "L2ITlb2and4MSize",  { 0x80000006, cpuq_t::regpos_t::EAX, 0,  12, "L2 instruction TLB number of entries for 2-MB and 4-MB pages. The value returned is for the number of entries available for the 2 MB page size; 4 MB pages require two 2 MB entries, so the number of entries available for the 4 MB page size is one - half the returned value." } },


        { "L2DTlb4KAssoc", { 0x80000006, cpuq_t::regpos_t::EBX, 28, 32, "L2 data TLB associativity for 4-KB pages. Encoding is per Table E-4 above." } },
        { "L2DTlb4KSize",  { 0x80000006, cpuq_t::regpos_t::EBX, 16, 28, "L2 data TLB number of entries for 4-KB pages." } },
        { "L2ITlb4KAssoc", { 0x80000006, cpuq_t::regpos_t::EBX, 12, 16, "L2 instruction TLB associativity for 4-KB pages. Encoding is per Table E-4 above" } },
        { "L2ITlb4KSize",  { 0x80000006, cpuq_t::regpos_t::EBX, 0,  12, "L2 instruction TLB number of entries for 4-KB pages." } },


        { "L2Size",        { 0x80000006, cpuq_t::regpos_t::ECX, 16, 32, "L2 data cache size in KB." } },
        { "L2Assoc",       { 0x80000006, cpuq_t::regpos_t::ECX, 12, 16, "L2 data cache associativity. Encoding is per Table E-3." } },
        { "L2LinesPerTag", { 0x80000006, cpuq_t::regpos_t::ECX, 8,  12, "L2 data cache lines per tag." } },
        { "L2LineSize",    { 0x80000006, cpuq_t::regpos_t::ECX, 0,   8, "L2 data cache line size in bytes." } },


        { "L3Size",        { 0x80000006, cpuq_t::regpos_t::ECX, 18, 32, "Specifies the L3 cache size range: (L3Size[31:18] * 512KB) <= L3 cache size < ((L3Size[31:18] + 1) * 512KB). " } },
        { "L3Assoc",       { 0x80000006, cpuq_t::regpos_t::ECX, 12, 16, "L3 cache associativity. Encoded per Table E-4 on page 588." } },
        { "L3LinesPerTag", { 0x80000006, cpuq_t::regpos_t::ECX, 8,  12, "L3 cache lines per tag." } },
        { "L3LineSize",    { 0x80000006, cpuq_t::regpos_t::ECX, 0,   8, "L3 cache line size in bytes." } },



        // power management
        { "HWA",              { 0x80000007, cpuq_t::regpos_t::EBX, 2, 3, "Hardware assert supported. Indicates support for MSRC001_10[DF:C0]." } },
        { "SUCCOR",           { 0x80000007, cpuq_t::regpos_t::EBX, 1, 2, "Software uncorrectable error containment and recovery capability. The processor supports software containment of uncorrectable errors through context synchronizing data poisoning and deferred error interrupts; see APM2, Chapter 9, \"Determining Machine - Check Architecture Support.\"" } },
        { "McaOverflowRecov", { 0x80000007, cpuq_t::regpos_t::EBX, 0, 1, "MCA overflow recovery support. If set, indicates that MCA overflow conditions (MCi_STATUS[Overflow] = 1) are not fatal; software may safely ignore such conditions.If clear, MCA overflow conditions require software to shut down the system.See APM2, Chapter 9, \"Handling Machine Check Exceptions.\" " } },

        { "CpuPwrSampleTimeRatio", { 0x80000007, cpuq_t::regpos_t::ECX, 0, 32, "Specifies the ratio of the compute unit power accumulator sample period to the TSC counter period.Returns a value of 0 if not applicable for the system. " } },


        { "ProcPowerReporting", { 0x80000007, cpuq_t::regpos_t::EDX, 12, 13, "Processor power reporting interface supported. " } },
        { "EffFreqRO",          { 0x80000007, cpuq_t::regpos_t::EDX, 10, 11, "Read-only effective frequency interface. 1=Indicates presence of MSRC000_00E7[Read - Only Max Performance Frequency Clock Count (MPerfReadOnly)] and MSRC000_00E8[Read - Only Actual Performance Frequency Clock Count(APerfReadOnly)].  " } },
        { "CPB",                { 0x80000007, cpuq_t::regpos_t::EDX, 9,  10, "Core performance boost" } },
        { "TscInvariant",       { 0x80000007, cpuq_t::regpos_t::EDX, 8,   9, "TSC invariant. The TSC rate is ensured to be invariant across all P-States, CStates, and stop grant transitions (such as STPCLK Throttling); therefore the TSC is suitable for use as a source of time. 0 = No such guarantee is made and software should avoid attempting to use the TSC as a source of time. " } },
        { "HwPstate",           { 0x80000007, cpuq_t::regpos_t::EDX, 7,   8, "Hardware P-state control. MSRC001_0061 [P-state Current Limit], MSRC001_0062[P - state Control] and MSRC001_0063[P - state Status] exist. " } },
        { "100MHzSteps",        { 0x80000007, cpuq_t::regpos_t::EDX, 6,   7, "100 MHz multiplier Control. " } },
        { "TM",                 { 0x80000007, cpuq_t::regpos_t::EDX, 4, 5, "Hardware thermal control (HTC)." } },
        { "TTP",                { 0x80000007, cpuq_t::regpos_t::EDX, 3, 4, "THERMTRIP" } },
        { "VID",                { 0x80000007, cpuq_t::regpos_t::EDX, 2, 3, "Voltage ID control. Function replaced by HwPstate." } },
        { "FID",                { 0x80000007, cpuq_t::regpos_t::EDX, 1, 2, "Frequency ID control. Function replaced by HwPstate." } },
        { "TS",                 { 0x80000007, cpuq_t::regpos_t::EDX, 0, 1, "Temperature sensor" } },


        // proc capacity parameters
        { "GuestPhysAddrSize", { 0x80000008, cpuq_t::regpos_t::EAX, 16, 24, "Maximum guest physical address size in bits. This number applies only to guests using nested paging.When this field is zero, refer to the PhysAddrSize field for the maximum guest physical address size.See \"Secure Virtual Machine\" in APM2." } },
        { "LinAddrSize",       { 0x80000008, cpuq_t::regpos_t::EAX, 8,  16, "Maximum linear address size in bits. " } },
        { "LinAddrSize",       { 0x80000008, cpuq_t::regpos_t::EAX, 0,   7, "Maximum physical address size in bits. When GuestPhysAddrSize is zero, this field also indicates the maximum guest physical address size. " } },

        { "CLZERO",        { 0x80000008, cpuq_t::regpos_t::EBX, 0, 1, "CLZERO instruction supported" } },
        { "InstRetCntMsr", { 0x80000008, cpuq_t::regpos_t::EBX, 1, 2, "Instruction Retired Counter MSR available" } },
        { "RstrFpErrPtrs", { 0x80000008, cpuq_t::regpos_t::EBX, 2, 3, "FP Error Pointers Restored by XRSTOR" } },
        { "RDPRU",         { 0x80000008, cpuq_t::regpos_t::EBX, 4, 5, "" } },
        { "MCOMMIT",       { 0x80000008, cpuq_t::regpos_t::EBX, 8, 9, "" } },
        { "WBNOINVD",      { 0x80000008, cpuq_t::regpos_t::EBX, 9, 10, "" } },



        { "PerfTscSize",   { 0x80000008, cpuq_t::regpos_t::ECX, 16, 17, R"(
Performance time-stamp counter size. Indicates the size of
MSRC001_0280[PTSC].
Bits Description
00b  40 bits
01b  48 bits
10b  56 bits
11b  64 bits
)" } },
        { "ApicIdSize",      { 0x80000008, cpuq_t::regpos_t::ECX, 12, 15, R"(
APIC ID size. The number of bits in the initial APIC20[ApicId] value that indicate
logical processor ID within a package. The size of this field determines the
maximum number of logical processors (MNLP) that the package could
theoretically support, and not the actual number of logical processors that are
implemented or enabled in the package, as indicated by CPUID
Fn8000_0008_ECX[NC]. A value of zero indicates that legacy methods must be
used to determine the maximum number of logical processors, as indicated by
CPUID Fn8000_0008_ECX[NC].
if (ApicIdSize[3:0] == 0) {
// Used by legacy dual-core/single-core processors
MNLP = CPUID Fn8000_0008_ECX[NC] + 1;
} else {
// use ApicIdSize[3:0] field
MNLP = (2 ^ raised to the power of ApicIdSize[3:0]);
}
)" } },


        { "NC",         { 0x80000008, cpuq_t::regpos_t::ECX, 0, 8, "Number of physical cores - 1. The number of cores in the processor is NC+1 " } },

        { "MaxRdpruID", { 0x80000008, cpuq_t::regpos_t::EDX, 16, 32, "The maximum ECX value recognized by RDPRU" } },



        // 1gb tlb
        { "L1DTlb1GAssoc", { 0x80000019, cpuq_t::regpos_t::EAX, 28, 32, "L1 data TLB associativity for 1 GB pages. See Table E-4 on page 588." } },
        { "L1DTlb1GAssoc", { 0x80000019, cpuq_t::regpos_t::EAX, 16, 28, "L1 data TLB number of entries for 1 GB pages." } },
        { "L1DTlb1GAssoc", { 0x80000019, cpuq_t::regpos_t::EAX, 12, 16, "L1 instruction TLB associativity for 1 GB pages. See Table E-4 on page 588." } },
        { "L1DTlb1GAssoc", { 0x80000019, cpuq_t::regpos_t::EAX, 0,  12, "L1 instruction TLB number of entries for 1 GB pages. " } },

        { "L2DTlb1GAssoc", { 0x80000019, cpuq_t::regpos_t::EBX, 28, 32, "L2 data TLB associativity for 1 GB pages. See Table E-4 on page 588." } },
        { "L2DTlb1GAssoc", { 0x80000019, cpuq_t::regpos_t::EBX, 16, 28, "L2 data TLB number of entries for 1 GB pages." } },
        { "L2DTlb1GAssoc", { 0x80000019, cpuq_t::regpos_t::EBX, 12, 16, "L2 instruction TLB associativity for 1 GB pages. See Table E-4 on page 588." } },
        { "L2DTlb1GAssoc", { 0x80000019, cpuq_t::regpos_t::EBX, 0,  12, "L2 instruction TLB number of entries for 1 GB pages. " } },

        // optimizations
        { "FP256", { 0x8000001A, cpuq_t::regpos_t::EAX, 2, 3, "256-bit AVX instructions are executed with full-width internal operations and pipelines rather than decomposing them into internal 128 - bit suboperations.This may impact how software performs instruction selection and scheduling. " } },
        { "MOVU",  { 0x8000001A, cpuq_t::regpos_t::EAX, 1, 2, "MOVU SSE nstructions are more efficient and should be preferred to SSE MOVL / MOVH. MOVUPS is more efficient than MOVLPS / MOVHPS. MOVUPD is more efficient than MOVLPD / MOVHPD." } },
        { "FP128", { 0x8000001A, cpuq_t::regpos_t::EAX, 0, 1, "128-bit SSE (multimedia) instructions are executed with full-width internal operations and pipelines rather than decomposing them into internal 64 - bit suboperations.This may impact how software performs instruction selection and scheduling." } },


        // sampling capabilities
        { "OpBrnFuse",     { 0x8000001B, cpuq_t::regpos_t::EAX, 8, 9, "Fused branch micro-op indication supported." } },
        { "RipInvalidChk", { 0x8000001B, cpuq_t::regpos_t::EAX, 7, 8, "Invalid RIP indication supported. " } },
        { "OpCntExt",      { 0x8000001B, cpuq_t::regpos_t::EAX, 6, 7, "IbsOpCurCnt and IbsOpMaxCnt extend by 7 bits. " } },
        { "BrnTrgt",       { 0x8000001B, cpuq_t::regpos_t::EAX, 5, 6, "Branch target address reporting supported. " } },
        { "OpCnt",         { 0x8000001B, cpuq_t::regpos_t::EAX, 4, 5, "Op counting mode supported. " } },
        { "RdWrOpCnt",     { 0x8000001B, cpuq_t::regpos_t::EAX, 3, 4, "Read write of op counter supported. " } },
        { "OpSam",         { 0x8000001B, cpuq_t::regpos_t::EAX, 2, 3, "IBS execution sampling supported. " } },
        { "FetchSam",      { 0x8000001B, cpuq_t::regpos_t::EAX, 1, 2, "IBS fetch sampling supported. " } },
        { "IBSFFV",        { 0x8000001B, cpuq_t::regpos_t::EAX, 0, 1, "IBS feature flags valid. " } },

        // lwp caps
        { "LwpInt",   { 0x8000001C, cpuq_t::regpos_t::EAX, 31, 32, "Interrupt on threshold overflow available." } },
        { "LwpPTSC",  { 0x8000001C, cpuq_t::regpos_t::EAX, 30, 31, "Performance time stamp counter in event record is available. " } },
        { "LwpCont",  { 0x8000001C, cpuq_t::regpos_t::EAX, 29, 30, "Sampling in continuous mode is available." } },
        { "LwpRNH",   { 0x8000001C, cpuq_t::regpos_t::EAX, 6, 7,   "Core reference clocks not halted event available." } },
        { "LwpCNH",   { 0x8000001C, cpuq_t::regpos_t::EAX, 5, 6,   "Core clocks not halted event available." } },
        { "LwpDME",   { 0x8000001C, cpuq_t::regpos_t::EAX, 4, 5,   "DC miss event available" } },
        { "LwpBRE",   { 0x8000001C, cpuq_t::regpos_t::EAX, 3, 4,   "Branch retired event available" } },
        { "LwpIRE",   { 0x8000001C, cpuq_t::regpos_t::EAX, 2, 3,   "Instructions retired event available." } },
        { "LwpVAL",   { 0x8000001C, cpuq_t::regpos_t::EAX, 1, 2,   "LWPVAL instruction available" } },
        { "LwpAvail", { 0x8000001C, cpuq_t::regpos_t::EAX, 0, 1,   "The LWP feature is available." } },

        { "LwpEventOffset", { 0x8000001C, cpuq_t::regpos_t::EBX, 24, 32, "Offset in bytes from the start of the LWPCB to the EventInterval1 field." } },
        { "LwpMaxEvents",   { 0x8000001C, cpuq_t::regpos_t::EBX, 16, 24, "Maximum EventId value supported." } },
        { "LwpEventSize",   { 0x8000001C, cpuq_t::regpos_t::EBX, 8,  16, "Event record size. Size in bytes of an event record in the LWP event ring buffer." } },
        { "LwpCbSize",      { 0x8000001C, cpuq_t::regpos_t::EBX, 0,   8, "Control block size. Size in quadwords of the LWPCB." } },

        { "LwpCacheLatency",     { 0x8000001C, cpuq_t::regpos_t::ECX, 31, 32, "Control block size. Size in quadwords of the LWPCB." } },
        { "LwpCacheLevels",      { 0x8000001C, cpuq_t::regpos_t::ECX, 30, 31, "Control block size. Size in quadwords of the LWPCB." } },
        { "LwpIpFiltering",      { 0x8000001C, cpuq_t::regpos_t::ECX, 29, 30, "Control block size. Size in quadwords of the LWPCB." } },
        { "LwpBranchPrediction", { 0x8000001C, cpuq_t::regpos_t::ECX, 28, 29, "Control block size. Size in quadwords of the LWPCB." } },
        { "LwpMinBufferSize",    { 0x8000001C, cpuq_t::regpos_t::ECX, 16, 24, "Control block size. Size in quadwords of the LWPCB." } },
        { "LwpVersion",          { 0x8000001C, cpuq_t::regpos_t::ECX, 9,  16, "Control block size. Size in quadwords of the LWPCB." } },
        { "LwpLatencyRnd",       { 0x8000001C, cpuq_t::regpos_t::ECX, 6,   9, "Control block size. Size in quadwords of the LWPCB." } },
        { "LwpDataAddress",      { 0x8000001C, cpuq_t::regpos_t::ECX, 5,   6, "Control block size. Size in quadwords of the LWPCB." } },
        { "LwpLatencyMax",       { 0x8000001C, cpuq_t::regpos_t::ECX, 0,   5, "Control block size. Size in quadwords of the LWPCB." } },



        // cache properties
        { "NumSharingCache",    { 0x8000001D, cpuq_t::regpos_t::EAX, 14, 26, R"(
Specifies the number of logical processors sharing the cache enumerated by N,
the value passed to the instruction in ECX. The number of logical processors
sharing this cache is the value of this field incremented by 1. To determine which
logical processors are sharing a cache, determine a Share Id for each processor
as follows:
ShareId = LocalApicId >> log2(NumSharingCache+1)
Logical processors with the same ShareId then share a cache. If
NumSharingCache+1 is not a power of two, round it up to the next power of two.
)" } },
        { "FullyAssociative",   { 0x8000001D, cpuq_t::regpos_t::EAX,  9, 10, "Fully associative cache. When set, indicates that the cache is fully associative. If 0 is returned in this field, the cache is set associative." } },
        { "SelfInitialization", { 0x8000001D, cpuq_t::regpos_t::EAX,  8,  9, "Self-initializing cache. When set, indicates that the cache is self initializing; software initialization not required.If 0 is returned in this field, hardware does not initialize this cache." } },
        { "CacheLevel",         { 0x8000001D, cpuq_t::regpos_t::EAX,  5,  8, R"(
Cache level. Identifies the level of this cache. Note that the enumeration value is
not necessarily equal to the cache level.
Bits Description
000b Reserved.
001b Level 1
010b Level 2
011b Level 3
111b-100b Reserved.
)" } },
        { "CacheType",          { 0x8000001D, cpuq_t::regpos_t::EAX,  0,  5, R"(
Cache type. Identifies the type of cache.
Bits Description
00h Null; no more caches.
01h Data cache
02h Instruction cache
03h Unified cache
1Fh-04h Reserved.
)" } },


        { "CacheNumWays",        { 0x8000001D, cpuq_t::regpos_t::EBX, 22, 32, "Number of ways for this cache. The number of ways is the value returned in this field incremented by 1." } },
        { "CachePhysPartitions", { 0x8000001D, cpuq_t::regpos_t::EBX, 12, 22, "Number of physical line partitions. The number of physical line partitions is the value returned in this field incremented by 1." } },
        { "CacheLineSize",       { 0x8000001D, cpuq_t::regpos_t::EBX,  0, 12, "Cache line size. The cache line size in bytes is the value returned in this field incremented by 1." } },

        { "CacheNumSets",        { 0x8000001D, cpuq_t::regpos_t::ECX,  0, 32, "Number of ways for set associative cache. Number of ways is the value returned in this field incremented by 1. Only valid for caches that are not fully associative (Fn8000_001D_EAX_xn[FullyAssociative] = 0). " } },

        { "CacheInclusive",      { 0x8000001D, cpuq_t::regpos_t::EDX,  1, 2, "Cache inclusivity. A value of 0 indicates that this cache is not inclusive of lower cache levels. A value of 1 indicates that the cache is inclusive of lower cache levels." } },
        { "WBINVD",              { 0x8000001D, cpuq_t::regpos_t::EDX,  0, 1, "Write-Back Invalidate/Invalidate execution scope. A value of 0 returned in this field indicates that the WBINVD / INVD instruction invalidates all lower level caches of non - originating logical processors sharing this cache.When set, this field indicates that the WBINVD / INVD instruction is not guaranteed to invalidate all lower level caches of non - originating logical processors sharing this cache. " } },



        { "ExtendedApicID",  { 0x8000001E, cpuq_t::regpos_t::EAX,  0, 32, "Extended APIC ID. If MSR0000_001B[ApicEn] = 0, this field is reserved.." } },

        { "ThreadsPerComputeUnit", { 0x8000001E, cpuq_t::regpos_t::EBX,  8, 16, R"(
Threads per compute unit (zero-based count). The actual number of threads
per compute unit is the value of this field + 1. To determine which logical
processors (threads) belong to a given Compute Unit, determine a ShareId
for each processor as follows:
ShareId = LocalApicId >> log2(ThreadsPerComputeUnit+1)
Logical processors with the same ShareId then belong to the same Compute
Unit. (If ThreadsPerComputeUnit+1 is not a power of two, round it up to the
next power of two).
)" } },
        { "ComputeUnitId",         { 0x8000001E, cpuq_t::regpos_t::EBX,  0,  8, "Compute unit ID. Identifies a Compute Unit, which may be one or more physical cores that each implement one or more logical processors. " } },


        { "NodesPerProcessor",  { 0x8000001E, cpuq_t::regpos_t::ECX,  8, 11, "Specifies the number of nodes in the package/socket in which this logical processor resides.Node in this context corresponds to a processor die. Encoding is N - 1, where N is the number of nodes present in the socket. " } },
        { "NodeId",             { 0x8000001E, cpuq_t::regpos_t::ECX,  0,  8, "Specifies the ID of the node containing the current logical processor. NodeId values are unique across the system.." } },

    };

    umap<signature_t, opcode_t, value_type_hash<signature_t>> opcode_map{
        { { "add",  argtype_t::EAX,      argtype_t::imm32    }, { 0x05, ("add dst, src | ADD | Add imm32 to EAX") } },
        { { "add",  argtype_t::RAX,      argtype_t::imm32    }, { 0x05, ("add dst, src | ADD | Add sign-extended imm32 to RAX") } },
        { { "add",  argtype_t::regmem32, argtype_t::imm32    }, { 0x81, ("add dst, src | ADD | Add imm32 to reg/mem32") } },
        { { "add",  argtype_t::regmem64, argtype_t::imm32    }, { 0x81, ("add dst, src | ADD | Add sign-extended imm32 to reg/mem64") } },
        { { "add",  argtype_t::regmem32, argtype_t::imm8     }, { 0x83, ("add dst, src | ADD | Add sign-extended imm8 to reg/mem32") } },
        { { "add",  argtype_t::regmem64, argtype_t::imm8     }, { 0x83, ("add dst, src | ADD | Add sign-extended imm8 to reg/mem64") } },
        { { "add",  argtype_t::regmem32, argtype_t::reg32    }, { 0x01, ("add dst, src | ADD | Add reg32 to reg/mem32") } },
        { { "add",  argtype_t::regmem64, argtype_t::reg64    }, { 0x01, ("add dst, src | ADD | Add reg64 to reg/mem64") } },
        { { "add",  argtype_t::reg32,    argtype_t::regmem32 }, { 0x03, ("add dst, src | ADD | Add reg/mem32 to reg32") } },
        { { "add",  argtype_t::reg64,    argtype_t::regmem64 }, { 0x03, ("add dst, src | ADD | Add reg/mem64 to reg64") } },

        { { "adc",  argtype_t::EAX,      argtype_t::imm32    }, { 0x15, ("adc dst, src | Add with Carry | Adds the carry flag (CF), the value in a register or memory location (first operand), and an immediate value or the value in a register or memory location (second operand), and stores the result in the first operand location. ") } },
        { { "adc",  argtype_t::RAX,      argtype_t::imm32    }, { 0x15, ("adc dst, src | Add with Carry | Adds the carry flag (CF), the value in a register or memory location (first operand), and an immediate value or the value in a register or memory location (second operand), and stores the result in the first operand location. ") } },
        { { "adc",  argtype_t::regmem32, argtype_t::imm32    }, { 0x81, ("adc dst, src | Add with Carry | Adds the carry flag (CF), the value in a register or memory location (first operand), and an immediate value or the value in a register or memory location (second operand), and stores the result in the first operand location. "),               opcode_flags_t::regopcode_ext, { ._f_regopcode_ext = 2 } } },
        { { "adc",  argtype_t::regmem64, argtype_t::imm32    }, { 0x81, ("adc dst, src | Add with Carry | Adds the carry flag (CF), the value in a register or memory location (first operand), and an immediate value or the value in a register or memory location (second operand), and stores the result in the first operand location. "), opcode_flags_t::regopcode_ext, { ._f_regopcode_ext = 2 } } },
        { { "adc",  argtype_t::regmem32, argtype_t::imm8     }, { 0x83, ("adc dst, src | Add with Carry | Adds the carry flag (CF), the value in a register or memory location (first operand), and an immediate value or the value in a register or memory location (second operand), and stores the result in the first operand location. "),  opcode_flags_t::regopcode_ext, { ._f_regopcode_ext = 2 } } },
        { { "adc",  argtype_t::regmem64, argtype_t::imm8     }, { 0x83, ("adc dst, src | Add with Carry | Adds the carry flag (CF), the value in a register or memory location (first operand), and an immediate value or the value in a register or memory location (second operand), and stores the result in the first operand location. "),  opcode_flags_t::regopcode_ext, { ._f_regopcode_ext = 2 } } },
        { { "adc",  argtype_t::regmem32, argtype_t::reg32    }, { 0x11, ("adc dst, src | Add with Carry | Adds the carry flag (CF), the value in a register or memory location (first operand), and an immediate value or the value in a register or memory location (second operand), and stores the result in the first operand location. ") } },
        { { "adc",  argtype_t::regmem64, argtype_t::reg64    }, { 0x11, ("adc dst, src | Add with Carry | Adds the carry flag (CF), the value in a register or memory location (first operand), and an immediate value or the value in a register or memory location (second operand), and stores the result in the first operand location. ") } },
        { { "adc",  argtype_t::reg32,    argtype_t::regmem32 }, { 0x13, ("adc dst, src | Add with Carry | Adds the carry flag (CF), the value in a register or memory location (first operand), and an immediate value or the value in a register or memory location (second operand), and stores the result in the first operand location. ") } },
        { { "adc",  argtype_t::reg64,    argtype_t::regmem64 }, { 0x13, ("adc dst, src | Add with Carry | Adds the carry flag (CF), the value in a register or memory location (first operand), and an immediate value or the value in a register or memory location (second operand), and stores the result in the first operand location. ") } },

        { { "adox", argtype_t::reg32,    argtype_t::regmem32 }, { 0xF3, "adox dst, src | Unsigned add with overflow flag | Adds the value in a register (first operand) with a register or memory (second operand) and the overflow flag,and stores the result in the first operand location.This instruction sets the OF based on the unsigned additionand whether there is a carry out.This instruction is useful in multi - precision addition algorithms.", opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup, 
            { ._f_opcode_count = 3, ._f_opcode_extra = { 0x0F, 0x38, 0xF6 }, ._f_cpuid_reqs = 1, ._f_cpuid_lookups = { &cpu_queries["ADX"] } } } },
        { { "adox", argtype_t::reg64,    argtype_t::regmem64 }, { 0xF3, "adox dst, src | Unsigned add with overflow flag | Adds the value in a register (first operand) with a register or memory (second operand) and the overflow flag,and stores the result in the first operand location.This instruction sets the OF based on the unsigned additionand whether there is a carry out.This instruction is useful in multi - precision addition algorithms.", opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup, 
            { ._f_opcode_count = 3, ._f_opcode_extra = { 0x0F, 0x38, 0xF6 }, ._f_cpuid_reqs = 1, ._f_cpuid_lookups = { &cpu_queries["ADX"] } } } },


        { { "and",  argtype_t::EAX,      argtype_t::imm32    }, { 0x25, ("and dst, src | AND | and the contents of EAX with an immediate 32-bit value and store the result in EAX.") } },
        { { "and",  argtype_t::RAX,      argtype_t::imm32    }, { 0x25, ("and dst, src | AND | and the contents of RAX with an immediate 32-bit value and store the result in RAX.") } },
        { { "and",  argtype_t::regmem32, argtype_t::imm32    }, { 0x81, ("and dst, src | AND | and the contents of reg/mem32 with imm32."),                 opcode_flags_t::regopcode_ext, { ._f_regopcode_ext = 4 } } },
        { { "and",  argtype_t::regmem64, argtype_t::imm32    }, { 0x81, ("and dst, src | AND | and the contents of reg/mem64 with a sign-extended imm32."), opcode_flags_t::regopcode_ext, { ._f_regopcode_ext = 4 } } },
        { { "and",  argtype_t::regmem32, argtype_t::imm8     }, { 0x83, ("and dst, src | AND | and the contents of reg/mem32 with a sign-extended imm8"),   opcode_flags_t::regopcode_ext, { ._f_regopcode_ext = 4 } } },
        { { "and",  argtype_t::regmem64, argtype_t::imm8     }, { 0x83, ("and dst, src | AND | and the contents of reg/mem64 with a sign-extended imm8"),   opcode_flags_t::regopcode_ext, { ._f_regopcode_ext = 4 } } },
        { { "and",  argtype_t::regmem32, argtype_t::reg32    }, { 0x21, ("and dst, src | AND | and the contents of a 32 bit register or memory location with the contents of a 32-bit register") } },
        { { "and",  argtype_t::regmem64, argtype_t::reg64    }, { 0x21, ("and dst, src | AND | and the contents of a 64-bit register or memory location with the contents of a 64-bit register") } },
        { { "and",  argtype_t::reg32,    argtype_t::regmem32 }, { 0x23, ("and dst, src | AND | and the contents of a 32-bit register with the contents of a 32-bit memory location or register.") } },
        { { "and",  argtype_t::reg64,    argtype_t::regmem64 }, { 0x23, ("and dst, src | AND | and the contents of a 64-bit register with the contents of a 64-bit memory location or register.") } },


        { { "andn", argtype_t::reg32,    argtype_t::reg32,    argtype_t::regmem32 }, 
          { 
              0xF2, 
              "andn dest, src1, src2 | And Not | Performs a bit-wise logical and of the second source operand and the one's complement of the first source operand and stores the result into the destination operand.",
              opcode_flags_t::vex_extended | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = {
                    &cpu_queries["BMI1"]
                },

                ._f_vex0 = vex0_t::VEX_3byte,
                ._f_vex1 = {
                    .map_select = 2
                },
                ._f_vex2 = {
                    .pp =   0,
                    .L =    0,
                    .w =    0
                },
                ._f_vex_vvvv_arg = 1
              }
          } 
        },
        { { "andn", argtype_t::reg64,    argtype_t::reg64,    argtype_t::regmem64 },
          {
              0xF2,
              "andn dest, src1, src2 | And Not | Performs a bit-wise logical and of the second source operand and the one's complement of the first source operand and stores the result into the destination operand.",
              opcode_flags_t::vex_extended | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = {
                    &cpu_queries["BMI1"]
                },

                ._f_vex0 = vex0_t::VEX_3byte,
                ._f_vex1 = {
                    .map_select = 2
                },
                ._f_vex2 = {
                    .pp = 0,
                    .L = 0,
                    .w = 1
                },
                ._f_vex_vvvv_arg = 1
              }
          }
        },


        { { "bextr", argtype_t::reg32,    argtype_t::regmem32,    argtype_t::reg32 },
          {
              0xF7,
              "BEXTR dest, src, cntl | Bit Field Extract | Extracts a contiguous field of bits from the first source operand, as specified by the control field setting in the second source operand and puts the extracted field into the least significant bit positions of the destination.The remaining bits in the destination register are cleared to 0.",
              opcode_flags_t::vex_extended | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = {
                    &cpu_queries["BMI1"]
                },

                ._f_vex0 = vex0_t::VEX_3byte,
                ._f_vex1 = {
                    .map_select = 2
                },
                ._f_vex2 = {
                    .pp = 0,
                    .L = 0,
                    .w = 0
                },
                ._f_vex_vvvv_arg = 2
              }
          }
        },
        { { "bextr", argtype_t::reg64,    argtype_t::regmem64,    argtype_t::reg64 },
          {
              0xF7,
              "BEXTR dest, src, cntl | Bit Field Extract | Extracts a contiguous field of bits from the first source operand, as specified by the control field setting in the second source operand and puts the extracted field into the least significant bit positions of the destination.The remaining bits in the destination register are cleared to 0.",
              opcode_flags_t::vex_extended | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = {
                    &cpu_queries["BMI1"]
                },

                ._f_vex0 = vex0_t::VEX_3byte,
                ._f_vex1 = {
                    .map_select = 2
                },
                ._f_vex2 = {
                    .pp = 0,
                    .L = 0,
                    .w = 1
                },
                ._f_vex_vvvv_arg = 2
              }
          }
        },



        { { "bextr", argtype_t::reg32,    argtype_t::regmem32,    argtype_t::imm32 },
          {
              0x10,
              "BEXTR dest, src, cntl | Bit Field Extract | Extracts a contiguous field of bits from the first source operand, as specified by the control field setting in the second source operand and puts the extracted field into the least significant bit positions of the destination.The remaining bits in the destination register are cleared to 0.",
              opcode_flags_t::vex_extended | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = {
                    &cpu_queries["TBM"]
                },

                ._f_vex0 = vex0_t::XOP,
                ._f_vex1 = {
                    .map_select = 0x0A
                },
                ._f_vex2 = {
                    .pp = 0,
                    .L = 0,
                    .vvvv = 0xF,
                    .w = 0
                },
                ._f_vex_vvvv_arg = 0xFF
              }
          }
        },
        { { "bextr", argtype_t::reg64,    argtype_t::regmem64,    argtype_t::imm64 },
          {
              0x10,
              "BEXTR dest, src, cntl | Bit Field Extract | Extracts a contiguous field of bits from the first source operand, as specified by the control field setting in the second source operand and puts the extracted field into the least significant bit positions of the destination.The remaining bits in the destination register are cleared to 0.",
              opcode_flags_t::vex_extended | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = {
                    &cpu_queries["TBM"]
                },

                ._f_vex0 = vex0_t::XOP,
                ._f_vex1 = {
                    .map_select = 0x0A
                },
                ._f_vex2 = {
                    .pp = 0,
                    .L = 0,
                    .vvvv = 0xF,
                    .w = 1
                },
                ._f_vex_vvvv_arg = 0xFF
              }
          }
        },

        // BLCFILL
        // BLCI
        // BLCIC 
        // BLCMSK
        // BLCS
        // BLSFILL
        // 

        { { "blsi", argtype_t::reg32,    argtype_t::regmem32 },
          {
              0xF3,
              "BLSI dest, src | Isolate Lowest Set Bit | Clears all bits in the source operand except for the least significant bit that is set to 1 and writes the result to the destination.If the source is all zeros, the destination is written with all zeros.",
              opcode_flags_t::vex_extended | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 3,

                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = {
                    &cpu_queries["BMI1"]
                },

                ._f_vex0 = vex0_t::VEX_3byte,
                ._f_vex1 = {
                    .map_select = 2
                },
                ._f_vex2 = {
                    .pp = 0,
                    .L = 0,
                    .w = 0
                },
                ._f_vex_vvvv_arg = 0
              }
          }
        },

        { { "blsi", argtype_t::reg64,    argtype_t::regmem64 },
          {
              0xF3,
              "BLSI dest, src | Isolate Lowest Set Bit | Clears all bits in the source operand except for the least significant bit that is set to 1 and writes the result to the destination.If the source is all zeros, the destination is written with all zeros.",
              opcode_flags_t::vex_extended | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 3,

                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = {
                    &cpu_queries["BMI1"]
                },

                ._f_vex0 = vex0_t::VEX_3byte,
                ._f_vex1 = {
                    .map_select = 2
                },
                ._f_vex2 = {
                    .pp = 0,
                    .L = 0,
                    .w = 1
                },
                ._f_vex_vvvv_arg = 0
              }
          }
        },

        // blsic

        { { "blsmsk", argtype_t::reg32,    argtype_t::regmem32 },
          {
              0xF3,
              "BLSMSK dest, src | Mask From Lowest Set Bit | Forms a mask with bits set to 1 from bit 0 up to and including the least significant bit position that is set to 1 in the source operand and writes the mask to the destination.If the value of the source operand is zero, the destination is written with all ones.",
              opcode_flags_t::vex_extended | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 2,

                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = {
                    &cpu_queries["BMI1"]
                },

                ._f_vex0 = vex0_t::VEX_3byte,
                ._f_vex1 = {
                    .map_select = 2
                },
                ._f_vex2 = {
                    .pp = 0,
                    .L = 0,
                    .w = 0
                },
                ._f_vex_vvvv_arg = 0
              }
          }
        },
        { { "blsmsk", argtype_t::reg64,    argtype_t::regmem64 },
          {
              0xF3,
              "BLSMSK dest, src | Mask From Lowest Set Bit | Forms a mask with bits set to 1 from bit 0 up to and including the least significant bit position that is set to 1 in the source operand and writes the mask to the destination.If the value of the source operand is zero, the destination is written with all ones.",
              opcode_flags_t::vex_extended | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 2,

                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = {
                    &cpu_queries["BMI1"]
                },

                ._f_vex0 = vex0_t::VEX_3byte,
                ._f_vex1 = {
                    .map_select = 2
                },
                ._f_vex2 = {
                    .pp = 0,
                    .L = 0,
                    .w = 1
                },
                ._f_vex_vvvv_arg = 0
              }
          }
        },


        { { "blsr", argtype_t::reg32,    argtype_t::regmem32 },
          {
              0xF3,
              "BLSR dest, src | Reset Lowest Set Bit | Clears the least-significant bit that is set to 1 in the input operand and writes the modified operand to the destination.",
              opcode_flags_t::vex_extended | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 1,

                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = {
                    &cpu_queries["BMI1"]
                },

                ._f_vex0 = vex0_t::VEX_3byte,
                ._f_vex1 = {
                    .map_select = 2
                },
                ._f_vex2 = {
                    .pp = 0,
                    .L = 0,
                    .w = 0
                },
                ._f_vex_vvvv_arg = 0
              }
          }
        },
        { { "blsr", argtype_t::reg64,    argtype_t::regmem64 },
          {
              0xF3,
              "BLSR dest, src | Reset Lowest Set Bit | Clears the least-significant bit that is set to 1 in the input operand and writes the modified operand to the destination.",
              opcode_flags_t::vex_extended | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 1,

                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = {
                    &cpu_queries["BMI1"]
                },

                ._f_vex0 = vex0_t::VEX_3byte,
                ._f_vex1 = {
                    .map_select = 2
                },
                ._f_vex2 = {
                    .pp = 0,
                    .L = 0,
                    .w = 1
                },
                ._f_vex_vvvv_arg = 0
              }
          }
        },

        // BOUND - invalid in 64-bit mode

        { { "bsf",  argtype_t::reg32, argtype_t::regmem32    }, 
          { 0x0F, 
            ("bsf dest, src | Bit Scan Forward | Searches the value in a register or a memory location (second operand) for the least-significant set bit. If a set bit is found, the instruction clears the zero flag(ZF) and stores the index of the least - significant set bit in a destination register (first operand).If the second operand contains 0, the instruction sets ZF to 1 and does not change the contents of the destination register.The bit index is an unsigned offset from bit 0 of the searched value."),
            opcode_flags_t::multibyte_opcode,
            {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0xBC }
            }
          } 
        },
        { { "bsf",  argtype_t::reg32, argtype_t::regmem32    },
          { 0x0F,
            ("bsf dest, src | Bit Scan Forward | Searches the value in a register or a memory location (second operand) for the least-significant set bit. If a set bit is found, the instruction clears the zero flag(ZF) and stores the index of the least - significant set bit in a destination register (first operand).If the second operand contains 0, the instruction sets ZF to 1 and does not change the contents of the destination register.The bit index is an unsigned offset from bit 0 of the searched value."),
            opcode_flags_t::multibyte_opcode,
            {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0xBC }
            }
          }
        },


        { { "bsr",  argtype_t::reg32, argtype_t::regmem32    },
          { 0x0F,
            ("bsf dest, src | Bit Scan Reverse | Searches the value in a register or a memory location (second operand) for the most-significant set bit. If a set bit is found, the instruction clears the zero flag(ZF) and stores the index of the most-significant set bit in a destination register (first operand).If the second operand contains 0, the instruction sets ZF to 1 and does not change the contents of the destination register.The bit index is an unsigned offset from bit 0 of the searched value."),
            opcode_flags_t::multibyte_opcode,
            {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0xBD }
            }
          }
        },
        { { "bsr",  argtype_t::reg32, argtype_t::regmem32    },
          { 0x0F,
            ("bsf dest, src | Bit Scan Reverse | Searches the value in a register or a memory location (second operand) for the most-significant set bit. If a set bit is found, the instruction clears the zero flag(ZF) and stores the index of the most-significant set bit in a destination register (first operand).If the second operand contains 0, the instruction sets ZF to 1 and does not change the contents of the destination register.The bit index is an unsigned offset from bit 0 of the searched value."),
            opcode_flags_t::multibyte_opcode,
            {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0xBD }
            }
          }
        },


        { { "bswap",  argtype_t::reg32  },
          { 0x0F,
            ("bswap reg | Byte Swap | Reverses the byte order of the specified register. This action converts the contents of the register from little endian to big endian or vice versa.In a doubleword, bits 7:0 are exchanged with bits 31 : 24,and bits 15 : 8 are exchanged with bits 23 : 16. In a quadword, bits 7 : 0 are exchanged with bits 63 : 56, bits 15 : 8 with bits 55 : 48, bits 23 : 16 with bits 47 : 40,and bits 31 : 24 with bits 39 : 32. A subsequent use of the BSWAP instruction with the same operand restores the original value of the operand."),
            opcode_flags_t::multibyte_opcode,
            {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0xC8 }
            }
          }
        },
        { { "bswap",  argtype_t::reg64  },
          { 0x0F,
            ("bswap reg | Byte Swap | Reverses the byte order of the specified register. This action converts the contents of the register from little endian to big endian or vice versa.In a doubleword, bits 7:0 are exchanged with bits 31 : 24,and bits 15 : 8 are exchanged with bits 23 : 16. In a quadword, bits 7 : 0 are exchanged with bits 63 : 56, bits 15 : 8 with bits 55 : 48, bits 23 : 16 with bits 47 : 40,and bits 31 : 24 with bits 39 : 32. A subsequent use of the BSWAP instruction with the same operand restores the original value of the operand."),
            opcode_flags_t::multibyte_opcode,
            {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0xC8 }
            }
          }
        },


        { { "bt",  argtype_t::regmem32, argtype_t::reg32  },
          { 0x0F,
            ("bt bit-base bit-index | Bit Test | Copies a bit, specified by a bit index in a register or 8-bit immediate value (second operand), from a bit string (first operand), also called the bit base, to the carry flag (CF) of the rFLAGS register. If the bit base operand is a register, the instruction uses the modulo 16, 32, or 64 (depending on the operand size) of the bit index to select a bit in the register. If the bit base operand is a memory location, bit 0 of the byte at the specified address is the bit base of the bit string. If the bit index is in a register, the instruction selects a bit position relative to the bit base. If the bit index is in an immediate value, the bit selected is that value modulo 16, 32, or 64, depending on operand size. When the instruction attempts to copy a bit from memory, it accesses 2, 4, or 8 bytes starting from the specified memory address for 16-bit, 32-bit, or 64-bit operand sizes, respectively. When using this bit addressing mechanism, avoid referencing areas of memory close to address space holes, such as references to memory-mapped I/O registers. Instead, use a MOV instruction to load a register from such an address and use a register form of the BT instruction to manipulate the data."),
            opcode_flags_t::multibyte_opcode,
            {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0xA3 }
            }
          }
        },
        { { "bt",  argtype_t::regmem64, argtype_t::reg64  },
          { 0x0F,
            ("bt bit-base bit-index | Bit Test | Copies a bit, specified by a bit index in a register or 8-bit immediate value (second operand), from a bit string (first operand), also called the bit base, to the carry flag (CF) of the rFLAGS register. If the bit base operand is a register, the instruction uses the modulo 16, 32, or 64 (depending on the operand size) of the bit index to select a bit in the register. If the bit base operand is a memory location, bit 0 of the byte at the specified address is the bit base of the bit string. If the bit index is in a register, the instruction selects a bit position relative to the bit base. If the bit index is in an immediate value, the bit selected is that value modulo 16, 32, or 64, depending on operand size. When the instruction attempts to copy a bit from memory, it accesses 2, 4, or 8 bytes starting from the specified memory address for 16-bit, 32-bit, or 64-bit operand sizes, respectively. When using this bit addressing mechanism, avoid referencing areas of memory close to address space holes, such as references to memory-mapped I/O registers. Instead, use a MOV instruction to load a register from such an address and use a register form of the BT instruction to manipulate the data."),
            opcode_flags_t::multibyte_opcode,
            {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0xA3 }
            }
          }
        },
        { { "bt",  argtype_t::regmem32, argtype_t::imm8  },
          { 0x0F,
            ("bt bit-base bit-index | Bit Test | Copies a bit, specified by a bit index in a register or 8-bit immediate value (second operand), from a bit string (first operand), also called the bit base, to the carry flag (CF) of the rFLAGS register. If the bit base operand is a register, the instruction uses the modulo 16, 32, or 64 (depending on the operand size) of the bit index to select a bit in the register. If the bit base operand is a memory location, bit 0 of the byte at the specified address is the bit base of the bit string. If the bit index is in a register, the instruction selects a bit position relative to the bit base. If the bit index is in an immediate value, the bit selected is that value modulo 16, 32, or 64, depending on operand size. When the instruction attempts to copy a bit from memory, it accesses 2, 4, or 8 bytes starting from the specified memory address for 16-bit, 32-bit, or 64-bit operand sizes, respectively. When using this bit addressing mechanism, avoid referencing areas of memory close to address space holes, such as references to memory-mapped I/O registers. Instead, use a MOV instruction to load a register from such an address and use a register form of the BT instruction to manipulate the data."),
            opcode_flags_t::multibyte_opcode | opcode_flags_t::regopcode_ext,
            {
                ._f_regopcode_ext = 4,
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0xBA }
            }
          }
        },
        { { "bt",  argtype_t::regmem64, argtype_t::imm8  },
          { 0x0F,
            ("bt bit-base bit-index | Bit Test | Copies a bit, specified by a bit index in a register or 8-bit immediate value (second operand), from a bit string (first operand), also called the bit base, to the carry flag (CF) of the rFLAGS register. If the bit base operand is a register, the instruction uses the modulo 16, 32, or 64 (depending on the operand size) of the bit index to select a bit in the register. If the bit base operand is a memory location, bit 0 of the byte at the specified address is the bit base of the bit string. If the bit index is in a register, the instruction selects a bit position relative to the bit base. If the bit index is in an immediate value, the bit selected is that value modulo 16, 32, or 64, depending on operand size. When the instruction attempts to copy a bit from memory, it accesses 2, 4, or 8 bytes starting from the specified memory address for 16-bit, 32-bit, or 64-bit operand sizes, respectively. When using this bit addressing mechanism, avoid referencing areas of memory close to address space holes, such as references to memory-mapped I/O registers. Instead, use a MOV instruction to load a register from such an address and use a register form of the BT instruction to manipulate the data."),
            opcode_flags_t::multibyte_opcode | opcode_flags_t::regopcode_ext,
            {
                ._f_regopcode_ext = 4,
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0xBA }
            }
          }
        },



        { { "btc",  argtype_t::regmem32, argtype_t::reg32  },
          { 0x0F,
            ("btc bit-base bit-index | Bit Test and Complement | Copies a bit, specified by a bit index in a register or 8-bit immediate value (second operand), from a bit string (first operand), also called the bit base, to the carry flag (CF) of the rFLAGS register, and then complements (toggles) the bit in the bit string. If the bit base operand is a register, the instruction uses the modulo 16, 32, or 64 (depending on the operand size) of the bit index to select a bit in the register. If the bit base operand is a memory location, bit 0 of the byte at the specified address is the bit base of the bit string. If the bit index is in a register, the instruction selects a bit position relative to the bit base. If the bit index is in an immediate value, the bit selected is that value modulo 16, 32, or 64, depending the operand size. This instruction is useful for implementing semaphores in concurrent operating systems. Such an application should precede this instruction with the LOCK prefix. For details about the LOCK prefix, see \"Lock Prefix\" on page 11. "),
            opcode_flags_t::multibyte_opcode,
            {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0xBB }
            }
          }
        },
        { { "btc",  argtype_t::regmem64, argtype_t::reg64  },
          { 0x0F,
            ("btc bit-base bit-index | Bit Test and Complement | Copies a bit, specified by a bit index in a register or 8-bit immediate value (second operand), from a bit string (first operand), also called the bit base, to the carry flag (CF) of the rFLAGS register, and then complements (toggles) the bit in the bit string. If the bit base operand is a register, the instruction uses the modulo 16, 32, or 64 (depending on the operand size) of the bit index to select a bit in the register. If the bit base operand is a memory location, bit 0 of the byte at the specified address is the bit base of the bit string. If the bit index is in a register, the instruction selects a bit position relative to the bit base. If the bit index is in an immediate value, the bit selected is that value modulo 16, 32, or 64, depending the operand size. This instruction is useful for implementing semaphores in concurrent operating systems. Such an application should precede this instruction with the LOCK prefix. For details about the LOCK prefix, see \"Lock Prefix\" on page 11. "),
            opcode_flags_t::multibyte_opcode,
            {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0xBB }
            }
          }
        },
        { { "btc",  argtype_t::regmem32, argtype_t::imm8  },
          { 0x0F,
            ("btc bit-base bit-index | Bit Test and Complement | Copies a bit, specified by a bit index in a register or 8-bit immediate value (second operand), from a bit string (first operand), also called the bit base, to the carry flag (CF) of the rFLAGS register, and then complements (toggles) the bit in the bit string. If the bit base operand is a register, the instruction uses the modulo 16, 32, or 64 (depending on the operand size) of the bit index to select a bit in the register. If the bit base operand is a memory location, bit 0 of the byte at the specified address is the bit base of the bit string. If the bit index is in a register, the instruction selects a bit position relative to the bit base. If the bit index is in an immediate value, the bit selected is that value modulo 16, 32, or 64, depending the operand size. This instruction is useful for implementing semaphores in concurrent operating systems. Such an application should precede this instruction with the LOCK prefix. For details about the LOCK prefix, see \"Lock Prefix\" on page 11. "),
            opcode_flags_t::multibyte_opcode | opcode_flags_t::regopcode_ext,
            {
                ._f_regopcode_ext = 7,
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0xBA }
            }
          }
        },
        { { "btc",  argtype_t::regmem64, argtype_t::imm8  },
          { 0x0F,
            ("btc bit-base bit-index | Bit Test and Complement | Copies a bit, specified by a bit index in a register or 8-bit immediate value (second operand), from a bit string (first operand), also called the bit base, to the carry flag (CF) of the rFLAGS register, and then complements (toggles) the bit in the bit string. If the bit base operand is a register, the instruction uses the modulo 16, 32, or 64 (depending on the operand size) of the bit index to select a bit in the register. If the bit base operand is a memory location, bit 0 of the byte at the specified address is the bit base of the bit string. If the bit index is in a register, the instruction selects a bit position relative to the bit base. If the bit index is in an immediate value, the bit selected is that value modulo 16, 32, or 64, depending the operand size. This instruction is useful for implementing semaphores in concurrent operating systems. Such an application should precede this instruction with the LOCK prefix. For details about the LOCK prefix, see \"Lock Prefix\" on page 11. "),
            opcode_flags_t::multibyte_opcode | opcode_flags_t::regopcode_ext,
            {
                ._f_regopcode_ext = 7,
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0xBA }
            }
          }
        },



        { { "btr",  argtype_t::regmem32, argtype_t::reg32  },
          { 0x0F,
            ("btr bit-base bit-index | Bit Test and Reset | Copies a bit, specified by a bit index in a register or 8-bit immediate value (second operand), from a bit string (first operand), also called the bit base, to the carry flag (CF) of the rFLAGS register, and then clears the bit in the bit string to 0. If the bit base operand is a register, the instruction uses the modulo 16, 32, or 64 (depending on the operand size) of the bit index to select a bit in the register. If the bit base operand is a memory location, bit 0 of the byte at the specified address is the bit base of the bit string. If the bit index is in a register, the instruction selects a bit position relative to the bit base. If the bit index is in an immediate value, the bit selected is that value modulo 16, 32, or 64, depending the operand size. This instruction is useful for implementing semaphores in concurrent operating systems. Such an application should precede this instruction with the LOCK prefix. For details about the LOCK prefix, see \"Lock Prefix\" on page 11. "),
            opcode_flags_t::multibyte_opcode,
            {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0xB3 }
            }
          }
        },
        { { "btr",  argtype_t::regmem64, argtype_t::reg64  },
          { 0x0F,
            ("btr bit-base bit-index | Bit Test and Reset | Copies a bit, specified by a bit index in a register or 8-bit immediate value (second operand), from a bit string (first operand), also called the bit base, to the carry flag (CF) of the rFLAGS register, and then clears the bit in the bit string to 0. If the bit base operand is a register, the instruction uses the modulo 16, 32, or 64 (depending on the operand size) of the bit index to select a bit in the register. If the bit base operand is a memory location, bit 0 of the byte at the specified address is the bit base of the bit string. If the bit index is in a register, the instruction selects a bit position relative to the bit base. If the bit index is in an immediate value, the bit selected is that value modulo 16, 32, or 64, depending the operand size. This instruction is useful for implementing semaphores in concurrent operating systems. Such an application should precede this instruction with the LOCK prefix. For details about the LOCK prefix, see \"Lock Prefix\" on page 11. "),
            opcode_flags_t::multibyte_opcode,
            {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0xB3 }
            }
          }
        },
        { { "btr",  argtype_t::regmem32, argtype_t::imm8  },
          { 0x0F,
            ("btr bit-base bit-index | Bit Test and Reset | Copies a bit, specified by a bit index in a register or 8-bit immediate value (second operand), from a bit string (first operand), also called the bit base, to the carry flag (CF) of the rFLAGS register, and then clears the bit in the bit string to 0. If the bit base operand is a register, the instruction uses the modulo 16, 32, or 64 (depending on the operand size) of the bit index to select a bit in the register. If the bit base operand is a memory location, bit 0 of the byte at the specified address is the bit base of the bit string. If the bit index is in a register, the instruction selects a bit position relative to the bit base. If the bit index is in an immediate value, the bit selected is that value modulo 16, 32, or 64, depending the operand size. This instruction is useful for implementing semaphores in concurrent operating systems. Such an application should precede this instruction with the LOCK prefix. For details about the LOCK prefix, see \"Lock Prefix\" on page 11. "),
            opcode_flags_t::multibyte_opcode | opcode_flags_t::regopcode_ext,
            {
                ._f_regopcode_ext = 6,
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0xBA }
            }
          }
        },
        { { "btr",  argtype_t::regmem64, argtype_t::imm8  },
          { 0x0F,
            ("btr bit-base bit-index | Bit Test and Reset | Copies a bit, specified by a bit index in a register or 8-bit immediate value (second operand), from a bit string (first operand), also called the bit base, to the carry flag (CF) of the rFLAGS register, and then clears the bit in the bit string to 0. If the bit base operand is a register, the instruction uses the modulo 16, 32, or 64 (depending on the operand size) of the bit index to select a bit in the register. If the bit base operand is a memory location, bit 0 of the byte at the specified address is the bit base of the bit string. If the bit index is in a register, the instruction selects a bit position relative to the bit base. If the bit index is in an immediate value, the bit selected is that value modulo 16, 32, or 64, depending the operand size. This instruction is useful for implementing semaphores in concurrent operating systems. Such an application should precede this instruction with the LOCK prefix. For details about the LOCK prefix, see \"Lock Prefix\" on page 11. "),
            opcode_flags_t::multibyte_opcode | opcode_flags_t::regopcode_ext,
            {
                ._f_regopcode_ext = 6,
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0xBA }
            }
          }
        },



        { { "bts",  argtype_t::regmem32, argtype_t::reg32  },
          { 0x0F,
            ("bts bit-base bit-index | Bit Test and Set | Copies a bit, specified by a bit index in a register or 8-bit immediate value (second operand), from a bit string (first operand), also called the bit base, to the carry flag (CF) of the rFLAGS register, and then sets the bit in the bitstring to 1. If the bit base operand is a register, the instruction uses the modulo 16, 32, or 64 (depending on the operand size) of the bit index to select a bit in the register. If the bit base operand is a memory location, bit 0 of the byte at the specified address is the bit base of the bit string. If the bit index is in a register, the instruction selects a bit position relative to the bit base. If the bit index is in an immediate value, the bit selected is that value modulo 16, 32, or 64, depending the operand size. This instruction is useful for implementing semaphores in concurrent operating systems. Such an application should precede this instruction with the LOCK prefix. For details about the LOCK prefix, see \"Lock Prefix\" on page 11. "),
            opcode_flags_t::multibyte_opcode,
            {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0xAB }
            }
          }
        },
        { { "bts",  argtype_t::regmem64, argtype_t::reg64  },
          { 0x0F,
            ("bts bit-base bit-index | Bit Test and Set | Copies a bit, specified by a bit index in a register or 8-bit immediate value (second operand), from a bit string (first operand), also called the bit base, to the carry flag (CF) of the rFLAGS register, and then sets the bit in the bitstring to 1. If the bit base operand is a register, the instruction uses the modulo 16, 32, or 64 (depending on the operand size) of the bit index to select a bit in the register. If the bit base operand is a memory location, bit 0 of the byte at the specified address is the bit base of the bit string. If the bit index is in a register, the instruction selects a bit position relative to the bit base. If the bit index is in an immediate value, the bit selected is that value modulo 16, 32, or 64, depending the operand size. This instruction is useful for implementing semaphores in concurrent operating systems. Such an application should precede this instruction with the LOCK prefix. For details about the LOCK prefix, see \"Lock Prefix\" on page 11. "),
            opcode_flags_t::multibyte_opcode,
            {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0xAB }
            }
          }
        },
        { { "bts",  argtype_t::regmem32, argtype_t::imm8  },
          { 0x0F,
            ("bts bit-base bit-index | Bit Test and Set | Copies a bit, specified by a bit index in a register or 8-bit immediate value (second operand), from a bit string (first operand), also called the bit base, to the carry flag (CF) of the rFLAGS register, and then sets the bit in the bitstring to 1. If the bit base operand is a register, the instruction uses the modulo 16, 32, or 64 (depending on the operand size) of the bit index to select a bit in the register. If the bit base operand is a memory location, bit 0 of the byte at the specified address is the bit base of the bit string. If the bit index is in a register, the instruction selects a bit position relative to the bit base. If the bit index is in an immediate value, the bit selected is that value modulo 16, 32, or 64, depending the operand size. This instruction is useful for implementing semaphores in concurrent operating systems. Such an application should precede this instruction with the LOCK prefix. For details about the LOCK prefix, see \"Lock Prefix\" on page 11. "),
            opcode_flags_t::multibyte_opcode | opcode_flags_t::regopcode_ext,
            {
                ._f_regopcode_ext = 5,
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0xBA }
            }
          }
        },
        { { "bts",  argtype_t::regmem64, argtype_t::imm8  },
          { 0x0F,
            ("bts bit-base bit-index | Bit Test and Set | Copies a bit, specified by a bit index in a register or 8-bit immediate value (second operand), from a bit string (first operand), also called the bit base, to the carry flag (CF) of the rFLAGS register, and then sets the bit in the bitstring to 1. If the bit base operand is a register, the instruction uses the modulo 16, 32, or 64 (depending on the operand size) of the bit index to select a bit in the register. If the bit base operand is a memory location, bit 0 of the byte at the specified address is the bit base of the bit string. If the bit index is in a register, the instruction selects a bit position relative to the bit base. If the bit index is in an immediate value, the bit selected is that value modulo 16, 32, or 64, depending the operand size. This instruction is useful for implementing semaphores in concurrent operating systems. Such an application should precede this instruction with the LOCK prefix. For details about the LOCK prefix, see \"Lock Prefix\" on page 11. "),
            opcode_flags_t::multibyte_opcode | opcode_flags_t::regopcode_ext,
            {
                ._f_regopcode_ext = 5,
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0xBA }
            }
          }
        },



        { { "bzhi", argtype_t::reg32,    argtype_t::regmem32,    argtype_t::reg32 },
          {
              0xF5,
              "BZHI dest, src, index | Zero High Bits | Copies bits, left to right, from the first source operand starting with the bit position specified by the second source operand (index), writes these bits to the destination, and clears all the bits in positions greater than or equal to index.",
              opcode_flags_t::vex_extended | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = {
                    &cpu_queries["BMI2"]
                },

                ._f_vex0 = vex0_t::VEX_3byte,
                ._f_vex1 = {
                    .map_select = 2
                },
                ._f_vex2 = {
                    .pp = 0,
                    .L = 0,
                    .w = 0
                },
                ._f_vex_vvvv_arg = 2
              }
          }
        },
        { { "bzhi", argtype_t::reg64,    argtype_t::regmem64,    argtype_t::reg64 },
          {
              0xF5,
              "BZHI dest, src, index | Zero High Bits | Copies bits, left to right, from the first source operand starting with the bit position specified by the second source operand (index), writes these bits to the destination, and clears all the bits in positions greater than or equal to index.",
              opcode_flags_t::vex_extended | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = {
                    &cpu_queries["BMI2"]
                },

                ._f_vex0 = vex0_t::VEX_3byte,
                ._f_vex1 = {
                    .map_select = 2
                },
                ._f_vex2 = {
                    .pp = 0,
                    .L = 0,
                    .w = 1
                },
                ._f_vex_vvvv_arg = 2
              }
          }
        },


        { { "call",  argtype_t::imm32 },    { 0xE8, ("CALL rel32off | Near Proc Call | Pushes the offset of the next instruction onto the stack and branches to the target address, which contains the first instruction of the called procedure. The target operand can specify a register, a memory location, or a label. A procedure accessed by a near CALL is located in the same code segment as the CALL instruction. If the CALL target is specified by a register or memory location, then a 16-, 32-, or 64-bit rIP is read from the operand, depending on the operand size. A 16- or 32-bit rIP is zero-extended to 64 bits. If the CALL target is specified by a displacement, the signed displacement is added to the rIP (of the following instruction), and the result is truncated to 16, 32, or 64 bits, depending on the operand size. The signed displacement is 16 or 32 bits, depending on the operand size.") } },
        { { "call",  argtype_t::regmem64 }, 
            { 0xFF, 
              "CALL rel32off | Near Proc Call | Pushes the offset of the next instruction onto the stack and branches to the target address, which contains the first instruction of the called procedure. The target operand can specify a register, a memory location, or a label. A procedure accessed by a near CALL is located in the same code segment as the CALL instruction. If the CALL target is specified by a register or memory location, then a 16-, 32-, or 64-bit rIP is read from the operand, depending on the operand size. A 16- or 32-bit rIP is zero-extended to 64 bits. If the CALL target is specified by a displacement, the signed displacement is added to the rIP (of the following instruction), and the result is truncated to 16, 32, or 64 bits, depending on the operand size. The signed displacement is 16 or 32 bits, depending on the operand size.",
               opcode_flags_t::regopcode_ext,
                {
                    ._f_regopcode_ext = 2
                }
            } },


        { { "cdqe" }, { 0x98, ("cdqe | Convert to Sign-Extended | Copies the sign bit in the AL or eAX register to the upper bits of the rAX register. The effect of this instruction is to convert a signed byte, word, or doubleword in the AL or eAX register into a signed word, doubleword, or quadword in the rAX register. This action helps avoid overflow problems in signed number arithmetic. ") } },
        { { "cqo" },  { 0x99, ("cqo  | Convert to Sign-Extended | Copies the sign bit in the rAX register to all bits of the rDX register. The effect of this instruction is to convert a signed word, doubleword, or quadword in the rAX register into a signed doubleword, quadword, or double-quadword in the rDX:rAX registers. This action helps avoid overflow problems in signed number arithmetic.") } },
        { { "clc" },  { 0xF8, ("clc  | Clear Carry Flag | Clears the carry flag (CF) in the rFLAGS register to zero.") } },
        { { "cld" },  { 0xF8, ("cld  | Clear Direction Flag | Clears the direction flag (DF) in the rFLAGS register to zero. If the DF flag is 0, each iteration of a string instruction increments the data pointer (index registers rSI or rDI). If the DF flag is 1, the string instruction decrements the pointer. Use the CLD instruction before a string instruction to make the data pointer increment.") } },

        { { "clflush", argtype_t::regmem64 },  
            { 0x0F, 
              "clflush mem8 | Cache Line Flush | Flushes the cache line specified by the mem8 linear-address. The instruction checks all levels of the cache hierarchy—internal caches and external caches—and invalidates the cache line in every cache in which it is found. If a cache contains a dirty copy of the cache line (that is, the cache line is in the modified or owned MOESI state), the line is written back to memory before it is invalidated. The instruction sets the cache-line MOESI state to invalid. The instruction also checks the physical address corresponding to the linear-address operand against the processor’s write-combining buffers. If the write-combining buffer holds data intended for that physical address, the instruction writes the entire contents of the buffer to memory. This occurs even though the data is not cached in the cache hierarchy. In a multiprocessor system, the instruction checks the write-combining buffers only on the processor that executed the CLFLUSH instruction",
              opcode_flags_t::regopcode_ext | opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_regopcode_ext = 7,
                    
                    ._f_opcode_count = 1,
                    ._f_opcode_extra = { 0xAE },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CLFSH"]
                    }
               } 
            } },
        { { "clflushopt", argtype_t::regmem64 },  
            { 0x66, 
              "clflushopt mem8 | Optimized Cache Line Flush | Flushes the cache line specified by the mem8 linear-address. The instruction checks all levels of the cache hierarchy—internal caches and external caches—and invalidates the cache line in every cache in which it is found. If a cache contains a dirty copy of the cache line (that is, the cache line is in the modified or owned MOESI state), the line is written back to memory before it is invalidated. The instruction sets the cache-line MOESI state to invalid. The instruction also checks the physical address corresponding to the linear-address operand against the processor’s write-combining buffers. If the write-combining buffer holds data intended for that physical address, the instruction writes the entire contents of the buffer to memory. This occurs even though the data is not cached in the cache hierarchy. In a multiprocessor system, the instruction checks the write-combining buffers only on the processor that executed the CLFLUSH instruction",
              opcode_flags_t::regopcode_ext | opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_regopcode_ext = 7,
                    
                    ._f_opcode_count = 2,
                    ._f_opcode_extra = { 0x0F, 0xAE },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CLFLOPT"]
                    }
               } 
            } },

        { { "clwb" },
            { 0x66,
              "clwb | Cache Line Write Back and Retain | Flushes the cache line specified by the mem8 linear address. The instruction checks all levels of the cache hierarchy—internal caches and external caches—and causes the cache line, if dirty, to be written to memory. The cache line may be retained in the cache where found in a non-dirty state. The CLWB instruction is weakly ordered with respect to other instructions that operate on memory. Speculative loads initiated by the processor, or specified explicitly using cache prefetch instructions, can be reordered around a CLWB instruction. CLWB is ordered naturally with older stores to the same address on the same logical processor. To create strict ordering of CLWB use a store-ordering instruction such as SFENCE. The CLWB instruction behaves like a load instruction with respect to setting the page table accessed and dirty bits. That is, it sets the page table accessed bit to 1, but does not set the page table dirty bit. ",
              opcode_flags_t::regopcode_ext | opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_regopcode_ext = 6,

                    ._f_opcode_count = 2,
                    ._f_opcode_extra = { 0x0F, 0xAE },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CLWB"]
                    }
               }
            } },

        { { "clzero" },
            { 0x0F,
              "clzero | Zero Cache Line | Clears the cache line specified by the logical address in rAX by writing a zero to every byte in the line. The instruction uses an implied non temporal memory type, similar to a streaming store, and uses the write combining protocol to minimize cache pollution. CLZERO is weakly-ordered with respect to other instructions that operate on memory. Software should use an SFENCE or stronger to enforce memory ordering of CLZERO with respect to other store instructions.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_opcode_count = 2,
                    ._f_opcode_extra = { 0x01, 0xFC },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CLZERO"]
                    }
               }
            } },
        
            
        { { "cmc" },  { 0xF5, ("cmc  | Complement Carry Flag | Complements (toggles) the carry flag (CF) bit of the rFLAGS register") } },

        { { "cmovo", argtype_t::reg32, argtype_t::regmem32 },
            { 0x0F,
              "cmovo dst, src | Conditional Move (If overflow) | Conditionally moves a 16-bit, 32-bit, or 64-bit value in memory or a general-purpose register (second operand) into a register (first operand), depending upon the settings of condition flags in the rFLAGS register. If the condition is not satisfied, the destination register is not modified. For the memory-based forms of CMOVcc, memory-related exceptions may be reported even if the condition is false. In 64-bit mode, CMOVcc with a 32-bit operand size will clear the upper 32 bits of the destination register even if the condition is false.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_opcode_count = 1,
                    ._f_opcode_extra = { 0x40 },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CMOV"]
                    }
               }
            } },
        { { "cmovo", argtype_t::reg64, argtype_t::regmem64 },
            { 0x0F,
              "cmovo dst, src | Conditional Move (If overflow) | Conditionally moves a 16-bit, 32-bit, or 64-bit value in memory or a general-purpose register (second operand) into a register (first operand), depending upon the settings of condition flags in the rFLAGS register. If the condition is not satisfied, the destination register is not modified. For the memory-based forms of CMOVcc, memory-related exceptions may be reported even if the condition is false. In 64-bit mode, CMOVcc with a 32-bit operand size will clear the upper 32 bits of the destination register even if the condition is false.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_opcode_count = 1,
                    ._f_opcode_extra = { 0x40 },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CMOV"]
                    }
               }
            } },

        { { "cmovno", argtype_t::reg32, argtype_t::regmem32 },
            { 0x0F,
              "cmovno dst, src | Conditional Move (If not overflow) | Conditionally moves a 16-bit, 32-bit, or 64-bit value in memory or a general-purpose register (second operand) into a register (first operand), depending upon the settings of condition flags in the rFLAGS register. If the condition is not satisfied, the destination register is not modified. For the memory-based forms of CMOVcc, memory-related exceptions may be reported even if the condition is false. In 64-bit mode, CMOVcc with a 32-bit operand size will clear the upper 32 bits of the destination register even if the condition is false.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_opcode_count = 1,
                    ._f_opcode_extra = { 0x41 },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CMOV"]
                    }
               }
            } },
        { { "cmovno", argtype_t::reg64, argtype_t::regmem64 },
            { 0x0F,
              "cmovno dst, src | Conditional Move (If not overflow) | Conditionally moves a 16-bit, 32-bit, or 64-bit value in memory or a general-purpose register (second operand) into a register (first operand), depending upon the settings of condition flags in the rFLAGS register. If the condition is not satisfied, the destination register is not modified. For the memory-based forms of CMOVcc, memory-related exceptions may be reported even if the condition is false. In 64-bit mode, CMOVcc with a 32-bit operand size will clear the upper 32 bits of the destination register even if the condition is false.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_opcode_count = 1,
                    ._f_opcode_extra = { 0x41 },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CMOV"]
                    }
               }
            } },
                

        { { "cmovc", argtype_t::reg32, argtype_t::regmem32 },
            { 0x0F,
              "cmovc dst, src | Conditional Move (If carry) | Conditionally moves a 16-bit, 32-bit, or 64-bit value in memory or a general-purpose register (second operand) into a register (first operand), depending upon the settings of condition flags in the rFLAGS register. If the condition is not satisfied, the destination register is not modified. For the memory-based forms of CMOVcc, memory-related exceptions may be reported even if the condition is false. In 64-bit mode, CMOVcc with a 32-bit operand size will clear the upper 32 bits of the destination register even if the condition is false.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_opcode_count = 1,
                    ._f_opcode_extra = { 0x42 },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CMOV"]
                    }
               }
            } },
        { { "cmovc", argtype_t::reg64, argtype_t::regmem64 },
            { 0x0F,
              "cmovc dst, src | Conditional Move (If carry) | Conditionally moves a 16-bit, 32-bit, or 64-bit value in memory or a general-purpose register (second operand) into a register (first operand), depending upon the settings of condition flags in the rFLAGS register. If the condition is not satisfied, the destination register is not modified. For the memory-based forms of CMOVcc, memory-related exceptions may be reported even if the condition is false. In 64-bit mode, CMOVcc with a 32-bit operand size will clear the upper 32 bits of the destination register even if the condition is false.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_opcode_count = 1,
                    ._f_opcode_extra = { 0x42 },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CMOV"]
                    }
               }
            } },

                
        { { "cmovnc", argtype_t::reg32, argtype_t::regmem32 },
            { 0x0F,
              "cmovnc dst, src | Conditional Move (If not carry) | Conditionally moves a 16-bit, 32-bit, or 64-bit value in memory or a general-purpose register (second operand) into a register (first operand), depending upon the settings of condition flags in the rFLAGS register. If the condition is not satisfied, the destination register is not modified. For the memory-based forms of CMOVcc, memory-related exceptions may be reported even if the condition is false. In 64-bit mode, CMOVcc with a 32-bit operand size will clear the upper 32 bits of the destination register even if the condition is false.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_opcode_count = 1,
                    ._f_opcode_extra = { 0x43 },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CMOV"]
                    }
               }
            } },
        { { "cmovnc", argtype_t::reg64, argtype_t::regmem64 },
            { 0x0F,
              "cmovc dst, src | Conditional Move (If not carry) | Conditionally moves a 16-bit, 32-bit, or 64-bit value in memory or a general-purpose register (second operand) into a register (first operand), depending upon the settings of condition flags in the rFLAGS register. If the condition is not satisfied, the destination register is not modified. For the memory-based forms of CMOVcc, memory-related exceptions may be reported even if the condition is false. In 64-bit mode, CMOVcc with a 32-bit operand size will clear the upper 32 bits of the destination register even if the condition is false.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_opcode_count = 1,
                    ._f_opcode_extra = { 0x43 },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CMOV"]
                    }
               }
            } },

                
        { { "cmovz", argtype_t::reg32, argtype_t::regmem32 },
            { 0x0F,
              "cmovz dst, src | Conditional Move (If zero) | Conditionally moves a 16-bit, 32-bit, or 64-bit value in memory or a general-purpose register (second operand) into a register (first operand), depending upon the settings of condition flags in the rFLAGS register. If the condition is not satisfied, the destination register is not modified. For the memory-based forms of CMOVcc, memory-related exceptions may be reported even if the condition is false. In 64-bit mode, CMOVcc with a 32-bit operand size will clear the upper 32 bits of the destination register even if the condition is false.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_opcode_count = 1,
                    ._f_opcode_extra = { 0x44 },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CMOV"]
                    }
               }
            } },
        { { "cmovz", argtype_t::reg64, argtype_t::regmem64 },
            { 0x0F,
              "cmovz dst, src | Conditional Move (If zero) | Conditionally moves a 16-bit, 32-bit, or 64-bit value in memory or a general-purpose register (second operand) into a register (first operand), depending upon the settings of condition flags in the rFLAGS register. If the condition is not satisfied, the destination register is not modified. For the memory-based forms of CMOVcc, memory-related exceptions may be reported even if the condition is false. In 64-bit mode, CMOVcc with a 32-bit operand size will clear the upper 32 bits of the destination register even if the condition is false.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_opcode_count = 1,
                    ._f_opcode_extra = { 0x44 },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CMOV"]
                    }
               }
            } },

                
        { { "cmovnz", argtype_t::reg32, argtype_t::regmem32 },
            { 0x0F,
              "cmovnz dst, src | Conditional Move (If not zero) | Conditionally moves a 16-bit, 32-bit, or 64-bit value in memory or a general-purpose register (second operand) into a register (first operand), depending upon the settings of condition flags in the rFLAGS register. If the condition is not satisfied, the destination register is not modified. For the memory-based forms of CMOVcc, memory-related exceptions may be reported even if the condition is false. In 64-bit mode, CMOVcc with a 32-bit operand size will clear the upper 32 bits of the destination register even if the condition is false.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_opcode_count = 1,
                    ._f_opcode_extra = { 0x45 },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CMOV"]
                    }
               }
            } },
        { { "cmovnz", argtype_t::reg64, argtype_t::regmem64 },
            { 0x0F,
              "cmovnz dst, src | Conditional Move (If not zero) | Conditionally moves a 16-bit, 32-bit, or 64-bit value in memory or a general-purpose register (second operand) into a register (first operand), depending upon the settings of condition flags in the rFLAGS register. If the condition is not satisfied, the destination register is not modified. For the memory-based forms of CMOVcc, memory-related exceptions may be reported even if the condition is false. In 64-bit mode, CMOVcc with a 32-bit operand size will clear the upper 32 bits of the destination register even if the condition is false.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_opcode_count = 1,
                    ._f_opcode_extra = { 0x45 },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CMOV"]
                    }
               }
            } },

                
        { { "cmovbe", argtype_t::reg32, argtype_t::regmem32 },
            { 0x0F,
              "cmovbe dst, src | Conditional Move (If below or equal (cf = 1 or zf = 1)) | Conditionally moves a 16-bit, 32-bit, or 64-bit value in memory or a general-purpose register (second operand) into a register (first operand), depending upon the settings of condition flags in the rFLAGS register. If the condition is not satisfied, the destination register is not modified. For the memory-based forms of CMOVcc, memory-related exceptions may be reported even if the condition is false. In 64-bit mode, CMOVcc with a 32-bit operand size will clear the upper 32 bits of the destination register even if the condition is false.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_opcode_count = 1,
                    ._f_opcode_extra = { 0x46 },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CMOV"]
                    }
               }
            } },
        { { "cmovbe", argtype_t::reg64, argtype_t::regmem64 },
            { 0x0F,
              "cmovbe dst, src | Conditional Move (If below or equal (cf = 1 or zf = 1)) | Conditionally moves a 16-bit, 32-bit, or 64-bit value in memory or a general-purpose register (second operand) into a register (first operand), depending upon the settings of condition flags in the rFLAGS register. If the condition is not satisfied, the destination register is not modified. For the memory-based forms of CMOVcc, memory-related exceptions may be reported even if the condition is false. In 64-bit mode, CMOVcc with a 32-bit operand size will clear the upper 32 bits of the destination register even if the condition is false.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_opcode_count = 1,
                    ._f_opcode_extra = { 0x46 },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CMOV"]
                    }
               }
            } },

                
        { { "cmovnbe", argtype_t::reg32, argtype_t::regmem32 },
            { 0x0F,
              "cmovnbe dst, src | Conditional Move (If not below or equal (cf = 0 and zf = 0)) | Conditionally moves a 16-bit, 32-bit, or 64-bit value in memory or a general-purpose register (second operand) into a register (first operand), depending upon the settings of condition flags in the rFLAGS register. If the condition is not satisfied, the destination register is not modified. For the memory-based forms of CMOVcc, memory-related exceptions may be reported even if the condition is false. In 64-bit mode, CMOVcc with a 32-bit operand size will clear the upper 32 bits of the destination register even if the condition is false.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_opcode_count = 1,
                    ._f_opcode_extra = { 0x47 },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CMOV"]
                    }
               }
            } },
        { { "cmovnbe", argtype_t::reg64, argtype_t::regmem64 },
            { 0x0F,
              "cmovnbe dst, src | Conditional Move (If not below or equal (cf = 0 or zf = 0)) | Conditionally moves a 16-bit, 32-bit, or 64-bit value in memory or a general-purpose register (second operand) into a register (first operand), depending upon the settings of condition flags in the rFLAGS register. If the condition is not satisfied, the destination register is not modified. For the memory-based forms of CMOVcc, memory-related exceptions may be reported even if the condition is false. In 64-bit mode, CMOVcc with a 32-bit operand size will clear the upper 32 bits of the destination register even if the condition is false.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_opcode_count = 1,
                    ._f_opcode_extra = { 0x47 },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CMOV"]
                    }
               }
            } },

                
        { { "cmovs", argtype_t::reg32, argtype_t::regmem32 },
            { 0x0F,
              "cmovs dst, src | Conditional Move (If sign (sf = 1)) | Conditionally moves a 16-bit, 32-bit, or 64-bit value in memory or a general-purpose register (second operand) into a register (first operand), depending upon the settings of condition flags in the rFLAGS register. If the condition is not satisfied, the destination register is not modified. For the memory-based forms of CMOVcc, memory-related exceptions may be reported even if the condition is false. In 64-bit mode, CMOVcc with a 32-bit operand size will clear the upper 32 bits of the destination register even if the condition is false.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_opcode_count = 1,
                    ._f_opcode_extra = { 0x48 },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CMOV"]
                    }
               }
            } },
        { { "cmovs", argtype_t::reg64, argtype_t::regmem64 },
            { 0x0F,
              "cmovs dst, src | Conditional Move (If sign (sf = 1)) | Conditionally moves a 16-bit, 32-bit, or 64-bit value in memory or a general-purpose register (second operand) into a register (first operand), depending upon the settings of condition flags in the rFLAGS register. If the condition is not satisfied, the destination register is not modified. For the memory-based forms of CMOVcc, memory-related exceptions may be reported even if the condition is false. In 64-bit mode, CMOVcc with a 32-bit operand size will clear the upper 32 bits of the destination register even if the condition is false.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_opcode_count = 1,
                    ._f_opcode_extra = { 0x48 },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CMOV"]
                    }
               }
            } },

                
        { { "cmovns", argtype_t::reg32, argtype_t::regmem32 },
            { 0x0F,
              "cmovns dst, src | Conditional Move (If not sign (sf = 1)) | Conditionally moves a 16-bit, 32-bit, or 64-bit value in memory or a general-purpose register (second operand) into a register (first operand), depending upon the settings of condition flags in the rFLAGS register. If the condition is not satisfied, the destination register is not modified. For the memory-based forms of CMOVcc, memory-related exceptions may be reported even if the condition is false. In 64-bit mode, CMOVcc with a 32-bit operand size will clear the upper 32 bits of the destination register even if the condition is false.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_opcode_count = 1,
                    ._f_opcode_extra = { 0x49 },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CMOV"]
                    }
               }
            } },
        { { "cmovns", argtype_t::reg64, argtype_t::regmem64 },
            { 0x0F,
              "cmovns dst, src | Conditional Move (If not sign (sf = 1)) | Conditionally moves a 16-bit, 32-bit, or 64-bit value in memory or a general-purpose register (second operand) into a register (first operand), depending upon the settings of condition flags in the rFLAGS register. If the condition is not satisfied, the destination register is not modified. For the memory-based forms of CMOVcc, memory-related exceptions may be reported even if the condition is false. In 64-bit mode, CMOVcc with a 32-bit operand size will clear the upper 32 bits of the destination register even if the condition is false.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_opcode_count = 1,
                    ._f_opcode_extra = { 0x49 },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CMOV"]
                    }
               }
            } },

                
        { { "cmovp", argtype_t::reg32, argtype_t::regmem32 },
            { 0x0F,
              "cmovp dst, src | Conditional Move (If parity (pf = 1)) | Conditionally moves a 16-bit, 32-bit, or 64-bit value in memory or a general-purpose register (second operand) into a register (first operand), depending upon the settings of condition flags in the rFLAGS register. If the condition is not satisfied, the destination register is not modified. For the memory-based forms of CMOVcc, memory-related exceptions may be reported even if the condition is false. In 64-bit mode, CMOVcc with a 32-bit operand size will clear the upper 32 bits of the destination register even if the condition is false.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_opcode_count = 1,
                    ._f_opcode_extra = { 0x4A },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CMOV"]
                    }
               }
            } },
        { { "cmovp", argtype_t::reg64, argtype_t::regmem64 },
            { 0x0F,
              "cmovp dst, src | Conditional Move (If parity (pf = 1)) | Conditionally moves a 16-bit, 32-bit, or 64-bit value in memory or a general-purpose register (second operand) into a register (first operand), depending upon the settings of condition flags in the rFLAGS register. If the condition is not satisfied, the destination register is not modified. For the memory-based forms of CMOVcc, memory-related exceptions may be reported even if the condition is false. In 64-bit mode, CMOVcc with a 32-bit operand size will clear the upper 32 bits of the destination register even if the condition is false.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_opcode_count = 1,
                    ._f_opcode_extra = { 0x4A },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CMOV"]
                    }
               }
            } },

                
        { { "cmovnp", argtype_t::reg32, argtype_t::regmem32 },
            { 0x0F,
              "cmovnp dst, src | Conditional Move (If not parity (pf = 0)) | Conditionally moves a 16-bit, 32-bit, or 64-bit value in memory or a general-purpose register (second operand) into a register (first operand), depending upon the settings of condition flags in the rFLAGS register. If the condition is not satisfied, the destination register is not modified. For the memory-based forms of CMOVcc, memory-related exceptions may be reported even if the condition is false. In 64-bit mode, CMOVcc with a 32-bit operand size will clear the upper 32 bits of the destination register even if the condition is false.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_opcode_count = 1,
                    ._f_opcode_extra = { 0x4B },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CMOV"]
                    }
               }
            } },
        { { "cmovnp", argtype_t::reg64, argtype_t::regmem64 },
            { 0x0F,
              "cmovnp dst, src | Conditional Move (If not parity (pf = 0)) | Conditionally moves a 16-bit, 32-bit, or 64-bit value in memory or a general-purpose register (second operand) into a register (first operand), depending upon the settings of condition flags in the rFLAGS register. If the condition is not satisfied, the destination register is not modified. For the memory-based forms of CMOVcc, memory-related exceptions may be reported even if the condition is false. In 64-bit mode, CMOVcc with a 32-bit operand size will clear the upper 32 bits of the destination register even if the condition is false.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_opcode_count = 1,
                    ._f_opcode_extra = { 0x4B },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CMOV"]
                    }
               }
            } },

                
        { { "cmovl", argtype_t::reg32, argtype_t::regmem32 },
            { 0x0F,
              "cmovl dst, src | Conditional Move (If less (SF != OF)) | Conditionally moves a 16-bit, 32-bit, or 64-bit value in memory or a general-purpose register (second operand) into a register (first operand), depending upon the settings of condition flags in the rFLAGS register. If the condition is not satisfied, the destination register is not modified. For the memory-based forms of CMOVcc, memory-related exceptions may be reported even if the condition is false. In 64-bit mode, CMOVcc with a 32-bit operand size will clear the upper 32 bits of the destination register even if the condition is false.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_opcode_count = 1,
                    ._f_opcode_extra = { 0x4C },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CMOV"]
                    }
               }
            } },
        { { "cmovl", argtype_t::reg64, argtype_t::regmem64 },
            { 0x0F,
              "cmovl dst, src | Conditional Move (If less (SF != OF)) | Conditionally moves a 16-bit, 32-bit, or 64-bit value in memory or a general-purpose register (second operand) into a register (first operand), depending upon the settings of condition flags in the rFLAGS register. If the condition is not satisfied, the destination register is not modified. For the memory-based forms of CMOVcc, memory-related exceptions may be reported even if the condition is false. In 64-bit mode, CMOVcc with a 32-bit operand size will clear the upper 32 bits of the destination register even if the condition is false.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_opcode_count = 1,
                    ._f_opcode_extra = { 0x4C },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CMOV"]
                    }
               }
            } },

                
        { { "cmovge", argtype_t::reg32, argtype_t::regmem32 },
            { 0x0F,
              "cmovge dst, src | Conditional Move (If greater than or equal (SF = OF)) | Conditionally moves a 16-bit, 32-bit, or 64-bit value in memory or a general-purpose register (second operand) into a register (first operand), depending upon the settings of condition flags in the rFLAGS register. If the condition is not satisfied, the destination register is not modified. For the memory-based forms of CMOVcc, memory-related exceptions may be reported even if the condition is false. In 64-bit mode, CMOVcc with a 32-bit operand size will clear the upper 32 bits of the destination register even if the condition is false.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_opcode_count = 1,
                    ._f_opcode_extra = { 0x4D },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CMOV"]
                    }
               }
            } },
        { { "cmovge", argtype_t::reg64, argtype_t::regmem64 },
            { 0x0F,
              "cmovge dst, src | Conditional Move (If greater than or equal (SF = OF)) | Conditionally moves a 16-bit, 32-bit, or 64-bit value in memory or a general-purpose register (second operand) into a register (first operand), depending upon the settings of condition flags in the rFLAGS register. If the condition is not satisfied, the destination register is not modified. For the memory-based forms of CMOVcc, memory-related exceptions may be reported even if the condition is false. In 64-bit mode, CMOVcc with a 32-bit operand size will clear the upper 32 bits of the destination register even if the condition is false.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_opcode_count = 1,
                    ._f_opcode_extra = { 0x4D },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CMOV"]
                    }
               }
            } },

                
        { { "cmovle", argtype_t::reg32, argtype_t::regmem32 },
            { 0x0F,
              "cmovle dst, src | Conditional Move (If less than or equal (ZF = 0 || SF != OF)) | Conditionally moves a 16-bit, 32-bit, or 64-bit value in memory or a general-purpose register (second operand) into a register (first operand), depending upon the settings of condition flags in the rFLAGS register. If the condition is not satisfied, the destination register is not modified. For the memory-based forms of CMOVcc, memory-related exceptions may be reported even if the condition is false. In 64-bit mode, CMOVcc with a 32-bit operand size will clear the upper 32 bits of the destination register even if the condition is false.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_opcode_count = 1,
                    ._f_opcode_extra = { 0x4E },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CMOV"]
                    }
               }
            } },
        { { "cmovle", argtype_t::reg64, argtype_t::regmem64 },
            { 0x0F,
              "cmovle dst, src | Conditional Move (If less than or equal (ZF = 0 || SF != OF)) | Conditionally moves a 16-bit, 32-bit, or 64-bit value in memory or a general-purpose register (second operand) into a register (first operand), depending upon the settings of condition flags in the rFLAGS register. If the condition is not satisfied, the destination register is not modified. For the memory-based forms of CMOVcc, memory-related exceptions may be reported even if the condition is false. In 64-bit mode, CMOVcc with a 32-bit operand size will clear the upper 32 bits of the destination register even if the condition is false.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_opcode_count = 1,
                    ._f_opcode_extra = { 0x4E },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CMOV"]
                    }
               }
            } },

                
        { { "cmovg", argtype_t::reg32, argtype_t::regmem32 },
            { 0x0F,
              "cmovg dst, src | Conditional Move (If greater (ZF = 0 && SF = OF)) | Conditionally moves a 16-bit, 32-bit, or 64-bit value in memory or a general-purpose register (second operand) into a register (first operand), depending upon the settings of condition flags in the rFLAGS register. If the condition is not satisfied, the destination register is not modified. For the memory-based forms of CMOVcc, memory-related exceptions may be reported even if the condition is false. In 64-bit mode, CMOVcc with a 32-bit operand size will clear the upper 32 bits of the destination register even if the condition is false.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_opcode_count = 1,
                    ._f_opcode_extra = { 0x4F },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CMOV"]
                    }
               }
            } },
        { { "cmovg", argtype_t::reg64, argtype_t::regmem64 },
            { 0x0F,
              "cmovg dst, src | Conditional Move (If greater (ZF = 0 && SF = OF)) | Conditionally moves a 16-bit, 32-bit, or 64-bit value in memory or a general-purpose register (second operand) into a register (first operand), depending upon the settings of condition flags in the rFLAGS register. If the condition is not satisfied, the destination register is not modified. For the memory-based forms of CMOVcc, memory-related exceptions may be reported even if the condition is false. In 64-bit mode, CMOVcc with a 32-bit operand size will clear the upper 32 bits of the destination register even if the condition is false.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
               {
                    ._f_opcode_count = 1,
                    ._f_opcode_extra = { 0x4F },

                    ._f_cpuid_reqs = 1,
                    ._f_cpuid_lookups = {
                        &cpu_queries["CMOV"]
                    }
               }
            } },


        { { "cmp",  argtype_t::EAX,      argtype_t::imm32    }, { 0x3D, "cmp a b | Compare | Compares the contents of a register or memory location (first operand) with an immediate value or the contents of a register or memory location(second operand),and sets or clears the status flags in the rFLAGS register to reflect the results.To perform the comparison, the instruction subtracts the second operand from the first operandand sets the status flags in the same manner as the SUB instruction, but does not alter the first operand.If the second operand is an immediate value, the instruction signextends the value to the length of the first operand. Use the CMP instruction to set the condition codes for a subsequent conditional jump(Jcc), conditional move(CMOVcc), or conditional SETcc instruction.Appendix F, \"Instruction Effects on RFLAGS\" shows how instructions affect the rFLAGS status flags." } },
        { { "cmp",  argtype_t::RAX,      argtype_t::imm32    }, { 0x3D, "cmp a b | Compare | Compares the contents of a register or memory location (first operand) with an immediate value or the contents of a register or memory location(second operand),and sets or clears the status flags in the rFLAGS register to reflect the results.To perform the comparison, the instruction subtracts the second operand from the first operandand sets the status flags in the same manner as the SUB instruction, but does not alter the first operand.If the second operand is an immediate value, the instruction signextends the value to the length of the first operand. Use the CMP instruction to set the condition codes for a subsequent conditional jump(Jcc), conditional move(CMOVcc), or conditional SETcc instruction.Appendix F, \"Instruction Effects on RFLAGS\" shows how instructions affect the rFLAGS status flags." } },
        
        { { "cmp",  argtype_t::regmem32, argtype_t::imm32    }, 
            { 0x81, 
              "cmp a b | Compare | Compares the contents of a register or memory location (first operand) with an immediate value or the contents of a register or memory location(second operand),and sets or clears the status flags in the rFLAGS register to reflect the results.To perform the comparison, the instruction subtracts the second operand from the first operandand sets the status flags in the same manner as the SUB instruction, but does not alter the first operand.If the second operand is an immediate value, the instruction signextends the value to the length of the first operand. Use the CMP instruction to set the condition codes for a subsequent conditional jump(Jcc), conditional move(CMOVcc), or conditional SETcc instruction.Appendix F, \"Instruction Effects on RFLAGS\" shows how instructions affect the rFLAGS status flags.",
              opcode_flags_t::regopcode_ext,
              { ._f_regopcode_ext = 7 }
            } },
        { { "cmp",  argtype_t::regmem64, argtype_t::imm32    }, 
            { 0x81, 
              "cmp a b | Compare | Compares the contents of a register or memory location (first operand) with an immediate value or the contents of a register or memory location(second operand),and sets or clears the status flags in the rFLAGS register to reflect the results.To perform the comparison, the instruction subtracts the second operand from the first operandand sets the status flags in the same manner as the SUB instruction, but does not alter the first operand.If the second operand is an immediate value, the instruction signextends the value to the length of the first operand. Use the CMP instruction to set the condition codes for a subsequent conditional jump(Jcc), conditional move(CMOVcc), or conditional SETcc instruction.Appendix F, \"Instruction Effects on RFLAGS\" shows how instructions affect the rFLAGS status flags.",
              opcode_flags_t::regopcode_ext,
              { ._f_regopcode_ext = 7 }
            } },

                
        { { "cmp",  argtype_t::regmem32, argtype_t::imm8    }, 
            { 0x83, 
              "cmp a b | Compare | Compares the contents of a register or memory location (first operand) with an immediate value or the contents of a register or memory location(second operand),and sets or clears the status flags in the rFLAGS register to reflect the results.To perform the comparison, the instruction subtracts the second operand from the first operandand sets the status flags in the same manner as the SUB instruction, but does not alter the first operand.If the second operand is an immediate value, the instruction signextends the value to the length of the first operand. Use the CMP instruction to set the condition codes for a subsequent conditional jump(Jcc), conditional move(CMOVcc), or conditional SETcc instruction.Appendix F, \"Instruction Effects on RFLAGS\" shows how instructions affect the rFLAGS status flags.",
              opcode_flags_t::regopcode_ext,
              { ._f_regopcode_ext = 7 }
            } },
        { { "cmp",  argtype_t::regmem64, argtype_t::imm8    }, 
            { 0x83, 
              "cmp a b | Compare | Compares the contents of a register or memory location (first operand) with an immediate value or the contents of a register or memory location(second operand),and sets or clears the status flags in the rFLAGS register to reflect the results.To perform the comparison, the instruction subtracts the second operand from the first operandand sets the status flags in the same manner as the SUB instruction, but does not alter the first operand.If the second operand is an immediate value, the instruction signextends the value to the length of the first operand. Use the CMP instruction to set the condition codes for a subsequent conditional jump(Jcc), conditional move(CMOVcc), or conditional SETcc instruction.Appendix F, \"Instruction Effects on RFLAGS\" shows how instructions affect the rFLAGS status flags.",
              opcode_flags_t::regopcode_ext,
              { ._f_regopcode_ext = 7 }
            } },

        { { "cmp",  argtype_t::regmem32, argtype_t::reg32    }, { 0x39, "cmp a b | Compare | Compares the contents of a register or memory location (first operand) with an immediate value or the contents of a register or memory location(second operand),and sets or clears the status flags in the rFLAGS register to reflect the results.To perform the comparison, the instruction subtracts the second operand from the first operandand sets the status flags in the same manner as the SUB instruction, but does not alter the first operand.If the second operand is an immediate value, the instruction signextends the value to the length of the first operand. Use the CMP instruction to set the condition codes for a subsequent conditional jump(Jcc), conditional move(CMOVcc), or conditional SETcc instruction.Appendix F, \"Instruction Effects on RFLAGS\" shows how instructions affect the rFLAGS status flags." } },
        { { "cmp",  argtype_t::regmem64, argtype_t::reg64    }, { 0x39, "cmp a b | Compare | Compares the contents of a register or memory location (first operand) with an immediate value or the contents of a register or memory location(second operand),and sets or clears the status flags in the rFLAGS register to reflect the results.To perform the comparison, the instruction subtracts the second operand from the first operandand sets the status flags in the same manner as the SUB instruction, but does not alter the first operand.If the second operand is an immediate value, the instruction signextends the value to the length of the first operand. Use the CMP instruction to set the condition codes for a subsequent conditional jump(Jcc), conditional move(CMOVcc), or conditional SETcc instruction.Appendix F, \"Instruction Effects on RFLAGS\" shows how instructions affect the rFLAGS status flags." } },
        { { "cmp",  argtype_t::reg32,    argtype_t::regmem32 }, { 0x3B, "cmp a b | Compare | Compares the contents of a register or memory location (first operand) with an immediate value or the contents of a register or memory location(second operand),and sets or clears the status flags in the rFLAGS register to reflect the results.To perform the comparison, the instruction subtracts the second operand from the first operandand sets the status flags in the same manner as the SUB instruction, but does not alter the first operand.If the second operand is an immediate value, the instruction signextends the value to the length of the first operand. Use the CMP instruction to set the condition codes for a subsequent conditional jump(Jcc), conditional move(CMOVcc), or conditional SETcc instruction.Appendix F, \"Instruction Effects on RFLAGS\" shows how instructions affect the rFLAGS status flags." } },
        { { "cmp",  argtype_t::reg64,    argtype_t::regmem64 }, { 0x3B, "cmp a b | Compare | Compares the contents of a register or memory location (first operand) with an immediate value or the contents of a register or memory location(second operand),and sets or clears the status flags in the rFLAGS register to reflect the results.To perform the comparison, the instruction subtracts the second operand from the first operandand sets the status flags in the same manner as the SUB instruction, but does not alter the first operand.If the second operand is an immediate value, the instruction signextends the value to the length of the first operand. Use the CMP instruction to set the condition codes for a subsequent conditional jump(Jcc), conditional move(CMOVcc), or conditional SETcc instruction.Appendix F, \"Instruction Effects on RFLAGS\" shows how instructions affect the rFLAGS status flags." } },



        { { "cmpsd" },  { 0xA7, "cmpsd | Compare strings | Compares the bytes, words, doublewords, or quadwords pointed to by the rSI and rDI registers, sets or clears the status flags of the rFLAGS register to reflect the results, and then increments or decrements the rSI and rDI registers according to the state of the DF flag in the rFLAGS register. To perform the comparison, the instruction subtracts the second operand from the first operand and sets the status flags in the same manner as the SUB instruction, but does not alter the first operand. The two operands must be the same size. If the DF flag is 0, the instruction increments rSI and rDI; otherwise, it decrements the pointers. It increments or decrements the pointers by 1, 2, 4, or 8, depending on the size of the operands." } },
        { { "cmpsq" },  { 0xA7, "cmpsd | Compare strings | Compares the bytes, words, doublewords, or quadwords pointed to by the rSI and rDI registers, sets or clears the status flags of the rFLAGS register to reflect the results, and then increments or decrements the rSI and rDI registers according to the state of the DF flag in the rFLAGS register. To perform the comparison, the instruction subtracts the second operand from the first operand and sets the status flags in the same manner as the SUB instruction, but does not alter the first operand. The two operands must be the same size. If the DF flag is 0, the instruction increments rSI and rDI; otherwise, it decrements the pointers. It increments or decrements the pointers by 1, 2, 4, or 8, depending on the size of the operands.", opcode_flags_t::operand64size_override } },

        { { "cmpxchg", argtype_t::regmem32, argtype_t::reg32 },
          {
              0x0F, 
              "cmpxchg cmp rep | Compare and Exchange | Compares the value in the AL, AX, EAX, or RAX register with the value in a register or a memory location (first operand). If the two values are equal, the instruction copies the value in the second operand to the first operand and sets the ZF flag in the rFLAGS register to 1. Otherwise, it copies the value in the first operand to the AL, AX, EAX, or RAX register and clears the ZF flag to 0. The OF, SF, AF, PF, and CF flags are set to reflect the results of the compare. When the first operand is a memory operand, CMPXCHG always does a read-modify-write on the memory operand. If the compared operands were unequal, CMPXCHG writes the same value to the memory operand that was read. The forms of the CMPXCHG instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see \"Lock Prefix\" on page 11.",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0xB1 }
              }
          }
        },
        { { "cmpxchg", argtype_t::regmem64, argtype_t::reg64 },
          {
              0x0F, 
              "cmpxchg cmp rep | Compare and Exchange | Compares the value in the AL, AX, EAX, or RAX register with the value in a register or a memory location (first operand). If the two values are equal, the instruction copies the value in the second operand to the first operand and sets the ZF flag in the rFLAGS register to 1. Otherwise, it copies the value in the first operand to the AL, AX, EAX, or RAX register and clears the ZF flag to 0. The OF, SF, AF, PF, and CF flags are set to reflect the results of the compare. When the first operand is a memory operand, CMPXCHG always does a read-modify-write on the memory operand. If the compared operands were unequal, CMPXCHG writes the same value to the memory operand that was read. The forms of the CMPXCHG instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see \"Lock Prefix\" on page 11.",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0xB1 }
              }
          }
        },

        { { "cmpxchg16b", argtype_t::regmem64 },
          {
              0x0F, 
              "cmpxchg16b cmp rep | Compare and Exchange Sixteen Bytes | Compares the value in the rDX:rAX registers with a 64-bit or 128-bit value in the specified memory location. If the values are equal, the instruction copies the value in the rCX:rBX registers to the memory location and sets the zero flag (ZF) of the rFLAGS register to 1. Otherwise, it copies the value in memory to the rDX:rAX registers and clears ZF to 0.",
              opcode_flags_t::regopcode_ext | opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_regopcode_ext = 1,
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0xC7 },
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["CMPXCHG16B"] }
              }
          }
        },

        { { "cpuid",  argtype_t::unused, argtype_t::unused   }, { 0x0F, 
                                                                  ("Returns information about the processor and its capabilities. EAX specifies the function number, and the data is returned in EAX, EBX, ECX, EDX."), 
                                                                  opcode_flags_t::multibyte_opcode, 0, 
                                                                  1, { 0xA2 } } },


            
        { { "crc32", argtype_t::reg32, argtype_t::regmem32 },
          {
              0xF2, 
              "crc32 dst with | CRC32 Cyclical Redudancy Check | Performs one step of a 32-bit cyclic redundancy check. The first source, which is also the destination, is a doubleword value in either a 32-bit or 64-bit GPR depending on the presence of a REX prefix and the value of the REX.W bit. The second source is a GPR or memory location of width 8, 16, or 32 bits.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_opcode_count = 3,
                ._f_opcode_extra = { 0x0F, 0x38,0xF1 },
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["SSE4.2"] }
              }
          }
        },
        { { "crc32", argtype_t::reg64, argtype_t::regmem64 },
          {
              0xF2, 
              "crc32 dst with | CRC32 Cyclical Redudancy Check | Performs one step of a 32-bit cyclic redundancy check. The first source, which is also the destination, is a doubleword value in either a 32-bit or 64-bit GPR depending on the presence of a REX prefix and the value of the REX.W bit. The second source is a GPR or memory location of width 8, 16, or 32 bits.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_opcode_count = 3,
                ._f_opcode_extra = { 0x0F, 0x38,0xF1 },
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["SSE4.2"] }
              }
          }
        },



        { { "dec", argtype_t::regmem32 },
          {
              0xFF, 
              "dec dst | Decrement by 1 | Subtracts 1 from the specified register or memory location. The CF flag is not affected.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 1
              }
          }
        },
        { { "dec", argtype_t::regmem64 },
          {
              0xFF, 
              "dec dst | Decrement by 1 | Subtracts 1 from the specified register or memory location. The CF flag is not affected.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 1
              }
          }
        },
            
        { { "div", argtype_t::regmem32 },
          {
              0xF7, 
              "div divisor | Unsigned Divide | Perform unsigned division of EDX:EAX by the contents of a 32-bit register or memory location and store the quotient in EAX and the remainder in EDX. ",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 6
              }
          }
        },
        { { "div", argtype_t::regmem64 },
          {
              0xF7,
              "div divisor | Unsigned Divide | Perform unsigned division of RDX:RAX by the contents of a 64-bit register or memory location and store the quotient in RAX and the remainder in RDX. ",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 6
              }
          }
        },
            
        { { "enter", argtype_t::imm64, argtype_t::imm32 },
          {
              0xC8,
              "enter size, nesting | Create Procedure Stack Frame | Creates a stack frame for a procedure. The first operand specifies the size of the stack frame allocated by the instruction. The second operand specifies the nesting level (0 to 31—the value is automatically masked to 5 bits). For nesting levels of 1 or greater, the processor copies earlier stack frame pointers before adjusting the stack pointer. This action provides a called procedure with access points to other nested stack frames.",
          }
        },
            
            
        { { "idiv", argtype_t::regmem32 },
          {
              0xF7, 
              "idiv divisor | Signed Divide | Perform signed division of EDX:EAX by the contents of a 32-bit register or memory location and store the quotient in EAX and the remainder in EDX. To avoid overflow problems, precede this instruction with a CBW, CWD, CDQ, or CQO instruction to sign-extend the dividend.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 7
              }
          }
        },
        { { "idiv", argtype_t::regmem64 },
          {
              0xF7,
              "idiv divisor | Signed Divide | Perform unsigned division of RDX:RAX by the contents of a 64-bit register or memory location and store the quotient in RAX and the remainder in RDX. To avoid overflow problems, precede this instruction with a CBW, CWD, CDQ, or CQO instruction to sign-extend the dividend.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 7
              }
          }
        },
            
            
        { { "imul", argtype_t::regmem32 },
          {
              0xF7, 
              "imul multiplicand | Signed Divide | Multiply the contents of EAX by the contents of a 32-bit memory or register operand and put the signed result in EDX:EAX.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 5
              }
          }
        },
        { { "imul", argtype_t::regmem64 },
          {
              0xF7, 
              "imul multiplicand | Signed Divide | Multiply the contents of RAX by the contents of a 64-bit memory or register operand and put the signed result in RDX:RAX.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 5
              }
          }
        },
            
        { { "inc", argtype_t::regmem32 },
          {
              0xFF, 
              "inc dst | Increment by 1 | Adds 1 to the specified register or memory location. The CF flag is not affected, even if the operand is incremented to 0000.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 0
              }
          }
        },
        { { "inc", argtype_t::regmem64 },
          {
              0xFF, 
              "inc dst | Increment by 1 | Adds 1 to the specified register or memory location. The CF flag is not affected, even if the operand is incremented to 0000.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 0
              }
          }
        },
            
        
        { { "int", argtype_t::imm8 },
          {
              0xCD, 
              "int interrupt_vector_number | Interrupt to Vector | Transfers execution to the interrupt handler specified by an 8-bit unsigned immediate value. This value is an interrupt vector number (00h to FFh), which the processor uses as an index into the interruptdescriptor table (IDT). "
          }
        },
            
        { { "jo", argtype_t::imm32 },
          {
              0x0F, 
              "jo rel32off | Jump if overflow (OF = 1) | If the jump is taken, the signed displacement is added to the rIP (of the following instruction) and the result is truncated to 16, 32, or 64 bits, depending on operand size. In 64-bit mode, the operand size defaults to 64 bits. The processor sign-extends the 8-bit or 32-bit displacement value to 64 bits before adding it to the RIP. ",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x80 }
              }
          }
        },
        { { "jno", argtype_t::imm32 },
          {
              0x0F, 
              "jno rel32off | Jump if not overlflow (OF = 0) | If the jump is taken, the signed displacement is added to the rIP (of the following instruction) and the result is truncated to 16, 32, or 64 bits, depending on operand size. In 64-bit mode, the operand size defaults to 64 bits. The processor sign-extends the 8-bit or 32-bit displacement value to 64 bits before adding it to the RIP. ",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x81 }
              }
          }
        },
        { { "jb", argtype_t::imm32 },
          {
              0x0F,
              "jb rel32off | Jump if below (CF = 1) | If the jump is taken, the signed displacement is added to the rIP (of the following instruction) and the result is truncated to 16, 32, or 64 bits, depending on operand size. In 64-bit mode, the operand size defaults to 64 bits. The processor sign-extends the 8-bit or 32-bit displacement value to 64 bits before adding it to the RIP. ",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x82 }
              }
          }
        },
        { { "jc", argtype_t::imm32 },
          {
              0x0F,
              "jc rel32off | Jump if carry (CF = 1) | If the jump is taken, the signed displacement is added to the rIP (of the following instruction) and the result is truncated to 16, 32, or 64 bits, depending on operand size. In 64-bit mode, the operand size defaults to 64 bits. The processor sign-extends the 8-bit or 32-bit displacement value to 64 bits before adding it to the RIP. ",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x82 }
              }
          }
        },
        { { "jnae", argtype_t::imm32 },
          {
              0x0F,
              "jnae rel32off | Jump if not above or equal (CF = 1) | If the jump is taken, the signed displacement is added to the rIP (of the following instruction) and the result is truncated to 16, 32, or 64 bits, depending on operand size. In 64-bit mode, the operand size defaults to 64 bits. The processor sign-extends the 8-bit or 32-bit displacement value to 64 bits before adding it to the RIP. ",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x82 }
              }
          }
        },
        { { "jb", argtype_t::imm32 },
          {
              0x0F,
              "jb rel32off | Jump if below (CF = 1) | If the jump is taken, the signed displacement is added to the rIP (of the following instruction) and the result is truncated to 16, 32, or 64 bits, depending on operand size. In 64-bit mode, the operand size defaults to 64 bits. The processor sign-extends the 8-bit or 32-bit displacement value to 64 bits before adding it to the RIP. ",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x82 }
              }
          }
        },

        { { "jnb", argtype_t::imm32 },
          {
              0x0F,
              "jnb rel32off | Jump if not below (CF = 0) | If the jump is taken, the signed displacement is added to the rIP (of the following instruction) and the result is truncated to 16, 32, or 64 bits, depending on operand size. In 64-bit mode, the operand size defaults to 64 bits. The processor sign-extends the 8-bit or 32-bit displacement value to 64 bits before adding it to the RIP. ",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x83 }
              }
          }
        },
        { { "jnc", argtype_t::imm32 },
          {
              0x0F,
              "jnc rel32off | Jump if not carry (CF = 0) | If the jump is taken, the signed displacement is added to the rIP (of the following instruction) and the result is truncated to 16, 32, or 64 bits, depending on operand size. In 64-bit mode, the operand size defaults to 64 bits. The processor sign-extends the 8-bit or 32-bit displacement value to 64 bits before adding it to the RIP. ",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x83 }
              }
          }
        },
        { { "jae", argtype_t::imm32 },
          {
              0x0F,
              "jae rel32off | Jump if above or equal (CF = 0) | If the jump is taken, the signed displacement is added to the rIP (of the following instruction) and the result is truncated to 16, 32, or 64 bits, depending on operand size. In 64-bit mode, the operand size defaults to 64 bits. The processor sign-extends the 8-bit or 32-bit displacement value to 64 bits before adding it to the RIP. ",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x83 }
              }
          }
        },

        { { "jz", argtype_t::imm32 },
          {
              0x0F,
              "jz rel32off | Jump if zero (ZF = 1) | If the jump is taken, the signed displacement is added to the rIP (of the following instruction) and the result is truncated to 16, 32, or 64 bits, depending on operand size. In 64-bit mode, the operand size defaults to 64 bits. The processor sign-extends the 8-bit or 32-bit displacement value to 64 bits before adding it to the RIP. ",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x84 }
              }
          }
        },
        { { "je", argtype_t::imm32 },
          {
              0x0F,
              "je rel32off | Jump if equal (ZF = 1) | If the jump is taken, the signed displacement is added to the rIP (of the following instruction) and the result is truncated to 16, 32, or 64 bits, depending on operand size. In 64-bit mode, the operand size defaults to 64 bits. The processor sign-extends the 8-bit or 32-bit displacement value to 64 bits before adding it to the RIP. ",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x84 }
              }
          }
        },

        { { "jnz", argtype_t::imm32 },
          {
              0x0F,
              "jnz rel32off | Jump if not zero (ZF = 0) | If the jump is taken, the signed displacement is added to the rIP (of the following instruction) and the result is truncated to 16, 32, or 64 bits, depending on operand size. In 64-bit mode, the operand size defaults to 64 bits. The processor sign-extends the 8-bit or 32-bit displacement value to 64 bits before adding it to the RIP. ",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x85 }
              }
          }
        },
        { { "jne", argtype_t::imm32 },
          {
              0x0F,
              "jne rel32off | Jump if not equal (ZF = 0) | If the jump is taken, the signed displacement is added to the rIP (of the following instruction) and the result is truncated to 16, 32, or 64 bits, depending on operand size. In 64-bit mode, the operand size defaults to 64 bits. The processor sign-extends the 8-bit or 32-bit displacement value to 64 bits before adding it to the RIP. ",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x85 }
              }
          }
        },

        { { "jbe", argtype_t::imm32 },
          {
              0x0F,
              "jbe rel32off | Jump if below or equal (CF = 1 or ZF = 1) | If the jump is taken, the signed displacement is added to the rIP (of the following instruction) and the result is truncated to 16, 32, or 64 bits, depending on operand size. In 64-bit mode, the operand size defaults to 64 bits. The processor sign-extends the 8-bit or 32-bit displacement value to 64 bits before adding it to the RIP. ",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x86 }
              }
          }
        },
        { { "jna", argtype_t::imm32 },
          {
              0x0F,
              "jna rel32off | Jump if not above (CF = 1 or ZF = 1) | If the jump is taken, the signed displacement is added to the rIP (of the following instruction) and the result is truncated to 16, 32, or 64 bits, depending on operand size. In 64-bit mode, the operand size defaults to 64 bits. The processor sign-extends the 8-bit or 32-bit displacement value to 64 bits before adding it to the RIP. ",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x86 }
              }
          }
        },

        { { "jnbe", argtype_t::imm32 },
          {
              0x0F,
              "jnbe rel32off | Jump if not below or equal (CF = 0 and ZF = 0) | If the jump is taken, the signed displacement is added to the rIP (of the following instruction) and the result is truncated to 16, 32, or 64 bits, depending on operand size. In 64-bit mode, the operand size defaults to 64 bits. The processor sign-extends the 8-bit or 32-bit displacement value to 64 bits before adding it to the RIP. ",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x87 }
              }
          }
        },
        { { "ja", argtype_t::imm32 },
          {
              0x0F,
              "ja rel32off | Jump if above (CF = 0 and ZF = 0) | If the jump is taken, the signed displacement is added to the rIP (of the following instruction) and the result is truncated to 16, 32, or 64 bits, depending on operand size. In 64-bit mode, the operand size defaults to 64 bits. The processor sign-extends the 8-bit or 32-bit displacement value to 64 bits before adding it to the RIP. ",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x87 }
              }
          }
        },

        { { "js", argtype_t::imm32 },
          {
              0x0F,
              "js rel32off | Jump if sign (SF = 1) | If the jump is taken, the signed displacement is added to the rIP (of the following instruction) and the result is truncated to 16, 32, or 64 bits, depending on operand size. In 64-bit mode, the operand size defaults to 64 bits. The processor sign-extends the 8-bit or 32-bit displacement value to 64 bits before adding it to the RIP. ",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x88 }
              }
          }
        },

        { { "jns", argtype_t::imm32 },
          {
              0x0F,
              "jns rel32off | Jump if not sign (SF = 0) | If the jump is taken, the signed displacement is added to the rIP (of the following instruction) and the result is truncated to 16, 32, or 64 bits, depending on operand size. In 64-bit mode, the operand size defaults to 64 bits. The processor sign-extends the 8-bit or 32-bit displacement value to 64 bits before adding it to the RIP. ",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x89 }
              }
          }
        },

        { { "jp", argtype_t::imm32 },
          {
              0x0F,
              "jp rel32off | Jump if parity (PF = 1) | If the jump is taken, the signed displacement is added to the rIP (of the following instruction) and the result is truncated to 16, 32, or 64 bits, depending on operand size. In 64-bit mode, the operand size defaults to 64 bits. The processor sign-extends the 8-bit or 32-bit displacement value to 64 bits before adding it to the RIP. ",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x8A }
              }
          }
        },
        { { "jpe", argtype_t::imm32 },
          {
              0x0F,
              "jpe rel32off | Jump if parity even (PF = 1) | If the jump is taken, the signed displacement is added to the rIP (of the following instruction) and the result is truncated to 16, 32, or 64 bits, depending on operand size. In 64-bit mode, the operand size defaults to 64 bits. The processor sign-extends the 8-bit or 32-bit displacement value to 64 bits before adding it to the RIP. ",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x8A }
              }
          }
        },

        { { "jnp", argtype_t::imm32 },
          {
              0x0F,
              "jnp rel32off | Jump if not parity (PF = 0) | If the jump is taken, the signed displacement is added to the rIP (of the following instruction) and the result is truncated to 16, 32, or 64 bits, depending on operand size. In 64-bit mode, the operand size defaults to 64 bits. The processor sign-extends the 8-bit or 32-bit displacement value to 64 bits before adding it to the RIP. ",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x8B }
              }
          }
        },
        { { "jpo", argtype_t::imm32 },
          {
              0x0F,
              "jpo rel32off | Jump if parity odd (PF = 0) | If the jump is taken, the signed displacement is added to the rIP (of the following instruction) and the result is truncated to 16, 32, or 64 bits, depending on operand size. In 64-bit mode, the operand size defaults to 64 bits. The processor sign-extends the 8-bit or 32-bit displacement value to 64 bits before adding it to the RIP. ",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x8B }
              }
          }
        },

        { { "jl", argtype_t::imm32 },
          {
              0x0F,
              "jl rel32off | Jump if less (SF != OF) | If the jump is taken, the signed displacement is added to the rIP (of the following instruction) and the result is truncated to 16, 32, or 64 bits, depending on operand size. In 64-bit mode, the operand size defaults to 64 bits. The processor sign-extends the 8-bit or 32-bit displacement value to 64 bits before adding it to the RIP. ",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x8C }
              }
          }
        },
        { { "jnge", argtype_t::imm32 },
          {
              0x0F,
              "jnge rel32off | Jump if not greater or equal (SF != OF) | If the jump is taken, the signed displacement is added to the rIP (of the following instruction) and the result is truncated to 16, 32, or 64 bits, depending on operand size. In 64-bit mode, the operand size defaults to 64 bits. The processor sign-extends the 8-bit or 32-bit displacement value to 64 bits before adding it to the RIP. ",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x8C }
              }
          }
        },

        { { "jnl", argtype_t::imm32 },
          {
              0x0F,
              "jnl rel32off | Jump if not less (SF = OF) | If the jump is taken, the signed displacement is added to the rIP (of the following instruction) and the result is truncated to 16, 32, or 64 bits, depending on operand size. In 64-bit mode, the operand size defaults to 64 bits. The processor sign-extends the 8-bit or 32-bit displacement value to 64 bits before adding it to the RIP. ",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x8D }
              }
          }
        },
        { { "jge", argtype_t::imm32 },
          {
              0x0F,
              "jnl rel32off | Jump if greater or equal (SF = OF) | If the jump is taken, the signed displacement is added to the rIP (of the following instruction) and the result is truncated to 16, 32, or 64 bits, depending on operand size. In 64-bit mode, the operand size defaults to 64 bits. The processor sign-extends the 8-bit or 32-bit displacement value to 64 bits before adding it to the RIP. ",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x8D }
              }
          }
        },

        { { "jle", argtype_t::imm32 },
          {
              0x0F,
              "jle rel32off | Jump if less or equal (ZF = 1 or SF != OF) | If the jump is taken, the signed displacement is added to the rIP (of the following instruction) and the result is truncated to 16, 32, or 64 bits, depending on operand size. In 64-bit mode, the operand size defaults to 64 bits. The processor sign-extends the 8-bit or 32-bit displacement value to 64 bits before adding it to the RIP. ",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x8E }
              }
          }
        },
        { { "jng", argtype_t::imm32 },
          {
              0x0F,
              "jng rel32off | Jump if not greater (ZF = 1 or SF != OF) | If the jump is taken, the signed displacement is added to the rIP (of the following instruction) and the result is truncated to 16, 32, or 64 bits, depending on operand size. In 64-bit mode, the operand size defaults to 64 bits. The processor sign-extends the 8-bit or 32-bit displacement value to 64 bits before adding it to the RIP. ",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x8E }
              }
          }
        },

        { { "jnle", argtype_t::imm32 },
          {
              0x0F,
              "jnle rel32off | Jump if not less or equal (ZF = 0 or SF = OF) | If the jump is taken, the signed displacement is added to the rIP (of the following instruction) and the result is truncated to 16, 32, or 64 bits, depending on operand size. In 64-bit mode, the operand size defaults to 64 bits. The processor sign-extends the 8-bit or 32-bit displacement value to 64 bits before adding it to the RIP. ",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x8F }
              }
          }
        },
        { { "jg", argtype_t::imm32 },
          {
              0x0F,
              "jg rel32off | Jump if greater (ZF = 0 or SF = OF) | If the jump is taken, the signed displacement is added to the rIP (of the following instruction) and the result is truncated to 16, 32, or 64 bits, depending on operand size. In 64-bit mode, the operand size defaults to 64 bits. The processor sign-extends the 8-bit or 32-bit displacement value to 64 bits before adding it to the RIP. ",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x8F }
              }
          }
        },

        { { "jrcxz", argtype_t::imm8 },
          {
              0xE3,
              "jrcxz rel8off | Jump if rCX Zero | Checks the contents of the count register (rCX) and, if 0, jumps to the target instruction located at thespecified 8-bit relative offset. Otherwise, execution continues with the instruction following the JrCXZ instruction.",
          }
        },

        { { "jmp", argtype_t::imm32 },
          {
              0xE9,
              "jmp rel32off | Near Jump | Unconditionally transfers control to a new address without saving the current rIP value. This form of the instruction jumps to an address in the current code segment and is called a near jump. The target operand can specify a register, a memory location, or a label.",
          }
        },
        { { "jmp", argtype_t::regmem32 },
          {
              0xFF,
              "jmp off | Near Jump | Unconditionally transfers control to a new address without saving the current rIP value. This form of the instruction jumps to an address in the current code segment and is called a near jump. The target operand can specify a register, a memory location, or a label.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 4
              }
          }
        },

        { { "lahf" },  { 
            0x9f, 
            "lahf | Load Status Flags into AH Register | Loads the lower 8 bits of the rFLAGS register, including sign flag (SF), zero flag (ZF), auxiliary carry flag (AF), parity flag (PF), and carry flag (CF), into the AH register. The instruction sets the reserved bits 1, 3, and 5 of the rFLAGS register to 1, 0, and 0, respectively, in the AH register.",
            opcode_flags_t::requires_cpuid_lookup,
            {
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = {
                    &cpu_queries["LahfSahf"]
                }
            }
        } },


        { { "lea", argtype_t::reg32, argtype_t::regmem32 },
          {
              0x8D,
              "lea dst, src | Load Effective Address | Computes the effective address of a memory location (second operand) and stores it in a generalpurpose register (first operand). "
          }
        },
        { { "lea", argtype_t::reg64, argtype_t::regmem64 },
          {
              0x8D,
              "lea dst, src | Load Effective Address | Computes the effective address of a memory location (second operand) and stores it in a generalpurpose register (first operand). "
          }
        },


        { { "leave" },
          {
              0xC9,
              "leave | Delete Procedure Stack Frame | Releases a stack frame created by a previous ENTER instruction. To release the frame, it copies the frame pointer (in the rBP register) to the stack pointer register (rSP), and then pops the old frame pointer from the stack into the rBP register, thus restoring the stack frame of the calling procedure.  "
          }
        },

        { { "lfence" },
          {
              0xC9,
              "lfence | Load Fence | Acts as a barrier to force strong memory ordering (serialization) between load instructions preceding the LFENCE and load instructions that follow the LFENCE. Loads from differing memory types may be performed out of order, in particular between WC/WC+ and other memory types. The LFENCE instruction assures that the system completes all previous loads before executing subsequent loads.  ",
              opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["SSE2"] }
              }
          }
        },

        { { "lodsq" },
          {
              0xAD,
              "lodsq | Load String | Load quadword at DS:rSI into RAX and then increment or decrement rSI.  "
          }
        },

        { { "loop", argtype_t::imm8 },
          {
              0xE2,
              "loop rel8off | Loop | Decrement rCX, then jump short if rCX is not 0."
          }
        },
        { { "loope", argtype_t::imm8 },
          {
              0xE1,
              "loope rel8off | Loop | Decrement rCX, then jump short if rCX is not 0 and ZF is 1."
          }
        },
        { { "loopne", argtype_t::imm8 },
          {
              0xE0,
              "loopne rel8off | Loop | Decrement rCX, then jump short if rCX is not 0 and ZF is 0."
          }
        },
        { { "loopnz", argtype_t::imm8 },
          {
              0xE0,
              "loopnz rel8off | Loop | Decrement rCX, then jump short if rCX is not 0 and ZF is 0."
          }
        },
        { { "loopz", argtype_t::imm8 },
          {
              0xE1,
              "loopz rel8off | Loop | Decrement rCX, then jump short if rCX is not 0 and ZF is 1."
          }
        },


        { { "lzcnt", argtype_t::reg32, argtype_t::regmem32 },
          {
              0xF3,
              "lzcnt dst, src | Count Leading Zeroes | Counts the number of leading zero bits in the 16-, 32-, or 64-bit general purpose register or memory source operand. Counting starts downward from the most significant bit and stops when the highest bit having a value of 1 is encountered or when the least significant bit is encountered. The count is written to the destination register. This instruction has two operands: LZCNT dest, src If the input operand is zero, CF is set to 1 and the size (in bits) of the input operand is written to the destination register. Otherwise, CF is cleared. If the most significant bit is a one, the ZF flag is set to 1, zero is written to the destination register. Otherwise, ZF is cleared.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_opcode_count = 2,
                ._f_opcode_extra = { 0x0F, 0xBD },
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["ABM"] }
              }
          }
        },
        { { "lzcnt", argtype_t::reg64, argtype_t::regmem64 },
          {
              0xF3,
              "lzcnt dst, src | Count Leading Zeroes | Counts the number of leading zero bits in the 16-, 32-, or 64-bit general purpose register or memory source operand. Counting starts downward from the most significant bit and stops when the highest bit having a value of 1 is encountered or when the least significant bit is encountered. The count is written to the destination register. This instruction has two operands: LZCNT dest, src If the input operand is zero, CF is set to 1 and the size (in bits) of the input operand is written to the destination register. Otherwise, CF is cleared. If the most significant bit is a one, the ZF flag is set to 1, zero is written to the destination register. Otherwise, ZF is cleared.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_opcode_count = 2,
                ._f_opcode_extra = { 0x0F, 0xBD },
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["ABM"] }
              }
          }
        },


        { { "mcommit" },
          {
              0xF3,
              "mcommit | Commit Stores to Memory | MCOMMIT provides a fencing and error detection capability for stores to system memory components that have delayed error reporting. Execution of MCOMMIT ensures that any preceding stores in the thread to such memory components have completed (target locations written, unless inhibited by an error condition) and that any errors encountered by those stores have been signaled to associated error logging resources. If any such errors are present, MCOMMIT will clear rFLAGS.CF to zero, otherwise it will set rFLAGS.CF to one",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_opcode_count = 3,
                ._f_opcode_extra = { 0x0F, 0x01, 0xFA },
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["MCOMMIT"] }
              }
          }
        },


        { { "mfence" },
          {
              0x0F,
              "mfence | Memory Fence | Acts as a barrier to force strong memory ordering (serialization) between load and store instructions preceding the MFENCE, and load and store instructions that follow the MFENCE. The processor may perform loads out of program order with respect to non-conflicting stores for certain memory types. The MFENCE instruction ensures that the system completes all previous memory accesses before executing subsequent accesses. The MFENCE instruction is weakly-ordered with respect to data and instruction prefetches. Speculative loads initiated by the processor, or specified explicitly using cache-prefetch instructions, can be reordered around an MFENCE. ",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_opcode_count = 2,
                ._f_opcode_extra = { 0xAE, 0x0F},
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["SSE2"] }
              }
          }
        },

        { { "monitorx" },
          {
              0x0F,
              "monitorx | Setup Monitor Address | Establishes a linear address range of memory for hardware to monitor and puts the processor in the monitor event pending state. When in the monitor event pending state, the monitoring hardware detects stores to the specified linear address range and causes the processor to exit the monitor event pending state. The MWAIT and MWAITX instructions use the state of the monitor hardware. The address range should be a write-back memory type. Executing MONITORX on an address range for a non-write-back memory type is not guaranteed to cause the processor to enter the monitor event pending state. The size of the linear address range that is established by the MONITORX instruction can be determined by CPUID function 0000_0005h. The rAX register provides the effective address. The DS segment is the default segment used to create the linear address. Segment overrides may be used with the MONITORX instruction. The ECX register specifies optional extensions for the MONITORX instruction. There are currently no extensions defined and setting any bits in ECX will result in a #GP exception. The ECX register operand is implicitly 32-bits. The EDX register specifies optional hints for the MONITORX instruction. There are currently no hints defined and EDX is ignored by the processor. The EDX register operand is implicitly 32-bits.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_opcode_count = 2,
                ._f_opcode_extra = { 0x01, 0xFA},
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["MONITORX"] }
              }
          }
        },

                   
                   
        { { "mov",  argtype_t::regmem32, argtype_t::reg32    }, { 0x89, ("mov dst, src | Move | Move the contents of a 32-bit register to a 32-bit destination register or memory operand") } },
        { { "mov",  argtype_t::regmem64, argtype_t::reg64    }, { 0x89, ("mov dst, src | Move | Move the contents of a 64-bit register to a 64-bit destination register or memory operand") } },
        { { "mov",  argtype_t::reg32,    argtype_t::regmem32 }, { 0x8B, ("mov dst, src | Move | Move the contents of a 32-bit register or memory to a 32-bit destination register") } },
        { { "mov",  argtype_t::reg64,    argtype_t::regmem64 }, { 0x8B, ("mov dst, src | Move | Move the contents of a 64-bit register or memory to a 64-bit destination register") } },
        { { "mov",  argtype_t::reg32,    argtype_t::imm32    }, { 0xB8, ("mov dst, src | Move | Move a 32-bit immediate value into a 32-bit register"), opcode_flags_t::register_adjusted } },
        { { "mov",  argtype_t::reg64,    argtype_t::imm64    }, { 0xB8, ("mov dst, src | Move | Move a 64-bit immediate value into a 64-bit register"), opcode_flags_t::register_adjusted } },
        { { "mov",  argtype_t::regmem32, argtype_t::imm32    }, { 0xC7, ("mov dst, src | Move | Move a 32-bit immediate value into a 32-bit register or memory operand") } },
        { { "mov",  argtype_t::regmem64, argtype_t::imm32    }, { 0xC7, ("mov dst, src | Move | Move a 32-bit immediate value into a 64-bit register or memory operand") } },


        { { "movbe", argtype_t::reg32, argtype_t::regmem32 },
          {
              0x0F,
              "movbe dst, src | Move Big Endian | Loads or stores a general purpose register while swapping the byte order. Operates on 16-bit, 32-bit, or 64-bit values. Converts big-endian formatted memory data to little-endian format when loading a register and reverses the conversion when storing a GPR to memory.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_opcode_count = 2,
                ._f_opcode_extra = { 0x38, 0xF0 },
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["MOVBE"] }
              }
          }
        },
        { { "movbe", argtype_t::reg64, argtype_t::regmem64 },
          {
              0x0F,
              "movbe dst, src | Move Big Endian | Loads or stores a general purpose register while swapping the byte order. Operates on 16-bit, 32-bit, or 64-bit values. Converts big-endian formatted memory data to little-endian format when loading a register and reverses the conversion when storing a GPR to memory.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_opcode_count = 2,
                ._f_opcode_extra = { 0x38, 0xF0 },
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["MOVBE"] }
              }
          }
        },
        { { "movbe", argtype_t::regmem32, argtype_t::reg32 },
          {
              0x0F,
              "movbe dst, src | Move Big Endian | Loads or stores a general purpose register while swapping the byte order. Operates on 16-bit, 32-bit, or 64-bit values. Converts big-endian formatted memory data to little-endian format when loading a register and reverses the conversion when storing a GPR to memory.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_opcode_count = 2,
                ._f_opcode_extra = { 0x38, 0xF1 },
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["MOVBE"] }
              }
          }
        },
        { { "movbe", argtype_t::regmem64, argtype_t::reg64 },
          {
              0x0F,
              "movbe dst, src | Move Big Endian | Loads or stores a general purpose register while swapping the byte order. Operates on 16-bit, 32-bit, or 64-bit values. Converts big-endian formatted memory data to little-endian format when loading a register and reverses the conversion when storing a GPR to memory.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_opcode_count = 2,
                ._f_opcode_extra = { 0x38, 0xF1 },
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["MOVBE"] }
              }
          }
        },

        { { "movd", argtype_t::reg32, argtype_t::regmem32 },
          {
              0x66,
              "movd xmm, src_regmem | Move Doubleword or Quadword | Move 32-bit value from a general-purpose register or 32-bit memory location to an XMM register (low 32, 0-extend to 128).",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_opcode_count = 2,
                ._f_opcode_extra = { 0x0F, 0x6E },
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["SSE2"] }
              }
          }
        },
        { { "movd", argtype_t::reg64, argtype_t::regmem64 },
          {
              0x66,
              "movd xmm, src_regmem | Move Doubleword or Quadword | Move 64-bit value from a general-purpose register or 64-bit memory location to an XMM register (low 64, 0-extend to 128).",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_opcode_count = 2,
                ._f_opcode_extra = { 0x0F, 0x6E },
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["SSE2"] }
              }
          }
        },

        { { "movd", argtype_t::regmem32, argtype_t::reg32 },
          {
              0x66,
              "movd dst_regmem, xmm | Move Doubleword or Quadword | Move 32-bit value from an XMM register to a 32-bit general-purpose register or memory location (low 32).",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_opcode_count = 2,
                ._f_opcode_extra = { 0x0F, 0x7E },
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["SSE2"] }
              }
          }
        },
        { { "movd", argtype_t::regmem64, argtype_t::reg64 },
          {
              0x66,
              "movd dst_regmem, xmm | Move Doubleword or Quadword | Move 64-bit value from an XMM register to a 32-bit general-purpose register or memory location (low 64).",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_opcode_count = 2,
                ._f_opcode_extra = { 0x0F, 0x7E },
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["SSE2"] }
              }
          }
        },


        { { "movmskpd", argtype_t::regmem32, argtype_t::reg32 },
          {
              0x66,
              "movmskpd reg32, xmm | Extract Packed Double-Precision Floating-Point Sign Mask | Moves the sign bits of two packed double-precision floating-point values in an XMM register (second operand) to the two low-order bits of a general-purpose register (first operand) with zero-extension.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_opcode_count = 2,
                ._f_opcode_extra = { 0x0F, 0x50 },
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["SSE2"] }
              }
          }
        },
        { { "movmskps", argtype_t::regmem32, argtype_t::reg32 },
          {
              0x0F,
              "movmskps reg32, xmm | Extract Packed Single-Precision Floating-Point Sign Mask | Moves the sign bits of two packed single-precision floating-point values in an XMM register (second operand) to the two low-order bits of a general-purpose register (first operand) with zero-extension.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x50 },
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["SSE2"] }
              }
          }
        },

        { { "movnti", argtype_t::mem32, argtype_t::reg32 },
          {
              0x0F,
              "movnti mem, reg | Stores a value in a 32-bit or 64-bit general-purpose register (second operand) in a memory location (first operand). This instruction indicates to the processor that the data is non-temporal and is unlikely to be used again soon. The processor treats the store as a write-combining (WC) memory write, which minimizes cache pollution. The exact method by which cache pollution is minimized depends on the hardware implementation of the instruction. For further information, see \"Memory Optimization\" in Volume 1. The MOVNTI instruction is weakly-ordered with respect to other instructions that operate on memory. Software should use an SFENCE instruction to force strong memory ordering of MOVNTI with respect to other stores.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0xC3 },
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["SSE2"] }
              }
          }
        },
        { { "movnti", argtype_t::mem64, argtype_t::reg64 },
          {
              0x0F,
              "movnti mem, reg | Stores a value in a 32-bit or 64-bit general-purpose register (second operand) in a memory location (first operand). This instruction indicates to the processor that the data is non-temporal and is unlikely to be used again soon. The processor treats the store as a write-combining (WC) memory write, which minimizes cache pollution. The exact method by which cache pollution is minimized depends on the hardware implementation of the instruction. For further information, see \"Memory Optimization\" in Volume 1. The MOVNTI instruction is weakly-ordered with respect to other instructions that operate on memory. Software should use an SFENCE instruction to force strong memory ordering of MOVNTI with respect to other stores.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0xC3 },
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["SSE2"] }
              }
          }
        },

        { { "movsx", argtype_t::reg32, argtype_t::imm8 },
          {
              0x0F,
              "movsx reg imm8 | Move with Sign-Extension | Copies the value in a register or memory location (second operand) into a register (first operand), extending the most significant bit of an 8-bit or 16-bit value into all higher bits in a 16-bit, 32-bit, or 64-bit register.",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0xBE }
              }
          }
        },
        { { "movsx", argtype_t::reg64, argtype_t::imm8 },
          {
              0x0F,
              "movsx reg imm8 | Move with Sign-Extension | Copies the value in a register or memory location (second operand) into a register (first operand), extending the most significant bit of an 8-bit or 16-bit value into all higher bits in a 16-bit, 32-bit, or 64-bit register.",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0xBE }
              }
          }
        },
        { { "movsxd", argtype_t::reg64, argtype_t::regmem32 },
          {
              0x63,
              "movsxd reg imm8 | Move with Sign-Extension Doubleword | Move the contents of a 32-bit register or memory operand to a 64-bit register with sign extension."
          }
        },
            
        { { "movzx", argtype_t::reg32, argtype_t::imm8 },
          {
              0x0F,
              "movsx reg imm8 | Move with Zero-Extension | Copies the value in a register or memory location (second operand) into a register (first operand), extending 0 into all higher bits in a 16-bit, 32-bit, or 64-bit register.",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0xB6 }
              }
          }
        },
        { { "movzx", argtype_t::reg64, argtype_t::imm8 },
          {
              0x0F,
              "movsx reg imm8 | Move with Zero-Extension | Copies the value in a register or memory location (second operand) into a register (first operand), extending 0 into all higher bits in a 16-bit, 32-bit, or 64-bit register.",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0xB6 }
              }
          }
        },


        { { "mul", argtype_t::regmem32 },
          {
              0xF7,
              "mul multiplicand | Unsigned Multiply | Multiplies a 32-bit register or memory operand by the contents of the EAX register and stores the result in the EDX:EAX register.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 4
              }
          }
        },
        { { "mul", argtype_t::regmem64 },
          {
              0xF7,
              "mul multiplicand | Unsigned Multiply | Multiplies a 32-bit register or memory operand by the contents of the EAX register and stores the result in the EDX:EAX register.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 4
              }
          }
        },


        { { "mulx", argtype_t::reg32, argtype_t::reg32, argtype_t::regmem32 },
          {
              0xF6,
              "mulx dest1, dest2, src | Multiply Unsigned | Multiplies a 32-bit register or memory operand by the contents of the EAX register and stores the result in the EDX:EAX register.",
              opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::vex_extended,
              {
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["BMI2"] },
                ._f_vex0 = vex0_t::VEX_3byte,
                ._f_vex1 = {
                    .map_select = 2
                },
                ._f_vex2 = {
                    .pp = 0b11,
                    .L = 0,
                    .w = 0
                },
                ._f_vex_vvvv_arg = 1
              }
          }
        },
        { { "mulx", argtype_t::reg64, argtype_t::reg64, argtype_t::regmem64 },
          {
              0xF6,
              "mulx dest1, dest2, src | Multiply Unsigned | Multiplies a 32-bit register or memory operand by the contents of the EAX register and stores the result in the EDX:EAX register.",
              opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::vex_extended,
              {
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["BMI2"] },
                ._f_vex0 = vex0_t::VEX_3byte,
                ._f_vex1 = {
                    .map_select = 2
                },
                ._f_vex2 = {
                    .pp = 0b11,
                    .L = 0,
                    .w = 1
                },
                ._f_vex_vvvv_arg = 1
              }
          }
        },

        { { "neg", argtype_t::regmem32 },
          {
              0xF7,
              "neg reg | Two's Complement Negation | Performs the two’s complement negation of the value in the specified register or memory location by subtracting the value from 0. Use this instruction only on signed integer numbers. If the value is 0, the instruction clears the CF flag to 0; otherwise, it sets CF to 1. The OF, SF, ZF, AF, and PF flag settings depend on the result of the operation. The forms of the NEG instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see \"Lock Prefix\" on page 11.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 3
              }
          }
        },
        { { "neg", argtype_t::regmem64 },
          {
              0xF7,
              "neg reg | Two's Complement Negation | Performs the two’s complement negation of the value in the specified register or memory location by subtracting the value from 0. Use this instruction only on signed integer numbers. If the value is 0, the instruction clears the CF flag to 0; otherwise, it sets CF to 1. The OF, SF, ZF, AF, and PF flag settings depend on the result of the operation. The forms of the NEG instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see \"Lock Prefix\" on page 11.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 3
              }
          }
        },

        { { "nop" },
          {
              0x90,
              "nop | No Operation | Performs no operation."
          }
        },


        { { "not", argtype_t::regmem32 },
          {
              0xF7,
              "not reg | Ones's Complement Negation | Performs the one’s complement negation of the value in the specified register or memory location byinverting each bit of the value. The memory-operand forms of the NOT instruction support the LOCK prefix. For details about the LOCK prefix, see \"Lock Prefix\" on page 11. ",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 2
              }
          }
        },
        { { "not", argtype_t::regmem64 },
          {
              0xF7,
              "not reg | Ones's Complement Negation | Performs the one’s complement negation of the value in the specified register or memory location byinverting each bit of the value. The memory-operand forms of the NOT instruction support the LOCK prefix. For details about the LOCK prefix, see \"Lock Prefix\" on page 11. ",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 2
              }
          }
        },


        { { "or",  argtype_t::EAX,      argtype_t::imm32    }, { 0x0D, ("or dst, src | Logical OR | Performs a logical or on the bits in a register, memory location, or immediate value (second operand)and a register or memory location (first operand) and stores the result in the first operand location. The two operands cannot both be memory locations. If both corresponding bits are 0, the corresponding bit of the result is 0; otherwise, the corresponding result bit is 1. The forms of the OR instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see \"Lock Prefix\" on page 11. ") } },
        { { "or",  argtype_t::RAX,      argtype_t::imm32    }, { 0x0D, ("or dst, src | Logical OR | Performs a logical or on the bits in a register, memory location, or immediate value (second operand)and a register or memory location (first operand) and stores the result in the first operand location. The two operands cannot both be memory locations. If both corresponding bits are 0, the corresponding bit of the result is 0; otherwise, the corresponding result bit is 1. The forms of the OR instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see \"Lock Prefix\" on page 11. ") } },
        { { "or",  argtype_t::regmem32, argtype_t::imm32    }, { 0x81, ("or dst, src | Logical OR | Performs a logical or on the bits in a register, memory location, or immediate value (second operand)and a register or memory location (first operand) and stores the result in the first operand location. The two operands cannot both be memory locations. If both corresponding bits are 0, the corresponding bit of the result is 0; otherwise, the corresponding result bit is 1. The forms of the OR instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see \"Lock Prefix\" on page 11. "), opcode_flags_t::regopcode_ext, {._f_regopcode_ext = 1 } } },
        { { "or",  argtype_t::regmem64, argtype_t::imm32    }, { 0x81, ("or dst, src | Logical OR | Performs a logical or on the bits in a register, memory location, or immediate value (second operand)and a register or memory location (first operand) and stores the result in the first operand location. The two operands cannot both be memory locations. If both corresponding bits are 0, the corresponding bit of the result is 0; otherwise, the corresponding result bit is 1. The forms of the OR instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see \"Lock Prefix\" on page 11. "), opcode_flags_t::regopcode_ext, {._f_regopcode_ext = 1 } } },
        { { "or",  argtype_t::regmem32, argtype_t::imm8     }, { 0x83, ("or dst, src | Logical OR | Performs a logical or on the bits in a register, memory location, or immediate value (second operand)and a register or memory location (first operand) and stores the result in the first operand location. The two operands cannot both be memory locations. If both corresponding bits are 0, the corresponding bit of the result is 0; otherwise, the corresponding result bit is 1. The forms of the OR instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see \"Lock Prefix\" on page 11. "), opcode_flags_t::regopcode_ext, {._f_regopcode_ext = 1 } } },
        { { "or",  argtype_t::regmem64, argtype_t::imm8     }, { 0x83, ("or dst, src | Logical OR | Performs a logical or on the bits in a register, memory location, or immediate value (second operand)and a register or memory location (first operand) and stores the result in the first operand location. The two operands cannot both be memory locations. If both corresponding bits are 0, the corresponding bit of the result is 0; otherwise, the corresponding result bit is 1. The forms of the OR instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see \"Lock Prefix\" on page 11. "), opcode_flags_t::regopcode_ext, {._f_regopcode_ext = 1 } } },
        { { "or",  argtype_t::regmem32, argtype_t::reg32    }, { 0x09, ("or dst, src | Logical OR | Performs a logical or on the bits in a register, memory location, or immediate value (second operand)and a register or memory location (first operand) and stores the result in the first operand location. The two operands cannot both be memory locations. If both corresponding bits are 0, the corresponding bit of the result is 0; otherwise, the corresponding result bit is 1. The forms of the OR instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see \"Lock Prefix\" on page 11. ") } },
        { { "or",  argtype_t::regmem64, argtype_t::reg64    }, { 0x09, ("or dst, src | Logical OR | Performs a logical or on the bits in a register, memory location, or immediate value (second operand)and a register or memory location (first operand) and stores the result in the first operand location. The two operands cannot both be memory locations. If both corresponding bits are 0, the corresponding bit of the result is 0; otherwise, the corresponding result bit is 1. The forms of the OR instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see \"Lock Prefix\" on page 11. ") } },
        { { "or",  argtype_t::reg32,    argtype_t::regmem32 }, { 0x0B, ("or dst, src | Logical OR | Performs a logical or on the bits in a register, memory location, or immediate value (second operand)and a register or memory location (first operand) and stores the result in the first operand location. The two operands cannot both be memory locations. If both corresponding bits are 0, the corresponding bit of the result is 0; otherwise, the corresponding result bit is 1. The forms of the OR instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see \"Lock Prefix\" on page 11. ") } },
        { { "or",  argtype_t::reg64,    argtype_t::regmem64 }, { 0x0B, ("or dst, src | Logical OR | Performs a logical or on the bits in a register, memory location, or immediate value (second operand)and a register or memory location (first operand) and stores the result in the first operand location. The two operands cannot both be memory locations. If both corresponding bits are 0, the corresponding bit of the result is 0; otherwise, the corresponding result bit is 1. The forms of the OR instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see \"Lock Prefix\" on page 11. ") } },


        { { "pause" },
          {
              0xF3,
              "pause | Pause | Improves the performance of spin loops, by providing a hint to the processor that the current code is in a spin loop. The processor may use this to optimize power consumption while in the spin loop. Architecturally, this instruction behaves like a NOP instruction. Processors that do not support PAUSE treat this opcode as a NOP instruction.",
              opcode_flags_t::multibyte_opcode,
              {
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x90 }
              }
          }
        },

        { { "pdep", argtype_t::reg32, argtype_t::reg32, argtype_t::regmem32 },
          {
              0xF5,
              "pdep dest, src, mask | Parallel Deposit Bits | Scatters consecutive bits of the first source operand, starting at the least significant bit, to bit positions in the destination as specified by 1 bits in the second source operand (mask). Bit positions in the destination corresponding to 0 bits in the mask are cleared.",
              opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::vex_extended,
              {
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["BMI2"] },
                ._f_vex0 = vex0_t::VEX_3byte,
                ._f_vex1 = {
                    .map_select = 2
                },
                ._f_vex2 = {
                    .pp = 0b11,
                    .L = 0,
                    .w = 0
                },
                ._f_vex_vvvv_arg = 1
              }
          }
        },
        { { "pdep", argtype_t::reg64, argtype_t::reg64, argtype_t::regmem64 },
          {
              0xF5,
              "pdep dest, src, mask | Parallel Deposit Bits | Scatters consecutive bits of the first source operand, starting at the least significant bit, to bit positions in the destination as specified by 1 bits in the second source operand (mask). Bit positions in the destination corresponding to 0 bits in the mask are cleared.",
              opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::vex_extended,
              {
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["BMI2"] },
                ._f_vex0 = vex0_t::VEX_3byte,
                ._f_vex1 = {
                    .map_select = 2
                },
                ._f_vex2 = {
                    .pp = 0b11,
                    .L = 0,
                    .w = 1
                },
                ._f_vex_vvvv_arg = 1
              }
          }
        },


        { { "pext", argtype_t::reg32, argtype_t::reg32, argtype_t::regmem32 },
          {
              0xF5,
              "pdep dest, src, mask | Parallel Extract Bits | Copies bits from the source operand, based on a mask, and packs them into the low-order bits of the destination. Clears all bits in the destination to the left of the most-significant bit copied.",
              opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::vex_extended,
              {
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["BMI2"] },
                ._f_vex0 = vex0_t::VEX_3byte,
                ._f_vex1 = {
                    .map_select = 2
                },
                ._f_vex2 = {
                    .pp = 0b10,
                    .L = 0,
                    .w = 0
                },
                ._f_vex_vvvv_arg = 1
              }
          }
        },
        { { "pext", argtype_t::reg64, argtype_t::reg64, argtype_t::regmem64 },
          {
              0xF5,
              "pdep dest, src, mask | Parallel Extract Bits | Copies bits from the source operand, based on a mask, and packs them into the low-order bits of the destination. Clears all bits in the destination to the left of the most-significant bit copied.",
              opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::vex_extended,
              {
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["BMI2"] },
                ._f_vex0 = vex0_t::VEX_3byte,
                ._f_vex1 = {
                    .map_select = 2
                },
                ._f_vex2 = {
                    .pp = 0b10,
                    .L = 0,
                    .w = 1
                },
                ._f_vex_vvvv_arg = 1
              }
          }
        },


        { { "pop",  argtype_t::regmem64, argtype_t::unused   }, { 0x8F, ("Pop the top of the stack into a 64-bit register or memory.") } },
        { { "pop",  argtype_t::reg64,    argtype_t::unused   }, { 0x58, ("Pop the top of the stack into a 64-bit register."), opcode_flags_t::register_adjusted } },
        { { "pop",  argtype_t::regmem32, argtype_t::unused   }, { 0x8F, ("Pop the top of the stack into a 64-bit register or memory."), opcode_flags_t::operand64size_override } },
        { { "pop",  argtype_t::reg32,    argtype_t::unused   }, { 0x58, ("Pop the top of the stack into a 64-bit register."), opcode_flags_t::register_adjusted | opcode_flags_t::operand64size_override } },
            
            
        { { "popcnt", argtype_t::reg32, argtype_t::regmem32 },
          {
              0xF3,
              "popcnt dst, src | Bit Population Count | Counts the number of bits having a value of 1 in the source operand and places the result in the destination register. The source operand is a 16-, 32-, or 64-bit general purpose register or memory operand; the destination operand is a general purpose register of the same size as the source operand register. If the input operand is zero, the ZF flag is set to 1 and zero is written to the destination register. Otherwise, the ZF flag is cleared. The other flags are cleared.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_opcode_count = 2,
                ._f_opcode_extra = { 0x0F, 0xB8 },
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["POPCNT"] }
              }
          }
        },

        { { "popfq" }, { 0x9D, ("Pop a quadword from the stack to the RFLAGS register"), opcode_flags_t::operand64size_override } },

        { { "prefetch", argtype_t::mem64 },
          {
              0x0F,
              "prefetch mem | Prefetch L1 Data-Cache Line | Loads the entire 64-byte aligned memory sequence containing the specified memory address into theL1 data cache. The position of the specified memory address within the 64-byte cache line is irrelevant. If a cache hit occurs, or if a memory fault is detected, no bus cycle is initiated and the instruction is treated as a NOP. The PREFETCHW instruction loads the prefetched line and sets the cache-line state to Modified, in anticipation of subsequent data writes to the line. The PREFETCH instruction, by contrast, typically sets the cache-line state to Exclusive (depending on the hardware implementation). ",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::regopcode_ext | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_regopcode_ext = 0,
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x0D },
                ._f_cpuid_reqs = 3,
                ._f_cpuid_lookups = { &cpu_queries["3DNowPrefetch"], &cpu_queries["LM"], &cpu_queries["3DNow"] }
              }
          }
        },
        { { "prefetchw", argtype_t::mem64 },
          {
              0x0F,
              "prefetchw mem | Prefetch L1 Data-Cache Line | Loads the entire 64-byte aligned memory sequence containing the specified memory address into theL1 data cache. The position of the specified memory address within the 64-byte cache line is irrelevant. If a cache hit occurs, or if a memory fault is detected, no bus cycle is initiated and the instruction is treated as a NOP. The PREFETCHW instruction loads the prefetched line and sets the cache-line state to Modified, in anticipation of subsequent data writes to the line. The PREFETCH instruction, by contrast, typically sets the cache-line state to Exclusive (depending on the hardware implementation). ",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::regopcode_ext | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_regopcode_ext = 1,
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x0D },
                ._f_cpuid_reqs = 3,
                ._f_cpuid_lookups = { &cpu_queries["3DNowPrefetch"], &cpu_queries["LM"], &cpu_queries["3DNow"] }
              }
          }
        },

        { { "prefetchnta", argtype_t::mem64 },
          {
              0x0F,
              "prefetchnta mem | Prefetch Data to Cache Level NTA | Loads a cache line from the specified memory address into the data-cache level specified by the locality reference bits 5:3 of the ModRM byte. Table 3-3 on page 279 lists the locality reference options for the instruction. This instruction loads a cache line even if the mem8 address is not aligned with the start of the line. If the cache line is already contained in a cache level that is lower than the specified locality reference, or if a memory fault is detected, a bus cycle is not initiated and the instruction is treated as a NOP. The operation of this instruction is implementation-dependent. The processor implementation can ignore or change this instruction. The size of the cache line also depends on the implementation, with a minimum size of 32 bytes. AMD processors alias PREFETCH1 and PREFETCH2 to PREFETCH0. For details on the use of this instruction, see the software-optimization documentation relating to particular hardware implementations. ",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::regopcode_ext | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_regopcode_ext = 0,
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x18 },
                ._f_cpuid_reqs = 3,
                ._f_cpuid_lookups = { &cpu_queries["3DNowPrefetch"], &cpu_queries["LM"], &cpu_queries["3DNow"] }
              }
          }
        },
        { { "prefetcht0", argtype_t::mem64 },
          {
              0x0F,
              "prefetchnta mem | Prefetch Data to Cache Level NTA | Loads a cache line from the specified memory address into the data-cache level specified by the locality reference bits 5:3 of the ModRM byte. Table 3-3 on page 279 lists the locality reference options for the instruction. This instruction loads a cache line even if the mem8 address is not aligned with the start of the line. If the cache line is already contained in a cache level that is lower than the specified locality reference, or if a memory fault is detected, a bus cycle is not initiated and the instruction is treated as a NOP. The operation of this instruction is implementation-dependent. The processor implementation can ignore or change this instruction. The size of the cache line also depends on the implementation, with a minimum size of 32 bytes. AMD processors alias PREFETCH1 and PREFETCH2 to PREFETCH0. For details on the use of this instruction, see the software-optimization documentation relating to particular hardware implementations. ",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::regopcode_ext | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_regopcode_ext = 1,
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x18 },
                ._f_cpuid_reqs = 3,
                ._f_cpuid_lookups = { &cpu_queries["3DNowPrefetch"], &cpu_queries["LM"], &cpu_queries["3DNow"] }
              }
          }
        },
        { { "prefetcht1", argtype_t::mem64 },
          {
              0x0F,
              "prefetchnta mem | Prefetch Data to Cache Level NTA | Loads a cache line from the specified memory address into the data-cache level specified by the locality reference bits 5:3 of the ModRM byte. Table 3-3 on page 279 lists the locality reference options for the instruction. This instruction loads a cache line even if the mem8 address is not aligned with the start of the line. If the cache line is already contained in a cache level that is lower than the specified locality reference, or if a memory fault is detected, a bus cycle is not initiated and the instruction is treated as a NOP. The operation of this instruction is implementation-dependent. The processor implementation can ignore or change this instruction. The size of the cache line also depends on the implementation, with a minimum size of 32 bytes. AMD processors alias PREFETCH1 and PREFETCH2 to PREFETCH0. For details on the use of this instruction, see the software-optimization documentation relating to particular hardware implementations. ",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::regopcode_ext | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_regopcode_ext = 2,
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x18 },
                ._f_cpuid_reqs = 3,
                ._f_cpuid_lookups = { &cpu_queries["3DNowPrefetch"], &cpu_queries["LM"], &cpu_queries["3DNow"] }
              }
          }
        },
        { { "prefetcht2", argtype_t::mem64 },
          {
              0x0F,
              "prefetchnta mem | Prefetch Data to Cache Level NTA | Loads a cache line from the specified memory address into the data-cache level specified by the locality reference bits 5:3 of the ModRM byte. Table 3-3 on page 279 lists the locality reference options for the instruction. This instruction loads a cache line even if the mem8 address is not aligned with the start of the line. If the cache line is already contained in a cache level that is lower than the specified locality reference, or if a memory fault is detected, a bus cycle is not initiated and the instruction is treated as a NOP. The operation of this instruction is implementation-dependent. The processor implementation can ignore or change this instruction. The size of the cache line also depends on the implementation, with a minimum size of 32 bytes. AMD processors alias PREFETCH1 and PREFETCH2 to PREFETCH0. For details on the use of this instruction, see the software-optimization documentation relating to particular hardware implementations. ",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::regopcode_ext | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_regopcode_ext = 3,
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0x18 },
                ._f_cpuid_reqs = 3,
                ._f_cpuid_lookups = { &cpu_queries["3DNowPrefetch"], &cpu_queries["LM"], &cpu_queries["3DNow"] }
              }
          }
        },

        { { "push", argtype_t::regmem32, }, { 0xFF, ("Push the contents of a 32-bit register or memory operand onto the stack (No prefix for encoding this in 64-bit mode)."), opcode_flags_t::regopcode_ext | opcode_flags_t::operand64size_override, {._f_regopcode_ext = 6 } } },
        { { "push", argtype_t::regmem64, }, { 0xFF, ("Push the contents of a 64-bit register or memory operand onto the stack."), opcode_flags_t::regopcode_ext, { ._f_regopcode_ext = 6 } } },
        { { "push", argtype_t::reg64,    }, { 0x50, ("Push the contents of a 64-bit register onto the stack."), opcode_flags_t::register_adjusted } },
        { { "push", argtype_t::imm32,    }, { 0x68, ("Push a sign-extended 32-bit immediate value onto the stack.") } },

        { { "pushfq" }, { 0x9C, ("Decrements the rSP register and copies the rFLAGS register (except for the VM and RF flags) onto the stack. The instruction clears the VM and RF flags in the rFLAGS image before putting it on the stack."), opcode_flags_t::operand64size_override } },

        { { "rcl", argtype_t::regmem32 }, 
          { 
              0xD1, 
              "rcl dst, 1 | Rotate Through Carry Left | Rotate the 33 bits consisting of the carry flag and a 32-bit register or memory location left 1 bit.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 2
              }
          } 
        },
        { { "rcl", argtype_t::regmem32, argtype_t::imm8 }, 
          { 
              0xC1, 
              "rcl dst, imm8 | Rotate Through Carry Left | Rotate the 33 bits consisting of the carry flag and a 32-bit register or memory location left the number of bits specified by an 8-bit immediate value.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 2
              }
          } 
        },
        { { "rcl", argtype_t::regmem64 },
          {
              0xD1,
              "rcl dst, 1 | Rotate Through Carry Left | Rotate the 33 bits consisting of the carry flag and a 32-bit register or memory location left 1 bit.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 2
              }
          }
        },
        { { "rcl", argtype_t::regmem64, argtype_t::imm8 },
          {
              0xC1,
              "rcl dst, imm8 | Rotate Through Carry Left | Rotate the 33 bits consisting of the carry flag and a 32-bit register or memory location left the number of bits specified by an 8-bit immediate value.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 2
              }
          }
        },

        { { "rcr", argtype_t::regmem32 },
          {
              0xD1,
              "rcr dst, 1 | Rotate Through Carry Right | Rotate the 33 bits consisting of the carry flag and a 32-bit register or memory location right 1 bit.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 3
              }
          }
        },
        { { "rcr", argtype_t::regmem32, argtype_t::imm8 },
          {
              0xC1,
              "rcr dst, imm8 | Rotate Through Carry Right | Rotate the 33 bits consisting of the carry flag and a 32-bit register or memory location right the number of bits specified by an 8-bit immediate value.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 3
              }
          }
        },
        { { "rcr", argtype_t::regmem64 },
          {
              0xD1,
              "rcr dst, 1 | Rotate Through Carry Right | Rotate the 33 bits consisting of the carry flag and a 32-bit register or memory location right 1 bit.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 3
              }
          }
        },
        { { "rcr", argtype_t::regmem64, argtype_t::imm8 },
          {
              0xC1,
              "rcr dst, imm8 | Rotate Through Carry Right | Rotate the 33 bits consisting of the carry flag and a 32-bit register or memory location right the number of bits specified by an 8-bit immediate value.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 3
              }
          }
        },

        { { "rdrand", argtype_t::reg32},
          {
              0x0F,
              "rdrand | Read Random | Loads the destination register with a hardware-generated random value. The size of the returned value in bits is determined by the size of the destination register. Hardware modifies the CF flag to indicate whether the value returned in the destination register is valid. If CF = 1, the value is valid. If CF = 0, the value is invalid. Software must test the state of the CF flag prior to using the value returned in the destination register to determine if the value is valid. If the returned value is invalid, software must execute the instruction again. Software should implement a retry limit to ensure forward progress of code. ",
              opcode_flags_t::regopcode_ext | opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_regopcode_ext = 6,
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0xC7 },
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["RDRAND"] }
              }
          }
        },

        { { "rdrand", argtype_t::reg64},
          {
              0x0F,
              "rdrand | Read Random | Loads the destination register with a hardware-generated random value. The size of the returned value in bits is determined by the size of the destination register. Hardware modifies the CF flag to indicate whether the value returned in the destination register is valid. If CF = 1, the value is valid. If CF = 0, the value is invalid. Software must test the state of the CF flag prior to using the value returned in the destination register to determine if the value is valid. If the returned value is invalid, software must execute the instruction again. Software should implement a retry limit to ensure forward progress of code. ",
              opcode_flags_t::regopcode_ext | opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_regopcode_ext = 6,
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0xC7 },
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["RDRAND"] }
              }
          }
        },
        { { "rdseed", argtype_t::reg64},
          {
              0x0F,
              "rdrand | Read Random Seed | Loads the destination register with a hardware-generated random \"seed\" value.",
              opcode_flags_t::regopcode_ext | opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_regopcode_ext = 7,
                ._f_opcode_count = 1,
                ._f_opcode_extra = { 0xC7 },
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["RDRAND"] }
              }
          }
        },

        { { "ret",  argtype_t::unused,   argtype_t::unused   }, { 0xC3, ("Near return to the calling procedure.") } },


        { { "rol", argtype_t::regmem32 },
          {
              0xD1,
              "rol dst, 1 | Rotate Left | Rotate a 32-bit register or memory operand left 1 bit.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 0
              }
          }
        },
        { { "rol", argtype_t::regmem32, argtype_t::imm8 },
          {
              0xC1,
              "rol dst, imm8 | Rotate Left | Rotate a 32-bit register or memory operand left the number of bits specified by an 8-bit immediate value.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 0
              }
          }
        },
        { { "rol", argtype_t::regmem64 },
          {
              0xD1,
              "rol dst, 1 | Rotate Left | Rotate a 64-bit register or memory operand left 1 bit.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 0
              }
          }
        },
        { { "rol", argtype_t::regmem64, argtype_t::imm8 },
          {
              0xC1,
              "rol dst, imm8 | Rotate Left | Rotate a 64-bit register or memory operand left the number of bits specified by an 8-bit immediate value.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 0
              }
          }
        },

        { { "ror", argtype_t::regmem32 },
          {
              0xD1,
              "ror dst, 1 | Rotate Right | Rotate a 32-bit register or memory operand right 1 bit.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 1
              }
          }
        },
        { { "ror", argtype_t::regmem32, argtype_t::imm8 },
          {
              0xC1,
              "ror dst, imm8 | Rotate Right | Rotate a 32-bit register or memory operand right the number of bits specified by an 8-bit immediate value.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 1
              }
          }
        },
        { { "ror", argtype_t::regmem64 },
          {
              0xD1,
              "ror dst, 1 | Rotate Right | Rotate a 64-bit register or memory operand right 1 bit.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 1
              }
          }
        },
        { { "ror", argtype_t::regmem64, argtype_t::imm8 },
          {
              0xC1,
              "ror dst, imm8 | Rotate Right | Rotate a 64-bit register or memory operand right the number of bits specified by an 8-bit immediate value.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 1
              }
          }
        },

        { { "rorx", argtype_t::reg32, argtype_t::regmem32, argtype_t::imm8 },
          {
              0xF0,
              "rorx dest, src, rot_cnt | Rotate Right Extended | Rotates the bits of the source operand right (toward the least-significant bit) by the number of bit positions specified in an immediate operand and writes the result to the destination. Does not affect the arithmetic flags.",
              opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::vex_extended,
              {
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["BMI2"] },
                ._f_vex0 = vex0_t::VEX_3byte,
                ._f_vex1 = {
                    .map_select = 3
                },
                ._f_vex2 = {
                    .pp = 0b11,
                    .L = 0,
                    .vvvv = 0b1111,
                    .w = 0
                }
              }
          }
        },
        { { "rorx", argtype_t::reg64, argtype_t::regmem64, argtype_t::imm8 },
          {
              0xF0,
              "rorx dest, src, rot_cnt | Rotate Right Extended | Rotates the bits of the source operand right (toward the least-significant bit) by the number of bit positions specified in an immediate operand and writes the result to the destination. Does not affect the arithmetic flags.",
              opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::vex_extended,
              {
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["BMI2"] },
                ._f_vex0 = vex0_t::VEX_3byte,
                ._f_vex1 = {
                    .map_select = 3
                },
                ._f_vex2 = {
                    .pp = 0b11,
                    .L = 0,
                    .vvvv = 0b1111,
                    .w = 1
                }
              }
          }
        },

        { { "sahf" },
          {
              0x9E,
              "sahf | Store AH into Flags | Loads the sign flag, the zero flag, the auxiliary flag, the parity flag, and the carry flag from the AH register into the lower 8 bits of the EFLAGS register. ",
              opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["LahfSahf"] }
              }
          }
        },


        { { "sal", argtype_t::regmem32 },
          {
              0xD1,
              "sal dst, 1 | Shift Left | Shift a 32-bit register or memory operand left 1 bit.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 4
              }
          }
        },
        { { "sal", argtype_t::regmem32, argtype_t::imm8 },
          {
              0xC1,
              "sal dst, imm8 | Shift Left | Shift a 32-bit register or memory operand left the number of bits specified by an 8-bit immediate value.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 4
              }
          }
        },
        { { "sal", argtype_t::regmem64 },
          {
              0xD1,
              "sal dst, 1 | Shift Left | Shift a 64-bit register or memory operand left 1 bit.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 4
              }
          }
        },
        { { "sal", argtype_t::regmem64, argtype_t::imm8 },
          {
              0xC1,
              "sal dst, imm8 | Shift Left | Shift a 64-bit register or memory operand left the number of bits specified by an 8-bit immediate value.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 4
              }
          }
        },


        { { "sar", argtype_t::regmem32 },
          {
              0xD1,
              "sar dst, 1 | Shift Right | Shift a 32-bit register or memory operand right 1 bit. The SAR instruction does not change the sign bit of the target operand. For each bit shift, it copies the sign bit to the next bit, preserving the sign of the result.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 7
              }
          }
        },
        { { "sar", argtype_t::regmem32, argtype_t::imm8 },
          {
              0xC1,
              "sar dst, imm8 | Shift Right | Shift a 32-bit register or memory operand right the number of bits specified by an 8-bit immediate value. The SAR instruction does not change the sign bit of the target operand. For each bit shift, it copies the sign bit to the next bit, preserving the sign of the result.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 7
              }
          }
        },
        { { "sar", argtype_t::regmem64 },
          {
              0xD1,
              "sar dst, 1 | Shift Right | Shift a 64-bit register or memory operand right 1 bit. The SAR instruction does not change the sign bit of the target operand. For each bit shift, it copies the sign bit to the next bit, preserving the sign of the result.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 7
              }
          }
        },
        { { "sar", argtype_t::regmem64, argtype_t::imm8 },
          {
              0xC1,
              "sar dst, imm8 | Shift Right | Shift a 64-bit register or memory operand right the number of bits specified by an 8-bit immediate value. The SAR instruction does not change the sign bit of the target operand. For each bit shift, it copies the sign bit to the next bit, preserving the sign of the result.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 7
              }
          }
        },
        { { "sarx", argtype_t::reg32, argtype_t::regmem32, argtype_t::imm8 },
          {
              0xF7,
              "sarx dest, src, rot_cnt | Shift Right Extended | Shifts the bits of the source operand right (toward the least-significant bit) by the number of bit positions specified in an immediate operand and writes the result to the destination. Does not affect the arithmetic flags.",
              opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::vex_extended,
              {
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["BMI2"] },
                ._f_vex0 = vex0_t::VEX_3byte,
                ._f_vex1 = {
                    .map_select = 2
                },
                ._f_vex2 = {
                    .pp = 0b10,
                    .L = 0,
                    .w = 0
                },
                ._f_vex_vvvv_arg = 1
              }
          }
        },

        { { "sbb",  argtype_t::EAX,      argtype_t::imm32    }, { 0x1D, ("sbb dst, src | Subtract with Borrow | Subtracts an immediate value or the value in a register or a memory location (second operand) from a register or a memory location (first operand), and stores the result in the first operand location. If the carry flag (CF) is 1, the instruction subtracts 1 from the result. Otherwise, it operates like SUB. The SBB instruction sign-extends immediate value operands to the length of the first operand size. This instruction evaluates the result for both signed and unsigned data types and sets the OF and CF flags to indicate a borrow in a signed or unsigned result, respectively. It sets the SF flag to indicate the sign of a signed result. This instruction is useful for multibyte (multiword) numbers because it takes into account the borrow from a previous SUB instruction. The forms of the SBB instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see “Lock Prefix” on page 11. ") } },
        { { "sbb",  argtype_t::RAX,      argtype_t::imm32    }, { 0x1D, ("sbb dst, src | Subtract with Borrow | Subtracts an immediate value or the value in a register or a memory location (second operand) from a register or a memory location (first operand), and stores the result in the first operand location. If the carry flag (CF) is 1, the instruction subtracts 1 from the result. Otherwise, it operates like SUB. The SBB instruction sign-extends immediate value operands to the length of the first operand size. This instruction evaluates the result for both signed and unsigned data types and sets the OF and CF flags to indicate a borrow in a signed or unsigned result, respectively. It sets the SF flag to indicate the sign of a signed result. This instruction is useful for multibyte (multiword) numbers because it takes into account the borrow from a previous SUB instruction. The forms of the SBB instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see “Lock Prefix” on page 11. ") } },
        { { "sbb",  argtype_t::regmem32, argtype_t::imm32    }, { 0x81, ("sbb dst, src | Subtract with Borrow | Subtracts an immediate value or the value in a register or a memory location (second operand) from a register or a memory location (first operand), and stores the result in the first operand location. If the carry flag (CF) is 1, the instruction subtracts 1 from the result. Otherwise, it operates like SUB. The SBB instruction sign-extends immediate value operands to the length of the first operand size. This instruction evaluates the result for both signed and unsigned data types and sets the OF and CF flags to indicate a borrow in a signed or unsigned result, respectively. It sets the SF flag to indicate the sign of a signed result. This instruction is useful for multibyte (multiword) numbers because it takes into account the borrow from a previous SUB instruction. The forms of the SBB instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see “Lock Prefix” on page 11. "), opcode_flags_t::regopcode_ext, {._f_regopcode_ext = 3 } } },
        { { "sbb",  argtype_t::regmem64, argtype_t::imm32    }, { 0x81, ("sbb dst, src | Subtract with Borrow | Subtracts an immediate value or the value in a register or a memory location (second operand) from a register or a memory location (first operand), and stores the result in the first operand location. If the carry flag (CF) is 1, the instruction subtracts 1 from the result. Otherwise, it operates like SUB. The SBB instruction sign-extends immediate value operands to the length of the first operand size. This instruction evaluates the result for both signed and unsigned data types and sets the OF and CF flags to indicate a borrow in a signed or unsigned result, respectively. It sets the SF flag to indicate the sign of a signed result. This instruction is useful for multibyte (multiword) numbers because it takes into account the borrow from a previous SUB instruction. The forms of the SBB instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see “Lock Prefix” on page 11. "), opcode_flags_t::regopcode_ext, {._f_regopcode_ext = 3 } } },
        { { "sbb",  argtype_t::regmem32, argtype_t::imm8     }, { 0x83, ("sbb dst, src | Subtract with Borrow | Subtracts an immediate value or the value in a register or a memory location (second operand) from a register or a memory location (first operand), and stores the result in the first operand location. If the carry flag (CF) is 1, the instruction subtracts 1 from the result. Otherwise, it operates like SUB. The SBB instruction sign-extends immediate value operands to the length of the first operand size. This instruction evaluates the result for both signed and unsigned data types and sets the OF and CF flags to indicate a borrow in a signed or unsigned result, respectively. It sets the SF flag to indicate the sign of a signed result. This instruction is useful for multibyte (multiword) numbers because it takes into account the borrow from a previous SUB instruction. The forms of the SBB instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see “Lock Prefix” on page 11. "), opcode_flags_t::regopcode_ext, {._f_regopcode_ext = 3 } } },
        { { "sbb",  argtype_t::regmem64, argtype_t::imm8     }, { 0x83, ("sbb dst, src | Subtract with Borrow | Subtracts an immediate value or the value in a register or a memory location (second operand) from a register or a memory location (first operand), and stores the result in the first operand location. If the carry flag (CF) is 1, the instruction subtracts 1 from the result. Otherwise, it operates like SUB. The SBB instruction sign-extends immediate value operands to the length of the first operand size. This instruction evaluates the result for both signed and unsigned data types and sets the OF and CF flags to indicate a borrow in a signed or unsigned result, respectively. It sets the SF flag to indicate the sign of a signed result. This instruction is useful for multibyte (multiword) numbers because it takes into account the borrow from a previous SUB instruction. The forms of the SBB instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see “Lock Prefix” on page 11. "), opcode_flags_t::regopcode_ext, {._f_regopcode_ext = 3 } } },
        { { "sbb",  argtype_t::regmem32, argtype_t::reg32    }, { 0x19, ("sbb dst, src | Subtract with Borrow | Subtracts an immediate value or the value in a register or a memory location (second operand) from a register or a memory location (first operand), and stores the result in the first operand location. If the carry flag (CF) is 1, the instruction subtracts 1 from the result. Otherwise, it operates like SUB. The SBB instruction sign-extends immediate value operands to the length of the first operand size. This instruction evaluates the result for both signed and unsigned data types and sets the OF and CF flags to indicate a borrow in a signed or unsigned result, respectively. It sets the SF flag to indicate the sign of a signed result. This instruction is useful for multibyte (multiword) numbers because it takes into account the borrow from a previous SUB instruction. The forms of the SBB instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see “Lock Prefix” on page 11. ") } },
        { { "sbb",  argtype_t::regmem64, argtype_t::reg64    }, { 0x19, ("sbb dst, src | Subtract with Borrow | Subtracts an immediate value or the value in a register or a memory location (second operand) from a register or a memory location (first operand), and stores the result in the first operand location. If the carry flag (CF) is 1, the instruction subtracts 1 from the result. Otherwise, it operates like SUB. The SBB instruction sign-extends immediate value operands to the length of the first operand size. This instruction evaluates the result for both signed and unsigned data types and sets the OF and CF flags to indicate a borrow in a signed or unsigned result, respectively. It sets the SF flag to indicate the sign of a signed result. This instruction is useful for multibyte (multiword) numbers because it takes into account the borrow from a previous SUB instruction. The forms of the SBB instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see “Lock Prefix” on page 11. ") } },
        { { "sbb",  argtype_t::reg32,    argtype_t::regmem32 }, { 0x1B, ("sbb dst, src | Subtract with Borrow | Subtracts an immediate value or the value in a register or a memory location (second operand) from a register or a memory location (first operand), and stores the result in the first operand location. If the carry flag (CF) is 1, the instruction subtracts 1 from the result. Otherwise, it operates like SUB. The SBB instruction sign-extends immediate value operands to the length of the first operand size. This instruction evaluates the result for both signed and unsigned data types and sets the OF and CF flags to indicate a borrow in a signed or unsigned result, respectively. It sets the SF flag to indicate the sign of a signed result. This instruction is useful for multibyte (multiword) numbers because it takes into account the borrow from a previous SUB instruction. The forms of the SBB instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see “Lock Prefix” on page 11. ") } },
        { { "sbb",  argtype_t::reg64,    argtype_t::regmem64 }, { 0x1B, ("sbb dst, src | Subtract with Borrow | Subtracts an immediate value or the value in a register or a memory location (second operand) from a register or a memory location (first operand), and stores the result in the first operand location. If the carry flag (CF) is 1, the instruction subtracts 1 from the result. Otherwise, it operates like SUB. The SBB instruction sign-extends immediate value operands to the length of the first operand size. This instruction evaluates the result for both signed and unsigned data types and sets the OF and CF flags to indicate a borrow in a signed or unsigned result, respectively. It sets the SF flag to indicate the sign of a signed result. This instruction is useful for multibyte (multiword) numbers because it takes into account the borrow from a previous SUB instruction. The forms of the SBB instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see “Lock Prefix” on page 11. ") } },



        { { "sfence" },
          {
              0x0F,
              "sfence | Store Fence | Acts as a barrier to force strong memory ordering (serialization) between store instructions preceding the SFENCE and store instructions that follow the SFENCE. Stores to differing memory types, or within the WC memory type, may become visible out of program order; the SFENCE instruction ensures that the system completes all previous stores in such a way that they are globally visible before executing subsequent stores. This includes emptying the store buffer and all write-combining buffers. The SFENCE instruction is weakly-ordered with respect to load instructions, data and instruction prefetches, and the LFENCE instruction. Speculative loads initiated by the processor, or specified explicitly using cache-prefetch instructions, can be reordered around an SFENCE. ",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_opcode_count = 2,
                ._f_opcode_extra = { 0xAE, 0x08 },
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["SSE"] }
              }
          }
        },

            //shift left double


        { { "shr", argtype_t::regmem32 },
          {
              0xD1,
              "shr dst, 1 | Shift Right | Shift a 32-bit register or memory operand right 1 bit.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 5
              }
          }
        },
        { { "shr", argtype_t::regmem32, argtype_t::imm8 },
          {
              0xC1,
              "shr dst, imm8 | Shift Right | Shift a 32-bit register or memory operand right the number of bits specified by an 8-bit immediate value.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 5
              }
          }
        },
        { { "shr", argtype_t::regmem64 },
          {
              0xD1,
              "shr dst, 1 | Shift Right | Shift a 64-bit register or memory operand right 1 bit.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 5
              }
          }
        },
        { { "shr", argtype_t::regmem64, argtype_t::imm8 },
          {
              0xC1,
              "shr dst, imm8 | Shift Right | Shift a 64-bit register or memory operand right the number of bits specified by an 8-bit immediate value.",
              opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 5
              }
          }
        },



        { { "stc" }, { 0xF9, ("Set the carry flag (CF) to 1") } },
        { { "std" }, { 0xFD, ("Set the direction flag (CF) to 1") } },



        { { "sub",  argtype_t::EAX,      argtype_t::imm32    }, { 0x2D, ("Subtract imm32 to EAX") } },
        { { "sub",  argtype_t::RAX,      argtype_t::imm32    }, { 0x2D, ("Subtract sign-extended imm32 to RAX") } },
        { { "sub",  argtype_t::regmem32, argtype_t::imm32    }, { 0x81, ("Subtract imm32 to reg/mem32"),               opcode_flags_t::regopcode_ext, { ._f_regopcode_ext = 5 } } },
        { { "sub",  argtype_t::regmem64, argtype_t::imm32    }, { 0x81, ("Subtract sign-extended imm32 to reg/mem64"), opcode_flags_t::regopcode_ext, { ._f_regopcode_ext = 5 } } },
        { { "sub",  argtype_t::regmem32, argtype_t::imm8     }, { 0x83, ("Subtract sign-extended imm8 to reg/mem32"),  opcode_flags_t::regopcode_ext, { ._f_regopcode_ext = 5 } } },
        { { "sub",  argtype_t::regmem64, argtype_t::imm8     }, { 0x83, ("Subtract sign-extended imm8 to reg/mem64"),  opcode_flags_t::regopcode_ext, { ._f_regopcode_ext = 5 } } },
        { { "sub",  argtype_t::regmem32, argtype_t::reg32    }, { 0x29, ("Subtract reg32 to reg/mem32") } },
        { { "sub",  argtype_t::regmem64, argtype_t::reg64    }, { 0x29, ("Subtract reg64 to reg/mem64") } },
        { { "sub",  argtype_t::reg32,    argtype_t::regmem32 }, { 0x2B, ("Subtract reg/mem32 to reg32") } },
        { { "sub",  argtype_t::reg64,    argtype_t::regmem64 }, { 0x2B, ("Subtract reg/mem64 to reg64") } },
        

        { { "test",  argtype_t::EAX,      argtype_t::imm32    }, { 0xA9, ("test dst, src | Test Bits | Performs a bit-wise logical and on the value in a register or memory location (first operand) with an immediate value or the value in a register (second operand) and sets the flags in the rFLAGS register based on the result.") } },
        { { "test",  argtype_t::RAX,      argtype_t::imm32    }, { 0xA9, ("test dst, src | Test Bits | Performs a bit-wise logical and on the value in a register or memory location (first operand) with an immediate value or the value in a register (second operand) and sets the flags in the rFLAGS register based on the result.") } },
        { { "test",  argtype_t::regmem32, argtype_t::imm32    }, { 0xF7, ("test dst, src | Test Bits | Performs a bit-wise logical and on the value in a register or memory location (first operand) with an immediate value or the value in a register (second operand) and sets the flags in the rFLAGS register based on the result."), opcode_flags_t::regopcode_ext, {._f_regopcode_ext = 0 } } },
        { { "test",  argtype_t::regmem64, argtype_t::imm32    }, { 0xF7, ("test dst, src | Test Bits | Performs a bit-wise logical and on the value in a register or memory location (first operand) with an immediate value or the value in a register (second operand) and sets the flags in the rFLAGS register based on the result."), opcode_flags_t::regopcode_ext, {._f_regopcode_ext = 0 } } },
        { { "test",  argtype_t::regmem32, argtype_t::reg32    }, { 0x85, ("test dst, src | Test Bits | Performs a bit-wise logical and on the value in a register or memory location (first operand) with an immediate value or the value in a register (second operand) and sets the flags in the rFLAGS register based on the result.") } },
        { { "test",  argtype_t::regmem64, argtype_t::reg64    }, { 0x85, ("test dst, src | Test Bits | Performs a bit-wise logical and on the value in a register or memory location (first operand) with an immediate value or the value in a register (second operand) and sets the flags in the rFLAGS register based on the result.") } },


        { { "tzcnt", argtype_t::reg32, argtype_t::regmem32 },
          {
              0xF3,
              "tzcnt dst, src | Count Trailing Zeros | Counts the number of trailing zero bits in the 16-, 32-, or 64-bit general purpose register or memory source operand. Counting starts upward from the least significant bit and stops when the lowest bit having a value of 1 is encountered or when the most significant bit is encountered. The count is written to the destination register. If the input operand is zero, CF is set to 1 and the size (in bits) of the input operand is written to the destination register. Otherwise, CF is cleared. If the least significant bit is a one, the ZF flag is set to 1 and zero is written to the destination register. Otherwise, ZF is cleared.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_opcode_count = 2,
                ._f_opcode_extra = { 0x0F, 0xBC },
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["BMI1"] }
              }
          }
        },
        { { "tzcnt", argtype_t::reg64, argtype_t::regmem64 },
          {
              0xF3,
              "tzcnt dst, src | Count Trailing Zeros | Counts the number of trailing zero bits in the 16-, 32-, or 64-bit general purpose register or memory source operand. Counting starts upward from the least significant bit and stops when the lowest bit having a value of 1 is encountered or when the most significant bit is encountered. The count is written to the destination register. If the input operand is zero, CF is set to 1 and the size (in bits) of the input operand is written to the destination register. Otherwise, CF is cleared. If the least significant bit is a one, the ZF flag is set to 1 and zero is written to the destination register. Otherwise, ZF is cleared.",
              opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
              {
                ._f_opcode_count = 2,
                ._f_opcode_extra = { 0x0F, 0xBC },
                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = { &cpu_queries["BMI1"] }
              }
          }
        },
    };

    bool clear_whitespace_inline(nextany_tokenizer::const_iterator_t& b, const nextany_tokenizer::const_iterator_t& e)
    {
        while (b->value.size == 0)
        {
            if (b->delimiter == '\n')
            {
                ++b;
                return false;
            }
            if (++b == e) return false;
        }
        return true;
    }

    optional<argument_t> parse_argument(instruction_t* pinstruction, argtype_t* parg, nextany_tokenizer::const_iterator_t& iter, const nextany_tokenizer::const_iterator_t& end, int64_t pos, const umap<string, int64_t>& labels)
    {
        argument_t ret;

        if (iter->value[0] == '-')
        {
            __usingif(parsed, parse::integer64(iter->value.view<uint8_t>()))
            {
                *((int64_t*)&ret.imm) = parsed;

                if (std::numeric_limits<int8_t>::lowest() <= parsed && parsed <= std::numeric_limits<int8_t>::max())
                {
                    *parg = argtype_t::imm8;
                }
                else if (std::numeric_limits<int16_t>::lowest() <= parsed && parsed <= std::numeric_limits<int16_t>::max())
                {
                    *parg = argtype_t::imm16;
                }
                else if (std::numeric_limits<int32_t>::lowest() <= parsed && parsed <= std::numeric_limits<int32_t>::max())
                {
                    *parg = argtype_t::imm32;
                }
                else
                {
                    *parg = argtype_t::imm64;
                }
            }
        }
        else if (iter->value[0] >= '0' && iter->value[0] <= '9')
        {
            __checkedinto(ret.imm, parse::uinteger64(iter->value.view<uint8_t>()));

            if (std::numeric_limits<uint8_t>::lowest() <= ret.imm && ret.imm <= std::numeric_limits<uint8_t>::max())
            {
                *parg = argtype_t::imm8;
            }
            else if (std::numeric_limits<uint16_t>::lowest() <= ret.imm && ret.imm <= std::numeric_limits<uint16_t>::max())
            {
                *parg = argtype_t::imm16;
            }
            else if (std::numeric_limits<uint32_t>::lowest() <= ret.imm && ret.imm <= std::numeric_limits<uint32_t>::max())
            {
                *parg = argtype_t::imm32;
            }
            else
            {
                *parg = argtype_t::imm64;
            }

        }
        else if (iter->value[0] == '[')
        {
            if (auto reg = register_t(buffer<char>::from_ptr(iter->value.ptr + 1, iter->value.size - 2)); reg != register_t::invalid)
            {
                if (reg == register_t::RBP || reg == register_t::EBP)
                {
                    // RBP indirect addressing requires base+offset syntax, where offset = 0
                    ret.disp = 0;
                    ret.base = reg;
                    ret.mode = modrm_t::mode_t::indirect_rbp_disp8;
                    ret.scale = 0;
                }
                else
                {
                    ret.reg = reg;
                    ret.mode = modrm_t::mode_t::register_indirect;
                }

                if (reg.size() == 64)
                {
                    *parg = argtype_t::mem64;
                }
                else
                {
                    *parg = argtype_t::mem32;
                }
            }
            else
            {
                // parse sib format
                // [base][+index*scale]
                static std::regex sibregex((R"___(^\[([a-zA-Z][a-zA-Z0-9]*)\]$|^\[([a-zA-Z][a-zA-Z0-9]*)\+([a-zA-Z][a-zA-Z0-9]*)\]$|^\[([a-zA-Z][a-zA-Z0-9]*)\+([0-9]*)\]$|^\[([a-zA-Z][a-zA-Z0-9]*)\*(2|4|8)\]$|^\[([a-zA-Z][a-zA-Z0-9]*)\+([a-zA-Z][a-zA-Z0-9]*)\*(2|4|8)\]$)___"), std::regex_constants::ECMAScript | std::regex_constants::optimize);
                std::match_results<const char*> matches;
                if (std::regex_search(iter->value.begin(), iter->value.end(), matches, sibregex))
                {
                    ret.scale = 0;

                    if (matches[2].matched && matches[3].matched)
                    {
                        // [base+index]
                        ret.base  = register_t(buffer<char>::from_ptr(matches[2].first, matches[2].second - matches[2].first));
                        ret.index = register_t(buffer<char>::from_ptr(matches[3].first, matches[3].second - matches[3].first));

                        if (ret.base == register_t::EBP || ret.base == register_t::RBP)
                        {
                            ret.disp = 0;
                            ret.mode = modrm_t::mode_t::indirect_disp32;
                        }
                        else
                        {
                            ret.mode = modrm_t::mode_t::register_indirect;
                        }
                    }
                    else if (matches[4].matched && matches[5].matched)
                    {
                        // [index*1+disp32]
                        register_t reg = register_t(buffer<char>::from_ptr(matches[4].first, matches[4].second - matches[4].first));

                        __checkedinto(ret.disp, parse::uinteger32(buffer<char>::from_ptr(matches[5].first, matches[5].second - matches[5].first)));

                        if (reg == register_t::EBP || reg == register_t::RBP)
                        {
                            ret.base = reg;
                            if (ret.disp <= std::numeric_limits<uint8_t>::max())
                            {
                                ret.mode = modrm_t::mode_t::indirect_rbp_disp8;
                            }
                            else
                            {
                                ret.mode = modrm_t::mode_t::indirect_rbp_disp32;
                            }
                        }
                        else if (reg == register_t::ESP || reg == register_t::RSP)
                        {
                            return __error_msg(errors::assembler::invalid_indirect_address_scheme, "Cannot add displacement to RSP");
                        }
                        else
                        {
                            ret.index = reg;
                            ret.mode = modrm_t::mode_t::indirect_disp32;
                        }
                    }
                    else if (matches[6].matched && matches[7].matched)
                    {
                        // [index*scale]
                        ret.base = register_t::RBP;
                        ret.disp = 0;
                        ret.mode = modrm_t::mode_t::indirect_disp32;

                        __checkedinto(ret.scale, parse::uinteger32(buffer<char>::from_ptr(matches[7].first, matches[7].second - matches[7].first)));
                        ret.scale = (ret.scale == 1 ? 0 : ret.scale == 2 ? 1 : ret.scale == 4 ? 2 : 3);

                        ret.index = register_t(buffer<char>::from_ptr(matches[6].first, matches[6].second - matches[6].first));
                    }
                    else if (matches[8].matched && matches[9].matched && matches[10].matched)
                    {
                        //[base+index*scale]
                        ret.base  = register_t(buffer<char>::from_ptr(matches[8].first, matches[8].second - matches[8].first));
                        ret.index = register_t(buffer<char>::from_ptr(matches[9].first, matches[9].second - matches[9].first));

                        if (ret.base == register_t::EBP || ret.base == register_t::RBP)
                        {
                            ret.disp = 0;
                            ret.mode = modrm_t::mode_t::indirect_disp32;
                        }

                        __checkedinto(ret.scale, parse::uinteger32(buffer<char>::from_ptr(matches[10].first, matches[10].second - matches[10].first)));
                        ret.scale = (ret.scale == 1 ? 0 : ret.scale == 2 ? 1 : ret.scale == 4 ? 2 : 3);
                    }

                    if (ret.base.size() == 64 || ret.index.size() == 64)
                    {
                        *parg = argtype_t::mem64;
                    }
                    else
                    {
                        *parg = argtype_t::mem32;
                    }
                }
                else
                {
                    return __error_msg(errors::assembler::invalid_indirect_address_scheme, "Addressing: "_s + to_string(iter->value) + " is invalid");
                }
            }
        }
        else if (iter->value == "eax" || iter->value == "EAX")
        {
            *parg = argtype_t::EAX;
            ret.mode = modrm_t::mode_t::register_direct;
            ret.reg = register_t::EAX;
        }
        else if (iter->value == "rax" || iter->value == "RAX")
        {
            *parg = argtype_t::RAX;
            ret.mode = modrm_t::mode_t::register_direct;
            ret.reg = register_t::RAX;
        }
        else
        {
            register_t reg(iter->value);
            if (reg == register_t::invalid)
            {
                if (auto label = labels.find(to_string(iter->value)); label != labels.end())
                {
                    pinstruction->opcode.flags |= opcode_flags_t::label;

                    *((int64_t*)&ret.imm) = label->second - pos;
                    if (std::numeric_limits<uint8_t>::lowest() <= ret.imm && ret.imm <= std::numeric_limits<uint8_t>::max())
                    {
                        *parg = argtype_t::imm8;
                    }
                    else if (std::numeric_limits<uint16_t>::lowest() <= ret.imm && ret.imm <= std::numeric_limits<uint16_t>::max())
                    {
                        *parg = argtype_t::imm16;
                    }
                    else if (std::numeric_limits<uint32_t>::lowest() <= ret.imm && ret.imm <= std::numeric_limits<uint32_t>::max())
                    {
                        *parg = argtype_t::imm32;
                    }
                    else
                    {
                        *parg = argtype_t::imm64;
                    }
                    return ret;
                }
                return __error_msg(errors::assembler::invalid_argument, "Argument "_s + to_string(iter->value) + " not recognized");
            }

            ret.mode = modrm_t::mode_t::register_direct;
            ret.reg = reg;

            if (reg.size() == 64)
            {
                *parg = argtype_t::reg64;
            }
            else
            {
                *parg = argtype_t::reg32;
            }
        }


        return ret;
    }
    optional<instruction_t> parse_instruction(nextany_tokenizer::const_iterator_t& iter, const nextany_tokenizer::const_iterator_t& end, int64_t pos, umap<string, int64_t>& labels) noexcept
    {
        if (iter->delimiter == '\n')
        {
            if (iter->value.size == 0)
            {
                return __error_msg(errors::assembler::instruction_incomplete, "Empty statement");
            }
            if (iter->value.back() == ':')
            {
                string label = to_string(iter->value);
                label.pop_back();

                labels[label] = pos;
                ++iter;
                return instruction_t{ .opcode = { .flags = opcode_flags_t::label } };
            }
        }

        instruction_t ret;
        if (iter->value.size >= 16)
        {
            return __error_msg(errors::assembler::invalid_instruction, "Label "_s + to_string(iter->value) + " is not a recognized instruction (length exceeded 16)");
        }

        do
        {
            if (auto pref = prefix(iter->value); pref != prefix::invalid)
            {
                ret.prefixes[ret.prefix_count++] = pref;
                if (++iter == end || !clear_whitespace_inline(iter, end)) return __error_msg(errors::assembler::unexpected_end_of_statment, "Label "_s + to_string(iter->value) + ": Ended in a prefix");
            }
            else break;
        } while (true);


        memcpy(ret.signature.label, iter->value.ptr, iter->value.size);

        int32_t argcount = 0;
        buffer<char> argnames[4];
        if (iter->delimiter != '\n' && ++iter != end && clear_whitespace_inline(iter, end))
        {

            do
            {
                if (argcount == 4)
                {
                    return __error_msg(errors::assembler::invalid_argument, "Argument count cannot exceed 4");
                }

                argnames[argcount] = iter->value.view();
                __checkedinto(ret.args[argcount], parse_argument(&ret, &ret.signature.types[argcount], iter, end, pos, labels));
                ++argcount;

                if (iter->delimiter == ',')
                {
                    if (++iter == end || !clear_whitespace_inline(iter, end)) return __error_msg(errors::assembler::unexpected_end_of_statment, "Label "_s + to_string(iter->value) + ": Ended in a ','");
                }
                else break;

            } while (true);
        }
        ++iter;

        if (argcount == 0)
        if (auto emptylabel = labels.find(s("")); emptylabel != labels.end())
        {
            // try to find an empty label overload
            signature_t test = ret.signature;
            test.types[0] = argtype_t::imm8;
            do
            {
                if (auto op = opcode_map.find(test); op != opcode_map.end())
                {
                    ret.signature = test;
                    ret.args[0] = argument_t {
                        .imm = (uint64_t)(emptylabel->second - pos)
                    };
                    ret.opcode = op->second;
                    ret.opcode.flags |= opcode_flags_t::label;
                    return ret;
                }

                do
                {
                    if (!(++test.types[0]).valid())
                    {
                        break;
                    }
                } while (true);

            } while (test.types[0].valid());
        }


        // find overload
        signature_t test = ret.signature;
        do
        {
            if (auto op = opcode_map.find(test); op != opcode_map.end())
            {
                ret.signature = test;

                auto flags = ret.opcode.flags;
                ret.opcode = op->second;
                ret.opcode.flags |= flags;
                break;
            }

            if (argcount == 0) return __error_msg(errors::assembler::instruction_overload_not_found, "Could not find overload for label "_s + (test.label));

            bool valid_overload = true;
            do
            {
                for (int i = 0; i < argcount; ++i)
                {
                    if ((++test.types[i]).valid())
                    {
                        break;
                    }
                    else
                    {
                        if (i + 1 == argcount)
                        {
                            string err = "Could not find overload for label "_s + (test.label);
                            for (int j = 0; j < argcount; ++j)
                            {
                                err += " " + to_string(argnames[j]);
                            }
                            return __error_msg(errors::assembler::instruction_overload_not_found, err);
                        }
                        test.types[i] = ret.signature.types[i];
                    }
                }

                valid_overload = true;
                for (int i = 0; i < 4; ++i)
                {
                    if (test.types[i].operand_size() != ret.signature.types[i].operand_size()
                        && ret.signature.types[i] != argtype_t::imm8)
                    {
                        valid_overload = false;
                        break;
                    }
                }
            } while (!valid_overload);

        } while (true);

        return ret;
    }

    optional<buffervec<uint8_t>> assemble(const string& code) noexcept
    {
        buffervec<uint8_t> ret;
        umap<string, int64_t> labels;

        nextany_tokenizer tokenizer;
        tokenizer.add(" \n\r,");
        tokenizer.set(code);
        auto b = tokenizer.begin();
        auto e = tokenizer.end();
        while (b != e)
        {
            while (b->value.size == 0)
            {
                if (++b == e) break;
            }
            if (b == e) break;

            instruction_t instruction;
            __checkedinto(instruction, parse_instruction(b, e, ret.size(), labels));
            if (instruction.opcode.code != 0 || !instruction.opcode.flags.has(opcode_flags_t::label))
            {
                __checked(instruction.emit(ret));
            }
        }

        return ret;
    }

#define __ms__(x) #x
#define __ms(x) __ms__(x)

    void* mem = nullptr;

    optional<uint32_t> cpuq_t::execute()
    {
        buffervec<uint8_t> assembly;

        string header = R"(
    push rsi
    push rdi
    push rcx
    push ebx
    push rbp

    push r9
    push r8
    push rdx
    push rcx

)";

        string footer = R"(
    cpuid
                    
    pop rbp
    mov [ebp], eax

    pop rbp
    mov [ebp], ebx

    pop rbp
    mov [ebp], ecx

    pop rbp
    mov [ebp], edx

    pop rbp
    pop ebx
    pop rcx
    pop rdi
    pop rsi
    ret
)";

        __checkedinto(assembly, assemble(header + "mov eax, " + fn + "\nmov ecx, " + subfn + "\n" + footer));
        memcpy(mem, assembly.ptr(), assembly.size());

        using cd = int(*)(uint32_t* rax, uint32_t* rbx, uint32_t* rcx, uint32_t* rdx);

        uint32_t result[4];
        ((cd)mem)(result, result + 1, result + 2, result + 3);

        return (result[(int32_t)regpos] >> bit_start) & mask(bit_end - bit_start);
    }

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
        buffervec<uint8_t> assembly;
        __checkedinto(assembly, assemble(R"(
                                    rdrand eax
                                    ret
                                )"));

        mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);


        printf("Has ADX: %s\n",  cpu_queries["ADX"].execute() == 1 ? "true" : "false");
        printf("Has BMI1: %s\n", cpu_queries["BMI1"].execute() == 1 ? "true" : "false");
        printf("Has BMI2: %s\n", cpu_queries["BMI2"].execute() == 1 ? "true" : "false");
        printf("Has TBM: %s\n", cpu_queries["TBM"].execute() == 1 ? "true" : "false");
        printf("Has CLFSH: %s\n", cpu_queries["CLFSH"].execute() == 1 ? "true" : "false");
        printf("Has CLFLOPT: %s\n", cpu_queries["CLFLOPT"].execute() == 1 ? "true" : "false");
        printf("ClFlush: %u\n", cpu_queries["CLFlush"].execute().value());
        printf("Has CLWB: %s\n", cpu_queries["CLWB"].execute() == 1 ? "true" : "false");
        printf("Has CLZERO: %s\n", cpu_queries["CLZERO"].execute() == 1 ? "true" : "false");
        printf("Has CMOV: %s\n", cpu_queries["CMOV"].execute() == 1 ? "true" : "false");
        printf("Has LahfSahf: %s\n", cpu_queries["LahfSahf"].execute() == 1 ? "true" : "false");
        printf("Has CMPXCHG16B: %s\n", cpu_queries["CMPXCHG16B"].execute() == 1 ? "true" : "false");
        printf("Has SSE42: %s\n", cpu_queries["SSE4.2"].execute() == 1 ? "true" : "false");
        printf("Has LWP: %s\n", cpu_queries["LWP"].execute() == 1 ? "true" : "false");
        printf("Has ABM: %s\n", cpu_queries["ABM"].execute() == 1 ? "true" : "false");
        printf("Has MCOMMMIT: %s\n", cpu_queries["MCOMMMIT"].execute() == 1 ? "true" : "false");
        printf("Has MONITORX: %s\n", cpu_queries["MONITORX"].execute() == 1 ? "true" : "false");
        printf("Has MOVBE: %s\n", cpu_queries["MOVBE"].execute() == 1 ? "true" : "false");
        printf("Has MMX: %s\n", cpu_queries["MMX"].execute() == 1 ? "true" : "false");
        printf("Has POPCNT: %s\n", cpu_queries["POPCNT"].execute() == 1 ? "true" : "false");
        printf("Has RDRAND: %s\n", cpu_queries["RDRAND"].execute() == 1 ? "true" : "false");
        
        //uint32_t v1 = cpu_queries["L1DcSize"].execute();
        //uint32_t v2 = cpu_queries["L1IcSize"].execute();
        //uint32_t v3 = cpu_queries["L1DcLinesPerTag"].execute();
        //uint32_t v4 = cpu_queries["L1DcLineSize"].execute();

        memcpy(mem, assembly.ptr(), assembly.size());
        using cd = int(*)();

        timer tk, tk2;
        volatile int b = 0;

        tk.start();
        b = ((cd)mem)();
        tk.stop();


        return error();
    }
}




int32_t main()
{
    if (auto e = cgengine::main(); !e.success())
    {
        printf("%s\n", e.to_string().c_str());
    }
}






