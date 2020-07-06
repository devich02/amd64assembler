
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
            XMM0, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6, XMM7,
            YMM0, YMM1, YMM2, YMM3, YMM4, YMM5, YMM6, YMM7,

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

            else if (name == s("MMX0")) value = MMX0;
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

            else if (name == s("YMM0")) value = YMM0;
            else if (name == s("YMM1")) value = YMM1;
            else if (name == s("YMM2")) value = YMM2;
            else if (name == s("YMM3")) value = YMM3;
            else if (name == s("YMM4")) value = YMM4;
            else if (name == s("YMM5")) value = YMM5;
            else if (name == s("YMM6")) value = YMM6;
            else if (name == s("YMM7")) value = YMM7;
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

            else if (name == ("MMX0") || name == ("mmx0")) value = MMX0;
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

            else if (name == ("YMM0") || name == ("ymm0")) value = YMM0;
            else if (name == ("YMM1") || name == ("ymm1")) value = YMM1;
            else if (name == ("YMM2") || name == ("ymm2")) value = YMM2;
            else if (name == ("YMM3") || name == ("ymm3")) value = YMM3;
            else if (name == ("YMM4") || name == ("ymm4")) value = YMM4;
            else if (name == ("YMM5") || name == ("ymm5")) value = YMM5;
            else if (name == ("YMM6") || name == ("ymm6")) value = YMM6;
            else if (name == ("YMM7") || name == ("ymm7")) value = YMM7;
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

        uint32_t size() const noexcept
        {
            switch (value)
            {
            case R8B: case R9B: case R10B: case R11B: case R12B: case R13B: case R14B: case R15B: return 1;
            case R8W: case R9W: case R10W: case R11W: case R12W: case R13W: case R14W: case R15W: return 2;
            case R8D: case R9D: case R10D: case R11D: case R12D: case R13D: case R14D: case R15D: return 4;
            case R8: case R9: case R10: case R11: case R12: case R13: case R14: case R15: return 8;

            case AX: case BX: case CX: case DX: case DI: case SI: case BP: case SP: case SS: return 2;
            case EAX: case EBX: case ECX: case EDX: case EDI: case ESI: case EBP: case ESP: return 4;
            case RAX: case RBX: case RCX: case RDX: case RDI: case RSI: case RBP: case RSP: return 8;
            }
            return 0;
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
            case register_t::R8: case register_t::R8D:
            case register_t::EAX:
            case register_t::RAX: value = AX; break;

            case register_t::R9: case register_t::R9D:
            case register_t::EBX:
            case register_t::RBX: value = BX; break;

            case register_t::R10: case register_t::R10D:
            case register_t::ECX:
            case register_t::RCX: value = CX; break;

            case register_t::R11: case register_t::R11D:
            case register_t::EDX:
            case register_t::RDX: value = DX; break;

            case register_t::R12: case register_t::R12D:
            case register_t::ESP:
            case register_t::RSP: value = SP; break;

            case register_t::R13: case register_t::R13D:
            case register_t::EBP:
            case register_t::RBP: value = BP; break;

            case register_t::R14: case register_t::R14D:
            case register_t::ESI:
            case register_t::RSI: value = SI; break;

            case register_t::R15: case register_t::R15D:
            case register_t::EDI:
            case register_t::RDI: value = DI; break;
            default: __assert(false);
            }
        }
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

        static rex_t make(register_t reg)
        {
            rex_t ret;
            if (reg >= register_t::R8B && reg <= register_t::R15)
            {
                ret.b = 1;
            }
            if (reg.size() == 8) ret.w = 1;
            return ret;
        }

        _executeinline uint32_t flags() const noexcept { return (b << 3) | (x << 2) | (r << 1) | w; }
        _executeinline uint32_t operand_size() const noexcept { return w == 1 ? 64 : 32; }
    };
    struct modrm_t
    {
        uint8_t _rm : 3;
        uint8_t _reg : 3;
        uint8_t  mod : 2;
        uint8_t reg(rex_t rex) noexcept
        {
            return (rex.r << 4) | _reg;
        }
        uint8_t rm(rex_t rex) noexcept
        {
            return (rex.b << 4) | _rm;
        }

        struct mode_t
        {
            enum vt
            {
                register_direct = 0b11,
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

        static modrm_t make(register_t dst) noexcept
        {
            switch (dst)
            {
            case register_t::RAX:
            case register_t::EAX:
                return { register_code_t::AX, 0, mode_t::register_direct };
                break;
            case register_t::RCX:
            case register_t::ECX:
                return { register_code_t::CX, 0, mode_t::register_direct };
                break;
            case register_t::RDX:
            case register_t::EDX:
                return { register_code_t::DX, 0, mode_t::register_direct };
                break;
            case register_t::EBX:
            case register_t::RBX:
                return { register_code_t::BX, 0, mode_t::register_direct };
                break;

            case register_t::ESP:
            case register_t::RSP:
                return { register_code_t::SP, 0, mode_t::register_direct };
                break;
            case register_t::EBP:
            case register_t::RBP:
                return { register_code_t::BP, 0, mode_t::register_direct };
                break;
            case register_t::ESI:
            case register_t::RSI:
                return { register_code_t::SI, 0, mode_t::register_direct };
                break;
            case register_t::EDI:
            case register_t::RDI:
                return { register_code_t::DI, 0, mode_t::register_direct };
                break;
            }

            __assert(false);
            return { 0,0,0 };
        }

        static modrm_t make(mode_t mode, register_t reg, register_t regmem) noexcept
        {
            modrm_t ret;
            ret.mod = mode;

            switch (reg)
            {
            case register_t::RAX:
            case register_t::EAX:
                ret._reg = register_code_t::AX;
                break;
            case register_t::RCX:
            case register_t::ECX:
                ret._reg = register_code_t::CX;
                break;
            case register_t::RDX:
            case register_t::EDX:
                ret._reg = register_code_t::DX;
                break;
            case register_t::EBX:
            case register_t::RBX:
                ret._reg = register_code_t::BX;
                break;

            case register_t::ESP:
            case register_t::RSP:
                ret._reg = register_code_t::SP;
                break;
            case register_t::EBP:
            case register_t::RBP:
                ret._reg = register_code_t::BP;
                break;
            case register_t::ESI:
            case register_t::RSI:
                ret._reg = register_code_t::SI;
                break;
            case register_t::EDI:
            case register_t::RDI:
                ret._reg = register_code_t::DI;
                break;
            }

            switch (regmem)
            {
            case register_t::RAX:
            case register_t::EAX:
                ret._rm = register_code_t::AX;
                break;
            case register_t::RCX:
            case register_t::ECX:
                ret._rm = register_code_t::CX;
                break;
            case register_t::RDX:
            case register_t::EDX:
                ret._rm = register_code_t::DX;
                break;
            case register_t::EBX:
            case register_t::RBX:
                ret._rm = register_code_t::BX;
                break;

            case register_t::ESP:
            case register_t::RSP:
                ret._rm = register_code_t::SP;
                break;
            case register_t::EBP:
            case register_t::RBP:
                ret._rm = register_code_t::BP;
                break;
            case register_t::ESI:
            case register_t::RSI:
                ret._rm = register_code_t::SI;
                break;
            case register_t::EDI:
            case register_t::RDI:
                ret._rm = register_code_t::DI;
                break;
            }

            return ret;
        }
    };
    struct sib_t
    {
        uint8_t _base : 3;
        uint8_t _index : 3;
        uint8_t _scale : 2;
        uint8_t index(rex_t rex) const noexcept
        {
            return (rex.x << 4) | _index;
        }
        uint8_t base(rex_t rex) const noexcept
        {
            return (rex.b << 4) | _base;
        }
        uint8_t scale() const noexcept
        {
            return 1 << _scale;
        }

        register_t index_register() const noexcept
        {
            switch (_index)
            {
            case 0b000: return register_t::RAX;
            case 0b001: return register_t::RCX;
            case 0b010: return register_t::RDX;
            case 0b011: return register_t::RBX;
            case 0b100: return register_t::none;
            case 0b101: return register_t::RBP;
            case 0b110: return register_t::RSI;
            case 0b111: return register_t::RDI;
            }
            return register_t::invalid;
        }

        //Table 1-13. SIB.base encodings for ModRM.r/m = 100b
        register_t base_register(modrm_t modrm) const noexcept
        {
            switch (_index)
            {
            case 0b000: return register_t::RAX;
            case 0b001: return register_t::RCX;
            case 0b010: return register_t::RDX;
            case 0b011: return register_t::RBX;
            case 0b100: return register_t::RSP;
                // if mode == 00, then the base is just the 32 bit displacement in the opcode
                // if mode == 01, then the base is [rBP] + the 8  bit displacement in the opcode
                // if mode == 10, then the base is [rBP] + the 32 bit displacement in the opcode
            case 0b101: return modrm.mod == 0 ? register_t::none : register_t::RBP;
            case 0b110: return register_t::RSI;
            case 0b111: return register_t::RDI;
            }
            return register_t::invalid;
        }
    };
#pragma pack(pop)


    rex_t push_register_op(buffervec<uint8_t>& assembly, register_t reg, uint8_t opcode) noexcept
    {
        rex_t rex = rex_t::make(reg);
        if (rex.flags() != 0) assembly.push(rex);
        assembly.push(opcode);
        return rex;
    }

    void push_indirect_op(buffervec<uint8_t>& assembly, register_t indirect_target, uint32_t operand_size, uint8_t opcode) noexcept
    {
        if (operand_size == 64)
        {
            rex_t rex;
            rex.w = 1;
            assembly.push(rex);
        }
        assembly.push(opcode);

        modrm_t modrm;
        modrm._reg = 0;
        modrm.mod = 0;
        modrm._rm = register_code_t(indirect_target);

        assembly.push(modrm);

        if (indirect_target == register_t::SP || indirect_target == register_t::ESP || indirect_target == register_t::RSP)
        {
            sib_t sib;
            sib._base = 0b100;
            sib._index = 0b100;
            sib._scale = 0;

            assembly.push(sib);
        }

    }

    uint32_t parse_indirect_op(buffervec<uint8_t>& assembly, const buffer<char>& _operand, uint32_t operand_size, uint8_t opcode) noexcept
    {
        buffer<char> operand = buffer<char>::from_ptr(_operand.ptr + 1, _operand.size - 2);

        register_t r = register_t(operand);
        if (r != register_t::invalid) push_indirect_op(assembly, r, operand_size, opcode);

        return operand_size;
    }

    //
    // [legacy-prefix <= 5x] [rex-prefix] [opcode-map escape] opcode [modrm] [sib] [imm]
    //
    struct instruction_t
    {
        // placeholder: legacy-prefix
        rex_t    rex;
        uint8_t  opcode;
        modrm_t  modrm;
        bool     has_modrm = false;
        sib_t    sib;
        uint64_t immediate;
        bool     has_immediate = false;

        error emit(buffervec<uint8_t>& assembly) noexcept
        {
            if (rex.flags() != 0) if (!assembly.push(rex)) return __error(errors::out_of_memory);
            if (!assembly.push(opcode)) return __error(errors::out_of_memory);
            if (has_modrm)
            {
                if (!assembly.push(modrm)) return __error(errors::out_of_memory);
                if (modrm._rm == 0b100 && modrm.mod != 0b11)
                {
                    if (!assembly.push(sib)) return __error(errors::out_of_memory);
                }
            }
            return error();
        }
    };

    struct argtype_t
    {
        enum vt
        {
            EAX,
            RAX,
            regmem32,
            regmem64,
            reg32,
            reg64,
            imm8,
            imm16,
            imm32,
            imm64,
            unused
        } value;

        __enum(argtype_t);
    };

    struct mnemonic_t
    {
        char      label[16]    = { 0 };
        uint8_t   operand_size = 32;
        argtype_t arg1         = argtype_t::unused;
        argtype_t arg2         = argtype_t::unused;

        _executeinline bool operator==(const mnemonic_t& other) const noexcept
        {
            return operand_size == other.operand_size
                && arg1 == other.arg1
                && arg2 == other.arg2
                && buffer<char>::from_ptr(label, 16) == buffer<char>::from_ptr(other.label, 16);
        }
    };

    struct opcode_t
    {
        uint8_t code;
        string  description;
    };

    namespace errors
    {
        namespace assembler
        {
            _inline error InvalidInstruction(error_scope::cgengine, 120000, "InvalidInstruction");
            _inline error InvalidArgument(error_scope::cgengine, 120001, "InvalidArgument");
            _inline error UnexpectedEndOfStatement(error_scope::cgengine, 120002, "UnexpectedEndOfStatement");
        }
    }

    umap<mnemonic_t, opcode_t, value_type_hash<mnemonic_t>> opcode_map {
        { { "add", 32, argtype_t::EAX,      argtype_t::imm32    }, { 0x05, s("Add imm32 to EAX") } }, 
        { { "add", 64, argtype_t::RAX,      argtype_t::imm32    }, { 0x05, s("Add sign-extended imm32 to RAX") } }, 
                                                               
        { { "add", 32, argtype_t::regmem32, argtype_t::imm32    }, { 0x81, s("Add imm32 to reg/mem32") } },
        { { "add", 64, argtype_t::regmem64, argtype_t::imm32    }, { 0x81, s("Add sign-extended imm32 to reg/mem64") } },
                                                               
        { { "add", 32, argtype_t::regmem32, argtype_t::imm8     }, { 0x83, s("Add sign-extended imm8 to reg/mem32") } },
        { { "add", 64, argtype_t::regmem64, argtype_t::imm8     }, { 0x83, s("Add sign-extended imm8 to reg/mem64") } },
                                                               
        { { "add", 32, argtype_t::regmem32, argtype_t::reg32    }, { 0x01, s("Add reg32 to reg/mem32") } },
        { { "add", 64, argtype_t::regmem64, argtype_t::reg64    }, { 0x01, s("Add reg64 to reg/mem64") } },

        { { "add", 32, argtype_t::reg32,    argtype_t::regmem32 }, { 0x03, s("Add reg/mem32 to reg32") } },
        { { "add", 64, argtype_t::reg64,    argtype_t::regmem64 }, { 0x03, s("Add reg/mem64 to reg64") } },
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

    error parse_argument(mnemonic_t& mnemonic, argtype_t* parg, instruction_t& ret, nextany_tokenizer::const_iterator_t& iter, const nextany_tokenizer::const_iterator_t& end)
    {
        if (iter->value[0] == '-')
        {
            __usingif(parsed, parse::integer64(iter->value.view<uint8_t>()))
            {
                *((int64_t*)&ret.immediate) = parsed;

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
                    mnemonic.operand_size = 64;
                }
            }
        }
        else if (iter->value[0] >= '0' && iter->value[0] <= '9')
        {
            __checkedinto(ret.immediate, parse::uinteger64(iter->value.view<uint8_t>()));

            if (std::numeric_limits<uint8_t>::lowest() <= ret.immediate && ret.immediate <= std::numeric_limits<uint8_t>::max())
            {
                *parg = argtype_t::imm8;
            }
            else if (std::numeric_limits<uint16_t>::lowest() <= ret.immediate && ret.immediate <= std::numeric_limits<uint16_t>::max())
            {
                *parg = argtype_t::imm16;
            }
            else if (std::numeric_limits<uint32_t>::lowest() <= ret.immediate && ret.immediate <= std::numeric_limits<uint32_t>::max())
            {
                *parg = argtype_t::imm32;
            }
            else
            {
                *parg = argtype_t::imm64;
                mnemonic.operand_size = 64;
            }
        }
        else if (iter->value[0] == '[')
        {

        }
        else if (iter->value == "eax" || iter->value == "EAX")
        {
            *parg = argtype_t::EAX;
        }
        else if (iter->value == "rax" || iter->value == "RAX")
        {
            *parg = argtype_t::RAX;
            mnemonic.operand_size = 64;
        }
        else
        {
            register_t reg(iter->value);
            if (reg == register_t::invalid)
            {
                return __error_msg(errors::assembler::InvalidArgument, "Argument "_s + to_string(iter->value) + " not recognized");
            }

            if (reg.size() == 64)
            {
                mnemonic.operand_size = 64;
                *parg = argtype_t::reg64;
            }
            else
            {
                *parg = argtype_t::reg32;
            }
        }

        return error();
    }
    optional<instruction_t> parse_instruction(nextany_tokenizer::const_iterator_t& iter, const nextany_tokenizer::const_iterator_t& end) noexcept
    {
        instruction_t ret;
        if (iter->value.size >= 16)
        {
            return __error_msg(errors::assembler::InvalidInstruction, "Label "_s + to_string(iter->value) + " is not a recognized instruction (length exceeded 16)");
        }

        mnemonic_t mnemonic;
        memcpy(mnemonic.label, iter->value.ptr, iter->value.size);

        if (++iter != end && clear_whitespace_inline(iter, end))
        {
            __checked(parse_argument(mnemonic, &mnemonic.arg1, ret, iter, end));
            if (iter != end && iter->delimiter == ',')
            {
                if (++iter == end) return __error_msg(errors::assembler::UnexpectedEndOfStatement, "Label "_s + to_string(iter->value) + ": Ended in a ','");
                __checked(parse_argument(mnemonic, &mnemonic.arg1, ret, iter, end));
            }
        }

        //if (arg[0] == '[')
        //{
        //    // indirect addressing mode
        //    instruction.has_modrm = true;
        //
        //}
        //else if (arg[0] >= '9')
        //{
        //    // direct register mode
        //    instruction.has_modrm = true;
        //    instruction.modrm.mod = modrm_t::mode_t::register_direct;
        //
        //}
        //else
        //{
        //    // parse immediate
        //
        //}
        return ret;
    }

    optional<buffervec<uint8_t>> assemble(const string& code) noexcept
    {
        buffervec<uint8_t> ret;

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
            __checkedinto(instruction, parse_instruction(b, e));
            __checked(instruction.emit(ret));
        }

        return ret;
    }

    using opemit = error(*)(buffervec<uint8_t>& assembly, const string& operands);

#define __ms__(x) #x
#define __ms(x) __ms__(x)
#define __moveop(o, c) if (!++optok) return __error_msg(errors::unexpected_value, "Instruction " o  " requires " __ms(c) " operands." );

    single_tokenizer optok;
    umap<string, opemit> opcode_emitter = {
        {
            s("add"),
            [](buffervec<uint8_t>& assembly, const string& operands) {
                optok.set(operands, ',');
                auto operand1 = optok.value();
                __moveop("add", 2);

                __useif(imm, parse::integer64trim(optok.value()))
                {
                    //
                    // ADD reg/mem16, imm8 83 /0 ib            Add sign-extended imm8 to reg/mem16
                    // ADD reg/mem32, imm8 83 /0 ib            Add sign-extended imm8 to reg/mem32.
                    // ADD reg/mem64, imm8 83 /0 ib            Add sign-extended imm8 to reg/mem64.
                    // 8-bit immediate
                    if (imm <= std::numeric_limits<int8_t>::max() && imm >= std::numeric_limits<int8_t>::lowest())
                    {
                        assembly.push((uint8_t)0x83);
                        assembly.push(modrm_t::make(register_t(operand1)));
                        assembly.push((int8_t)imm);
                    }
                    else if (imm <= std::numeric_limits<int32_t>::max() && imm >= std::numeric_limits<int32_t>::lowest())
                    {
                        assembly.push((uint8_t)0x05);
                        assembly.push(imm);
                    }
                }
                __else
                {
                    if (operand1[0] == '[')
                    {

                    }
                    else
                    {
                        if (optok.value()[0] == '[')
                        {

                        }
                        else
                        {
                            assembly.push((uint8_t)0x03);
                            assembly.push(modrm_t::make(modrm_t::mode_t::register_direct, operand1, optok.value()));
                        }
                    }
                }

                

                return error();
            }
        },
        {
            s("lea"),
            [](buffervec<uint8_t>& assembly, const string& operands) {

                /*
                LEA reg32, mem 8D /r Store effective address in a 32-bit register.
                LEA reg64, mem 8D /r Store effective address in a 64-bit register.
                */
                instruction_t instruction {
                    .rex = {
                        .w = 1
                    },
                    .opcode = 0x8D
                };


                return error();
            }
        },
        {
            s("mov"),
            [](buffervec<uint8_t>& assembly, const string& operands) {
                optok.set(operands, ',');
                auto operand1 = optok.value();
                __moveop("mov", 2);

                /*
                MOV reg32, imm32 B8 +rd id Move an 32-bit immediate value into a 32-bit register.
                MOV reg64, imm64 B8 +rq iq Move an 64-bit immediate value into a 64-bit register
                MOV reg/mem32, imm32 C7 /0 id Move a 32-bit immediate value to a 32-bit register or memory operand.
                MOV reg/mem64, imm32 C7 /0 id Move a 32-bit signed immediate value to a 64-bit register or memory operand.
                */
                __useif(imm, parse::integer64trim(optok.value()))
                {
                    // indirect
                    if (operand1[0] == '[')
                    {
                        if (imm <= std::numeric_limits<uint32_t>::max() && imm >= std::numeric_limits<uint32_t>::lowest())
                        {
                            parse_indirect_op(assembly, optok.value(), 32, 0xC7);
                            assembly.push((uint32_t)imm);
                        }
                        else if (imm <= std::numeric_limits<int32_t>::max() && imm >= std::numeric_limits<int32_t>::lowest())
                        {
                            parse_indirect_op(assembly, optok.value(), 64, 0xC7);
                            assembly.push((int32_t)imm);
                        }
                        else __assert(false);
                    }

                    // register direct
                    else
                    {
                        register_t r = register_t(operand1);
                        rex_t rex = push_register_op(assembly, r, (uint8_t)(0xB8 + (int32_t)register_code_t(r)));

                        if (rex.operand_size() == 32)
                        {
                            assembly.push((int32_t)imm);
                        }
                        else
                        {
                            assembly.push((int64_t)imm);
                        }
                    }
                }
                __else
                {

                }

                return error();
            }
        },
        {
            s("push"),
            [](buffervec<uint8_t>& assembly, const string& operands) {
                optok.set(operands, ',');
                
                /*
                    PUSH imm32 68 id Push a 32-bit immediate value onto the stack. (No prefix for encoding this in 64-bit mode.)
                    PUSH imm64 68 id Push a sign-extended 32-bit immediate value onto the stack.
                */
                __useif(imm, parse::integer32trim(optok.value()))
                {
                    assembly.push((uint8_t)(0x68));
                    assembly.push((int32_t)imm);
                }
                __else
                {

                }

                return error();
            }
        },
        {
            s("pop"),
            [](buffervec<uint8_t>& assembly, const string& operands) {

                /*
                    POP reg32 58 +rd Pop the top of the stack into a 32-bit register. (No prefix for encoding this in 64-bit mode.)
                    POP reg64 58 +rq Pop the top of the stack into a 64-bit register
                */
                optok.set(operands, ',');
                auto operand1 = optok.value();

                register_t r = register_t(operand1);
                rex_t rex = rex_t::make(r);

                if (rex.b != 0) assembly.push(rex);
                assembly.push((uint8_t)(0x58 + (int32_t)register_code_t(r)));

                return error();
            }
        },
        {
            s("ret"),
            [](buffervec<uint8_t>& assembly, const string& operands) {
                assembly.push((uint8_t)0xC3);
                return error();
            }
        }
    };




    error main() noexcept
    {
        buffervec<uint8_t> assembly;
        __checkedinto(assembly, assemble(R"(
                                    add eax, 350
                                    ret
                                )"));

        //opcode_emitter[s("mov")](assembly, "eax,350");
        //opcode_emitter[s("mov")](assembly, "rax,350");
        //opcode_emitter[s("add")](assembly, "eax,ecx");
        //opcode_emitter[s("push")](assembly, "4");
        //opcode_emitter[s("mov")](assembly, "[rsp],8");
        //opcode_emitter[s("pop")](assembly, "eax");
        //opcode_emitter[s("ret")](assembly, "");


        void* mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        memcpy(mem, assembly.ptr(), assembly.size());
        using cd = int(*)(long long int a, int b, long long int c, int d);
        int b = ((cd)mem)(4, 5,60000000000ll, 7);

        return error();
    }
}




int32_t main()
{
    cgengine::main();
}






