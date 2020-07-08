
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

            case register_t::R11: case register_t::R11D:
            case register_t::EBX:
            case register_t::RBX: value = BX; break;

            case register_t::R9: case register_t::R9D:
            case register_t::ECX:
            case register_t::RCX: value = CX; break;

            case register_t::R10: case register_t::R10D:
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
            regmem32 = EAX + 4,
            regmem64 = EAX + 5,
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
            if (value == EAX || value == regmem32 || value == reg32 || value == imm32 || value == imm16 || value == imm8) return 32;
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
            return reg >= register_t::R8B && reg <= register_t::R15;
        }
        _executeinline bool is_index_ex() const noexcept
        {
            return mode != modrm_t::mode_t::register_direct && index >= register_t::R8B && index <= register_t::R15;
        }
        _executeinline bool is_base_ex() const noexcept
        {
            return mode != modrm_t::mode_t::register_direct && base >= register_t::R8B && base <= register_t::R15;
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
    };

    struct opcode_t
    {
        uint8_t code;
        const char* description;
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
        } flagvars;
    };

    //
    // [legacy-prefix <= 5x] [rex-prefix] [opcode-map escape] opcode [modrm] [sib] [imm]
    //
    struct instruction_t
    {
        // placeholder: legacy-prefix
        opcode_t    opcode;
        argument_t  args[4];
        signature_t signature;

    private:
        bool compute_modrmsib(argtype_t type, argument_t arg, modrm_t& target_modrm, sib_t& target_sib, uint32_t* sibdisp)
        {
            if (!type.is_modrm()) return false;

            if (type == argtype_t::reg32 || type == argtype_t::reg64)
            {
                target_modrm.reg = register_code_t(arg.reg);
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
            if (type.is_immediate())
            {
                     if (type == argtype_t::imm8  && !assembly.push(*((uint8_t*)&arg.imm))) return __error(errors::out_of_memory);
                else if (type == argtype_t::imm16 && !assembly.push(*((uint16_t*)&arg.imm))) return __error(errors::out_of_memory);
                else if (type == argtype_t::imm32 && !assembly.push(*((uint32_t*)&arg.imm))) return __error(errors::out_of_memory);
                else if (type == argtype_t::imm64 && !assembly.push(arg.imm)) return __error(errors::out_of_memory);
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
            uint8_t code = opcode.code + (opcode.flags.has(opcode_flags_t::register_adjusted) ? (uint8_t)register_code_t(args[0].reg) : 0);
            if (!assembly.push(code)) return __error(errors::out_of_memory);
            if (opcode.flags.has(opcode_flags_t::multibyte_opcode))
            {
                for (uint8_t i = 0; i < opcode.flagvars._f_opcode_count; ++i)
                {
                    if (!assembly.push(opcode.flagvars._f_opcode_extra[i])) return __error(errors::out_of_memory);
                }
            }

            return error();
        }
    public:

        error emit(buffervec<uint8_t>& assembly) noexcept
        {

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
                    .b = (uint8_t)((signature.types[0].is_modrm() && args[0].is_reg_ex())   || (signature.types[1].is_modrm() && args[1].is_reg_ex()) ? 1 : 0),
                    .x = (uint8_t)((signature.types[0].is_modrm() && args[0].is_index_ex()) || (signature.types[1].is_modrm() && args[1].is_index_ex()) ? 1 : 0),
                    .r = (uint8_t)((signature.types[0].is_modrm() && args[0].is_base_ex())  || (signature.types[1].is_modrm() && args[1].is_base_ex()) ? 1 : 0),
                    .w = (uint8_t)((signature.operand_size() == 32 ? 0 : 1))
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

            return error();
        }
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
        }
    }


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
        { { "add",  argtype_t::EAX,      argtype_t::imm32    }, { 0x05, ("Add imm32 to EAX") } },
        { { "add",  argtype_t::RAX,      argtype_t::imm32    }, { 0x05, ("Add sign-extended imm32 to RAX") } },
        { { "add",  argtype_t::regmem32, argtype_t::imm32    }, { 0x81, ("Add imm32 to reg/mem32") } },
        { { "add",  argtype_t::regmem64, argtype_t::imm32    }, { 0x81, ("Add sign-extended imm32 to reg/mem64") } },
        { { "add",  argtype_t::regmem32, argtype_t::imm8     }, { 0x83, ("Add sign-extended imm8 to reg/mem32") } },
        { { "add",  argtype_t::regmem64, argtype_t::imm8     }, { 0x83, ("Add sign-extended imm8 to reg/mem64") } },
        { { "add",  argtype_t::regmem32, argtype_t::reg32    }, { 0x01, ("Add reg32 to reg/mem32") } },
        { { "add",  argtype_t::regmem64, argtype_t::reg64    }, { 0x01, ("Add reg64 to reg/mem64") } },
        { { "add",  argtype_t::reg32,    argtype_t::regmem32 }, { 0x03, ("Add reg/mem32 to reg32") } },
        { { "add",  argtype_t::reg64,    argtype_t::regmem64 }, { 0x03, ("Add reg/mem64 to reg64") } },


        { { "adox", argtype_t::reg32,    argtype_t::regmem32 }, { 0xF3, "Unsigned add with overflow flag", opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup, 
            { ._f_opcode_count = 3, ._f_opcode_extra = { 0x0F, 0x38, 0xF6 }, ._f_cpuid_reqs = 1, ._f_cpuid_lookups = { &cpu_queries["ADX"] } } } },
        { { "adox", argtype_t::reg64,    argtype_t::regmem64 }, { 0xF3, "Unsigned add with overflow flag", opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup, 
            { ._f_opcode_count = 3, ._f_opcode_extra = { 0x0F, 0x38, 0xF6 }, ._f_cpuid_reqs = 1, ._f_cpuid_lookups = { &cpu_queries["ADX"] } } } },


        { { "and",  argtype_t::EAX,      argtype_t::imm32    }, { 0x25, ("and the contents of EAX with an immediate 32-bit value and store the result in EAX.") } },
        { { "and",  argtype_t::RAX,      argtype_t::imm32    }, { 0x25, ("and the contents of RAX with an immediate 32-bit value and store the result in RAX.") } },
        { { "and",  argtype_t::regmem32, argtype_t::imm32    }, { 0x81, ("and the contents of reg/mem32 with imm32."),                 opcode_flags_t::regopcode_ext, { ._f_regopcode_ext = 4 } } },
        { { "and",  argtype_t::regmem64, argtype_t::imm32    }, { 0x81, ("and the contents of reg/mem64 with a sign-extended imm32."), opcode_flags_t::regopcode_ext, { ._f_regopcode_ext = 4 } } },
        { { "and",  argtype_t::regmem32, argtype_t::imm8     }, { 0x83, ("and the contents of reg/mem32 with a sign-extended imm8"),   opcode_flags_t::regopcode_ext, { ._f_regopcode_ext = 4 } } },
        { { "and",  argtype_t::regmem64, argtype_t::imm8     }, { 0x83, ("and the contents of reg/mem64 with a sign-extended imm8"),   opcode_flags_t::regopcode_ext, { ._f_regopcode_ext = 4 } } },
        { { "and",  argtype_t::regmem32, argtype_t::reg32    }, { 0x21, ("and the contents of a 32 bit register or memory location with the contents of a 32-bit register") } },
        { { "and",  argtype_t::regmem64, argtype_t::reg64    }, { 0x21, ("and the contents of a 64-bit register or memory location with the contents of a 64-bit register") } },
        { { "and",  argtype_t::reg32,    argtype_t::regmem32 }, { 0x23, ("and the contents of a 32-bit register with the contents of a 32-bit memory location or register.") } },
        { { "and",  argtype_t::reg64,    argtype_t::regmem64 }, { 0x23, ("and the contents of a 64-bit register with the contents of a 64-bit memory location or register.") } },


        { { "andn", argtype_t::reg32,    argtype_t::reg32,    argtype_t::regmem32 }, 
          { 
              0xF2, 
              "Performs a bit-wise logical and of the second source operand and the one's complement of the first source operand and stores the result into the destination operand.",
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
              "ANDN dest, src1, src2 : Performs a bit-wise logical and of the second source operand and the one's complement of the first source operand and stores the result into the destination operand.",
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
              "BEXTR dest, src, cntl : Extracts a contiguous field of bits from the first source operand, as specified by the control field setting in the second source operand and puts the extracted field into the least significant bit positions of the destination.The remaining bits in the destination register are cleared to 0.",
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
              "BEXTR dest, src, cntl : Extracts a contiguous field of bits from the first source operand, as specified by the control field setting in the second source operand and puts the extracted field into the least significant bit positions of the destination.The remaining bits in the destination register are cleared to 0.",
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
              "BEXTR dest, src, cntl : Extracts a contiguous field of bits from the first source operand, as specified by the control field setting in the second source operand and puts the extracted field into the least significant bit positions of the destination.The remaining bits in the destination register are cleared to 0.",
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
              "BEXTR dest, src, cntl : Extracts a contiguous field of bits from the first source operand, as specified by the control field setting in the second source operand and puts the extracted field into the least significant bit positions of the destination.The remaining bits in the destination register are cleared to 0.",
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
              "BLSI dest, src : Clears all bits in the source operand except for the least significant bit that is set to 1 and writes the result to the destination.If the source is all zeros, the destination is written with all zeros.",
              opcode_flags_t::vex_extended | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 3,

                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = {
                    &cpu_queries["BMI"]
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
              "BLSI dest, src : Clears all bits in the source operand except for the least significant bit that is set to 1 and writes the result to the destination.If the source is all zeros, the destination is written with all zeros.",
              opcode_flags_t::vex_extended | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 3,

                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = {
                    &cpu_queries["BMI"]
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
              "BLSMSK dest, src : Forms a mask with bits set to 1 from bit 0 up to and including the least significant bit position that is set to 1 in the source operand and writes the mask to the destination.If the value of the source operand is zero, the destination is written with all ones.",
              opcode_flags_t::vex_extended | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 2,

                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = {
                    &cpu_queries["BMI"]
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
              "BLSMSK dest, src : Forms a mask with bits set to 1 from bit 0 up to and including the least significant bit position that is set to 1 in the source operand and writes the mask to the destination.If the value of the source operand is zero, the destination is written with all ones.",
              opcode_flags_t::vex_extended | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::regopcode_ext,
              {
                ._f_regopcode_ext = 2,

                ._f_cpuid_reqs = 1,
                ._f_cpuid_lookups = {
                    &cpu_queries["BMI"]
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

        { { "cpuid",  argtype_t::unused, argtype_t::unused   }, { 0x0F, 
                                                                  ("Returns information about the processor and its capabilities. EAX specifies the function number, and the data is returned in EAX, EBX, ECX, EDX."), 
                                                                  opcode_flags_t::multibyte_opcode, 0, 
                                                                  1, { 0xA2 } } },

                   
                   
                   
        { { "mov",  argtype_t::regmem32, argtype_t::reg32    }, { 0x89, ("Move the contents of a 32-bit register to a 32-bit destination register or memory operand") } },
        { { "mov",  argtype_t::regmem64, argtype_t::reg64    }, { 0x89, ("Move the contents of a 64-bit register to a 64-bit destination register or memory operand") } },
                   
        { { "mov",  argtype_t::reg32,    argtype_t::regmem32 }, { 0x8B, ("Move the contents of a 32-bit register or memory to a 32-bit destination register") } },
        { { "mov",  argtype_t::reg64,    argtype_t::regmem64 }, { 0x8B, ("Move the contents of a 64-bit register or memory to a 64-bit destination register") } },
                   
        { { "mov",  argtype_t::reg32,    argtype_t::imm32    }, { 0xB8, ("Move a 32-bit immediate value into a 32-bit register"), opcode_flags_t::register_adjusted } },
        { { "mov",  argtype_t::reg64,    argtype_t::imm64    }, { 0xB8, ("Move a 64-bit immediate value into a 64-bit register"), opcode_flags_t::register_adjusted } },
                                                             
        { { "mov",  argtype_t::regmem32, argtype_t::imm32    }, { 0xC7, ("Move a 32-bit immediate value into a 32-bit register or memory operand") } },
        { { "mov",  argtype_t::regmem64, argtype_t::imm32    }, { 0xC7, ("Move a 32-bit immediate value into a 64-bit register or memory operand") } },


        { { "pop",  argtype_t::regmem64, argtype_t::unused   }, { 0x8F, ("Pop the top of the stack into a 64-bit register or memory.") } },
        { { "pop",  argtype_t::reg64,    argtype_t::unused   }, { 0x58, ("Pop the top of the stack into a 64-bit register."), opcode_flags_t::register_adjusted } },

        //{ { "push", argtype_t::regmem32, argtype_t::unused   }, { 0xFF, ("Push the contents of a 32-bit register or memory operand onto the stack (No prefix for encoding this in 64-bit mode).") } },
        { { "push", argtype_t::regmem64, argtype_t::unused   }, { 0xFF, ("Push the contents of a 64-bit register or memory operand onto the stack."), opcode_flags_t::regopcode_ext, { ._f_regopcode_ext = 6 } } },
        { { "push", argtype_t::reg64,    argtype_t::unused   }, { 0x50, ("Push the contents of a 64-bit register onto the stack."), opcode_flags_t::register_adjusted } },
        { { "push", argtype_t::imm32,    argtype_t::unused   }, { 0x68, ("Push a sign-extended 32-bit immediate value onto the stack.") } },

        { { "ret",  argtype_t::unused,   argtype_t::unused   }, { 0xC3, ("Near return to the calling procedure.") } },


        { { "sub",  argtype_t::EAX,      argtype_t::imm32    }, { 0x2D, ("Add imm32 to EAX") } },
        { { "sub",  argtype_t::RAX,      argtype_t::imm32    }, { 0x2D, ("Add sign-extended imm32 to RAX") } },
        { { "sub",  argtype_t::regmem32, argtype_t::imm32    }, { 0x81, ("Add imm32 to reg/mem32"),               opcode_flags_t::regopcode_ext, { ._f_regopcode_ext = 5 } } },
        { { "sub",  argtype_t::regmem64, argtype_t::imm32    }, { 0x81, ("Add sign-extended imm32 to reg/mem64"), opcode_flags_t::regopcode_ext, { ._f_regopcode_ext = 5 } } },
        { { "sub",  argtype_t::regmem32, argtype_t::imm8     }, { 0x83, ("Add sign-extended imm8 to reg/mem32"),  opcode_flags_t::regopcode_ext, { ._f_regopcode_ext = 5 } } },
        { { "sub",  argtype_t::regmem64, argtype_t::imm8     }, { 0x83, ("Add sign-extended imm8 to reg/mem64"),  opcode_flags_t::regopcode_ext, { ._f_regopcode_ext = 5 } } },
        { { "sub",  argtype_t::regmem32, argtype_t::reg32    }, { 0x29, ("Add reg32 to reg/mem32") } },
        { { "sub",  argtype_t::regmem64, argtype_t::reg64    }, { 0x29, ("Add reg64 to reg/mem64") } },
        { { "sub",  argtype_t::reg32,    argtype_t::regmem32 }, { 0x2B, ("Add reg/mem32 to reg32") } },
        { { "sub",  argtype_t::reg64,    argtype_t::regmem64 }, { 0x2B, ("Add reg/mem64 to reg64") } },
        
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

    optional<argument_t> parse_argument(argtype_t* parg, nextany_tokenizer::const_iterator_t& iter, const nextany_tokenizer::const_iterator_t& end)
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
                    *parg = argtype_t::regmem64;
                }
                else
                {
                    *parg = argtype_t::regmem32;
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
                        *parg = argtype_t::regmem64;
                    }
                    else
                    {
                        *parg = argtype_t::regmem32;
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
    optional<instruction_t> parse_instruction(nextany_tokenizer::const_iterator_t& iter, const nextany_tokenizer::const_iterator_t& end) noexcept
    {
        instruction_t ret;
        if (iter->value.size >= 16)
        {
            return __error_msg(errors::assembler::invalid_instruction, "Label "_s + to_string(iter->value) + " is not a recognized instruction (length exceeded 16)");
        }

        memcpy(ret.signature.label, iter->value.ptr, iter->value.size);

        int32_t argcount = 0;
        if (iter->delimiter != '\n' && ++iter != end && clear_whitespace_inline(iter, end))
        {

            do
            {
                if (argcount == 4)
                {
                    return __error_msg(errors::assembler::invalid_argument, "Argument count cannot exceed 4");
                }

                __checkedinto(ret.args[argcount], parse_argument(&ret.signature.types[argcount], iter, end));
                ++argcount;

                if (iter->delimiter == ',')
                {
                    if (++iter == end || !clear_whitespace_inline(iter, end)) return __error_msg(errors::assembler::unexpected_end_of_statment, "Label "_s + to_string(iter->value) + ": Ended in a ','");
                }
                else break;

            } while (true);
        }
        ++iter;

        // find overload
        signature_t test = ret.signature;
        do
        {
            if (auto op = opcode_map.find(test); op != opcode_map.end())
            {
                ret.signature = test;
                ret.opcode = op->second;
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
                            return __error_msg(errors::assembler::instruction_overload_not_found, "Could not find overload for label "_s + (test.label));
                        }
                        test.types[i] = ret.signature.types[i];
                    }
                }

                valid_overload = true;
                for (int i = 0; i < 4; ++i)
                {
                    if (test.types[i].operand_size() < ret.signature.types[i].operand_size())
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

#define __ms__(x) #x
#define __ms(x) __ms__(x)

    void* mem = nullptr;

    optional<uint32_t> cpuq_t::execute()
    {
        buffervec<uint8_t> assembly;

        string header = R"(
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
    ret
)";

        __checkedinto(assembly, assemble(header + "mov eax, " + fn + "\nmov ecx, " + subfn + "\n" + footer));
        memcpy(mem, assembly.ptr(), assembly.size());

        using cd = int(*)(uint32_t* rax, uint32_t* rbx, uint32_t* rcx, uint32_t* rdx);

        uint32_t result[4];
        ((cd)mem)(result, result + 1, result + 2, result + 3);

        return (result[(int32_t)regpos] >> bit_start) & mask(bit_end - bit_start);
    }

    error main() noexcept
    {
        buffervec<uint8_t> assembly;
        __checkedinto(assembly, assemble(R"(
                                    mov  eax, 3002
                                    blsi eax, eax
                                    ret
                                )"));

        mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);


        printf("Has ADX: %s\n",  cpu_queries["ADX"].execute() == 1 ? "true" : "false");
        printf("Has BMI1: %s\n", cpu_queries["BMI1"].execute() == 1 ? "true" : "false");
        printf("Has TBM: %s\n", cpu_queries["TBM"].execute() == 1 ? "true" : "false");

        //uint32_t v1 = cpu_queries["L1DcSize"].execute();
        //uint32_t v2 = cpu_queries["L1IcSize"].execute();
        //uint32_t v3 = cpu_queries["L1DcLinesPerTag"].execute();
        //uint32_t v4 = cpu_queries["L1DcLineSize"].execute();



        memcpy(mem, assembly.ptr(), assembly.size());
        using cd = int(*)(uint32_t* rax, uint32_t* rbx, uint32_t* rcx, uint32_t* rdx);

        uint32_t rax, rbx, rcx, rdx;
        int b = ((cd)mem)(&rax, &rbx, &rcx, &rdx);




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






