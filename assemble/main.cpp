
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
        uint8_t rm : 3;
        uint8_t reg : 3;
        uint8_t mod : 2;

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
        uint8_t base  : 3 = 0;
        uint8_t index : 3 = 0;
        uint8_t scale : 2 = 0;
    };
#pragma pack(pop)


    rex_t pushregister_op(buffervec<uint8_t>& assembly, register_t reg, uint8_t opcode) noexcept
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
        modrm.reg = 0;
        modrm.mod = 0;
        modrm.rm = register_code_t(indirect_target);

        assembly.push(modrm);

        if (indirect_target == register_t::SP || indirect_target == register_t::ESP || indirect_target == register_t::RSP)
        {
            sib_t sib;
            sib.base = 0b100;
            sib.index = 0b100;
            sib.scale = 0;

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


    struct argtype_t
    {
        enum vt
        {
            EAX      = 0b10000000,
            RAX      = EAX + 1,
            reg32    = EAX + 2,
            reg64    = EAX + 3,
            regmem32 = EAX + 4,
            regmem64 = EAX + 5,
            imm8     = 0b00010000,
            imm16    = imm8 + 1,
            imm32    = imm8 + 2,
            imm64    = imm8 + 3,
            unused
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
        argtype_t arg1 = argtype_t::unused;
        argtype_t arg2 = argtype_t::unused;

        uint32_t operand_size() const noexcept
        {
            return (
                arg1 == argtype_t::RAX
                || arg2 == argtype_t::RAX
                || arg1 == argtype_t::regmem64
                || arg2 == argtype_t::regmem64
                || arg1 == argtype_t::reg64
                || arg2 == argtype_t::reg64
                || arg1 == argtype_t::imm64
                || arg2 == argtype_t::imm64
                ) ? 64 : 32;
        }

        _executeinline bool operator==(const signature_t& other) const noexcept
        {
            return arg1 == other.arg1
                && arg2 == other.arg2
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
        uint32_t   disp  = 0;

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
            register_adjusted = 0b00000001
        } value;
        __enum(opcode_flags_t);
        _executeinline bool has(vt v) noexcept
        {
            return (value & v) != 0;
        }
    };
    struct opcode_t
    {
        uint8_t code;
        string  description;
        opcode_flags_t flags = opcode_flags_t::none;
    };


    //
    // [legacy-prefix <= 5x] [rex-prefix] [opcode-map escape] opcode [modrm] [sib] [imm]
    //
    struct instruction_t
    {
        // placeholder: legacy-prefix
        opcode_t   opcode;
        argument_t arg1, arg2;
        signature_t signature;

    private:
        bool apply_modrmsib(argtype_t type, argument_t arg, modrm_t& target_modrm, sib_t& target_sib)
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
                target_modrm.rm = register_code_t(arg.reg);

                // sib indicator
                if (target_modrm.mod != modrm_t::mode_t::register_direct
                    && target_modrm.rm == 0b100)
                {
                    target_sib.base = register_code_t(arg.base);
                    target_sib.index = register_code_t(arg.index);
                    target_sib.scale = arg.scale;
                    return true;
                }
                return false;
            } 
            __assert(false);
            return false;
        }
    public:

        error emit(buffervec<uint8_t>& assembly) noexcept
        {
            rex_t rex{
                .b = (uint8_t)((signature.arg1.is_modrm() && arg1.is_reg_ex())   || (signature.arg2.is_modrm() && arg2.is_reg_ex())   ? 1 : 0),
                .x = (uint8_t)((signature.arg1.is_modrm() && arg1.is_index_ex()) || (signature.arg2.is_modrm() && arg2.is_index_ex()) ? 1 : 0),
                .r = (uint8_t)((signature.arg1.is_modrm() && arg1.is_base_ex())  || (signature.arg2.is_modrm() && arg2.is_base_ex())  ? 1 : 0),
                .w = (uint8_t)((signature.operand_size() == 32 ? 0 : 1))
            };
            if (rex.flags() != 0) if (!assembly.push(rex)) return __error(errors::out_of_memory);

            uint8_t code = opcode.code + (opcode.flags.has(opcode_flags_t::register_adjusted) ? (uint8_t)register_code_t(arg1.reg) : 0);
            if (!assembly.push(code)) return __error(errors::out_of_memory);

            if ((!opcode.flags.has(opcode_flags_t::register_adjusted) && signature.arg1.is_modrm()) || signature.arg2.is_modrm())
            {
                modrm_t modrm;
                sib_t   sib;
                
                bool needs_sib = 
                        apply_modrmsib(signature.arg1, arg1, modrm, sib) 
                        || apply_modrmsib(signature.arg2, arg2, modrm, sib);

                if (!assembly.push(modrm)) return __error(errors::out_of_memory);
                if (needs_sib && !assembly.push(sib)) return __error(errors::out_of_memory);
            }

            
            if (signature.arg1.is_immediate())
            { 
                if (signature.arg1 == argtype_t::imm8 && !assembly.push(*((uint8_t*)&arg1.imm))) return __error(errors::out_of_memory);
                else if (signature.arg1 == argtype_t::imm16 && !assembly.push(*((uint16_t*)&arg1.imm))) return __error(errors::out_of_memory);
                else if (signature.arg1 == argtype_t::imm32 && !assembly.push(*((uint32_t*)&arg1.imm))) return __error(errors::out_of_memory);
                else if (signature.arg1 == argtype_t::imm64 && !assembly.push(arg1.imm)) return __error(errors::out_of_memory);
            }
            else if (signature.arg2.is_immediate())
            {
                if (signature.arg2 == argtype_t::imm8 && !assembly.push(*((uint8_t*)&arg2.imm))) return __error(errors::out_of_memory);
                else if (signature.arg2 == argtype_t::imm16 && !assembly.push(*((uint16_t*)&arg2.imm))) return __error(errors::out_of_memory);
                else if (signature.arg2 == argtype_t::imm32 && !assembly.push(*((uint32_t*)&arg2.imm))) return __error(errors::out_of_memory);
                else if (signature.arg2 == argtype_t::imm64 && !assembly.push(arg2.imm)) return __error(errors::out_of_memory);
            }

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

    umap<signature_t, opcode_t, value_type_hash<signature_t>> opcode_map {
        { { "add",  argtype_t::EAX,      argtype_t::imm32    }, { 0x05, s("Add imm32 to EAX") } }, 
        { { "add",  argtype_t::RAX,      argtype_t::imm32    }, { 0x05, s("Add sign-extended imm32 to RAX") } }, 
                                                            
        { { "add",  argtype_t::regmem32, argtype_t::imm32    }, { 0x81, s("Add imm32 to reg/mem32") } },
        { { "add",  argtype_t::regmem64, argtype_t::imm32    }, { 0x81, s("Add sign-extended imm32 to reg/mem64") } },
                                                            
        { { "add",  argtype_t::regmem32, argtype_t::imm8     }, { 0x83, s("Add sign-extended imm8 to reg/mem32") } },
        { { "add",  argtype_t::regmem64, argtype_t::imm8     }, { 0x83, s("Add sign-extended imm8 to reg/mem64") } },
                                                            
        { { "add",  argtype_t::regmem32, argtype_t::reg32    }, { 0x01, s("Add reg32 to reg/mem32") } },
        { { "add",  argtype_t::regmem64, argtype_t::reg64    }, { 0x01, s("Add reg64 to reg/mem64") } },
                   
        { { "add",  argtype_t::reg32,    argtype_t::regmem32 }, { 0x03, s("Add reg/mem32 to reg32") } },
        { { "add",  argtype_t::reg64,    argtype_t::regmem64 }, { 0x03, s("Add reg/mem64 to reg64") } },
                   
                   
                   
        { { "mov",  argtype_t::regmem32, argtype_t::reg32    }, { 0x89, s("Move the contents of a 32-bit register to a 32-bit destination register or memory operand") } },
        { { "mov",  argtype_t::regmem64, argtype_t::reg64    }, { 0x89, s("Move the contents of a 64-bit register to a 64-bit destination register or memory operand") } },
                   
        { { "mov",  argtype_t::reg32,    argtype_t::regmem32 }, { 0x8B, s("Move the contents of a 32-bit register or memory to a 32-bit destination register") } },
        { { "mov",  argtype_t::reg64,    argtype_t::regmem64 }, { 0x8B, s("Move the contents of a 64-bit register or memory to a 64-bit destination register") } },
                   
        { { "mov",  argtype_t::reg32,    argtype_t::imm32    }, { 0xB8, s("Move a 32-bit immediate value into a 32-bit register"), { opcode_flags_t::register_adjusted } } },
        { { "mov",  argtype_t::reg64,    argtype_t::imm64    }, { 0xB8, s("Move a 64-bit immediate value into a 64-bit register"), { opcode_flags_t::register_adjusted } } },
                                                             
        { { "mov",  argtype_t::regmem32, argtype_t::imm32    }, { 0xC7, s("Move a 32-bit immediate value into a 32-bit register or memory operand") } },
        { { "mov",  argtype_t::regmem64, argtype_t::imm64    }, { 0xC7, s("Move a 64-bit immediate value into a 64-bit register or memory operand") } },


        { { "pop",  argtype_t::regmem64, argtype_t::unused   }, { 0xFF, s("Pop the top of the stack into a 64-bit register or memory.") } },

        //{ { "push", argtype_t::regmem32, argtype_t::unused   }, { 0xFF, s("Push the contents of a 32-bit register or memory operand onto the stack (No prefix for encoding this in 64-bit mode).") } },
        { { "push", argtype_t::regmem64, argtype_t::unused   }, { 0xFF, s("Push the contents of a 64-bit register or memory operand onto the stack.") } },

        { { "ret",  argtype_t::unused,   argtype_t::unused   }, { 0xC3, s("Near return to the calling procedure.") } },

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
                ret.reg = reg;
                ret.mode = modrm_t::mode_t::register_indirect;
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

        if (++iter != end && clear_whitespace_inline(iter, end))
        {
            __checkedinto(ret.arg1, parse_argument(&ret.signature.arg1, iter, end));
            if (iter != end && iter->delimiter == ',')
            {
                if (++iter == end || !clear_whitespace_inline(iter, end)) return __error_msg(errors::assembler::unexpected_end_of_statment, "Label "_s + to_string(iter->value) + ": Ended in a ','");
                __checkedinto(ret.arg2, parse_argument(&ret.signature.arg2, iter, end));
                ++iter;
            }
        }

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

            if (!(++test.arg2).valid())
            {
                if (!(++test.arg1).valid())
                {
                    return __error_msg(errors::assembler::instruction_overload_not_found, "Could not find overload for label "_s + to_string(iter->value));
                }
                test.arg2 = ret.signature.arg2;
            }

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


    error main() noexcept
    {
        buffervec<uint8_t> assembly;
        __checkedinto(assembly, assemble(R"(
                                    mov eax, 350
                                    mov ebx, 350
                                    add eax, ebx
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
    if (auto e = cgengine::main(); !e.success())
    {
        printf("%s\n", e.to_string().c_str());
    }
}






