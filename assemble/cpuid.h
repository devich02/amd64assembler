#pragma once

#include "structures.h"

namespace cgengine
{
    namespace assembler
    {
        _inline umap<string, cpuq_t>& cpuid_queries()
        {
            static umap<string, cpuq_t>* pqueries = statics::get<umap<string, cpuq_t>*>(_FUNC, umap<string, cpuq_t>
            {
                { "ExtFamily", { 1, cpuq_t::regpos_t::EAX, 20, 28, "Processor extended family. See above for definition of Family[7:0]. (APM3)" } },
                { "ExtModel",   { 1, cpuq_t::regpos_t::EAX, 16, 20, "Processor extended model. See above for definition of Model[7:0]. (APM3)."  } },
                { "BaseFamily", { 1, cpuq_t::regpos_t::EAX, 8, 12,  "Base processor family. See above for definition of Family[7:0]. (APM3)."  } },
                { "BaseModel",  { 1, cpuq_t::regpos_t::EAX, 4, 8,   "Base processor model. See above for definition of Model[7:0]. (APM3)."  } },
                { "Stepping",   { 1, cpuq_t::regpos_t::EAX, 0, 4,   "Processor stepping. Processor stepping (revision) for a specific model. (APM3)."  } },

                { "LocalApicId",           { 1, cpuq_t::regpos_t::EBX, 24, 32, "Initial local APIC physical ID. The 8-bit value assigned to the local APIC physical ID register at power - up.Some of the bits of LocalApicId represent the core within a processor and other bits represent the processor ID.See the APIC20 \"APIC ID\" register in the processor BKDG or PPR for details."  } },
                { "LogicalProcessorCount", { 1, cpuq_t::regpos_t::EBX, 16, 24, "Logical processor count. If CPUID Fn0000_0001_EDX[HTT] = 1 then LogicalProcessorCount is the number of logic processors per package. If CPUID Fn0000_0001_EDX[HTT] = 0 then LogicalProcessorCount is reserved."} },
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


                { "ARAT",    { 6, cpuq_t::regpos_t::EAX, 2, 3, "If set, indicates that the timebase for the local APIC timer is not affected by processor p-state." } },
                { "EffFreq", { 6, cpuq_t::regpos_t::ECX, 0, 1, "Effective frequency interface support. If set, indicates presence of MSR0000_00E7 (MPERF) and MSR0000_00E8(APERF)." } },


                { "MaxSubFn",  { 7, cpuq_t::regpos_t::EAX, 0,  32, "Returns the number of subfunctions supported" } },
                { "SHA",       { 7, cpuq_t::regpos_t::EBX, 29, 30, "SHA instruction extension" } },
                { "CLWB",      { 7, cpuq_t::regpos_t::EBX, 24, 25, "" } },
                { "CLFLUSHOPT",{ 7, cpuq_t::regpos_t::EBX, 23, 24, "" } },
                { "RDPID",     { 7, cpuq_t::regpos_t::EBX, 22, 23, "RDPID instruction and TSC_AUX MSR support." } },
                { "SMAP",      { 7, cpuq_t::regpos_t::EBX, 20, 21, "Supervisor mode access prevention" } },
                { "ADX",       { 7, cpuq_t::regpos_t::EBX, 19, 20, "ADCX, ADOX instruction support." } },
                { "RDSEED",    { 7, cpuq_t::regpos_t::EBX, 18, 19, "" } },
                { "BMI2",      { 7, cpuq_t::regpos_t::EBX, 8, 9,   "Bit manipulation group 2 support" } },
                { "SMEP",      { 7, cpuq_t::regpos_t::EBX, 7, 8,   "Supervisor mode execution prevention" } },
                { "AVX2",      { 7, cpuq_t::regpos_t::EBX, 5, 6,   "" } },
                { "BMI1",      { 7, cpuq_t::regpos_t::EBX, 3, 4,   "Bit manipulation group 1 support" } },
                { "UMIP",      { 7, cpuq_t::regpos_t::EBX, 2, 3,   "User mode instruction prevention support" } },
                { "FSGSBASE",  { 7, cpuq_t::regpos_t::EBX, 0, 1,   "FS and GS base read/write instruction support" } },

                { "VPCMULQDQ", { 7, cpuq_t::regpos_t::ECX, 10, 11, "" } },
                { "VAES",      { 7, cpuq_t::regpos_t::ECX, 9, 10, "" } },
                { "OSPKE",     { 7, cpuq_t::regpos_t::ECX, 4, 5, "OS has enabled Memory Protection Keys and use of the RDPKRU/WRPKRU instructions by setting CR4.PKE = 1. " } },
                { "PKU",       { 7, cpuq_t::regpos_t::ECX, 3, 4, "Memory protection keys supported" } },



                { "XFeatureSupportedMask_low",  { 0xD, cpuq_t::regpos_t::EAX, 0, 32, "Reports the valid bit positions for the lower 32 bits of the XFeatureEnabledMask register.If a bit is set, the corresponding feature is supported.See \"XSAVE / XRSTOR Instructions\" in APM2." } },
                { "XFeatureEnabledSizeMax",     { 0xD, cpuq_t::regpos_t::EBX, 0, 32, "Size in bytes of XSAVE/XRSTOR area for the currently enabled features in XCR0. " } },
                { "XFeatureSupportedSizeMax",   { 0xD, cpuq_t::regpos_t::ECX, 0, 32, "Size in bytes of XSAVE/XRSTOR area for all features that the logical processor supports.See XFeatureEnabledSizeMax. " } },
                { "XFeatureSupportedMask_high", { 0xD, cpuq_t::regpos_t::EDX, 0, 32, "Reports the valid bit positions for the upper 32 bits of the XFeatureEnabledMask register.If a bit is set, the corresponding feature is supported." } },


                { "XSAVEOPT",         { 0xD, cpuq_t::regpos_t::EAX, 0, 1, "" , 1} },
                { "YmmSaveStateSize",   { 0xD, cpuq_t::regpos_t::EAX, 0, 32, " YMM state save size. The state save area size in bytes for The YMM registers.", 2} },
                { "YmmSaveStateOffset", { 0xD, cpuq_t::regpos_t::EBX, 0, 32, " YMM state save offset. The offset in bytes from the base of the extended state save area of the YMM register state save area.", 2} },
                { "LwpSaveStateSize",   { 0xD, cpuq_t::regpos_t::EBX, 0, 32, " LWP state save area size. The size of the save area for LWP state in bytes. See \"Lightweight Profiling\" in APM2.", 3} },
                { "LwpSaveStateOffset", { 0xD, cpuq_t::regpos_t::EBX, 0, 32, " LWP state save byte offset. The offset in bytes from the base of the extended state save area of the state save area for LWP.See \"Lightweight Profiling\" in APM2", 3} },



                { "PkgType", { 0x80000001, cpuq_t::regpos_t::EBX, 28, 32, "Package type. If (Family[7:0] >= 10h), this field is valid. If (Family[7:0]<10h), this field is reserved. " } },
                { "BrandId", { 0x80000001, cpuq_t::regpos_t::EBX, 0,  16, "Brand ID. This field, in conjunction with CPUID Fn0000_0001_EBX[8BitBrandId], is used by system firmware to generate the processor name string.See your processor revision guide for how to program the processor name string. " } },




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

            });
            return *pqueries;
        }
    }
}