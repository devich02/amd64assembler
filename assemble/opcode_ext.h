#pragma once

#include "opcodes_core.h"

namespace cgengine
{
    namespace assembler
    {
        namespace ___internal
        {
            _inline void add_ext_ops()
            {
                vector<std::pair<signature_t, opcode_t>> ext
                {
                    // https://www.felixcloutier.com/x86/PABSB:PABSW:PABSD:PABSQ.html

                    { { "pabsb", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pabsb xmm1, xmm2/m128 | Packed Absolute Value | Compute the absolute value of bytes in <em>xmm2/m128</em> and store UNSIGNED result in <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x38,0x1C },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSSE3"] }
                          }
                       }
                    },

                    { { "pabsw", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pabsw xmm1, xmm2/m128 | Packed Absolute Value | Compute the absolute value of 16-bit integers in <em>xmm2/m128</em> and store UNSIGNED result in <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x38,0x1D },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSSE3"] }
                          }
                       }
                    },

                    { { "pabsd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pabsd xmm1, xmm2/m128 | Packed Absolute Value | Compute the absolute value of 32-bit integers in <em>xmm2/m128</em> and store UNSIGNED result in <em>xmm1.</em>",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x38,0x1E },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSSE3"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PADDB:PADDW:PADDD:PADDQ.html

                    { { "paddb", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "paddb xmm1, xmm2/m128 | Add Packed Integers | Add packed byte integers from <em>xmm2/m128</em> and <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xFC },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },

                    { { "paddw", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "paddw xmm1, xmm2/m128 | Add Packed Integers | Add packed word integers from <em>xmm2/m128</em> and <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xFD },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },

                    { { "paddd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "paddd xmm1, xmm2/m128 | Add Packed Integers | Add packed doubleword integers from <em>xmm2/m128</em> and <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xFE },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },

                    { { "paddq", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "paddq xmm1, xmm2/m128 | Add Packed Integers | Add packed quadword integers from <em>xmm2/m128</em> and <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xD4 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/ADDPD.html

                    { { "addpd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "addpd xmm1, xmm2/m128 | Add Packed Double-Precision Floating-Point Values | Add packed double-precision floating-point values from xmm2/mem to xmm1 and store result in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x58 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/ADDPS.html

                    { { "addps", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x0F,
                          "addps xmm1, xmm2/m128 | Add Packed Single-Precision Floating-Point Values | Add packed single-precision floating-point values from xmm2/m128 to xmm1 and store result in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 1,
                              ._f_opcode_extra = { 0x58 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/ADDSD.html

                    { { "addsd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF2,
                          "addsd xmm1, xmm2/m64 | Add Scalar Double-Precision Floating-Point Values | Add the low double-precision floating-point value from xmm2/mem to xmm1 and store the result in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x58 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/ADDSS.html

                    { { "addss", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF3,
                          "addss xmm1, xmm2/m32 | Add Scalar Single-Precision Floating-Point Values | Add the low single-precision floating-point value from xmm2/mem to xmm1 and store the result in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x58 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PADDSB:PADDSW.html

                    { { "paddsb", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "paddsb xmm1, xmm2/m128 | Add Packed Signed Integers with Signed Saturation | Add packed signed byte integers from <em>xmm2/m128</em> and <em>xmm1</em> saturate the results.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xEC },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },

                    { { "paddsw", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "paddsw xmm1, xmm2/m128 | Add Packed Signed Integers with Signed Saturation | Add packed signed word integers from <em>xmm2/m128</em> and <em>xmm1</em> and saturate the results.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xED },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PADDUSB:PADDUSW.html

                    { { "paddusb", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "paddusb xmm1, xmm2/m128 | Add Packed Unsigned Integers with Unsigned Saturation | Add packed unsigned byte integers from <em>xmm2/m128</em> and <em>xmm1</em> saturate the results.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xDC },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },

                    { { "dd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "dd /r, PADDUSW, xmm1, xmm2/m128 | Add Packed Unsigned Integers with Unsigned Saturation | Add packed unsigned word integers from <em>xmm2/m128</em> to <em>xmm1</em> and saturate the results.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xDD },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/ADDSUBPD.html

                    { { "addsubpd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "addsubpd xmm1, xmm2/m128 | Packed Double-FP Add/Subtract | Add/subtract double-precision floating-point values from <em>xmm2/m128</em> to <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xD0 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE3"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/ADDSUBPS.html

                    { { "addsubps", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF2,
                          "addsubps xmm1, xmm2/m128 | Packed Single-FP Add/Subtract | Add/subtract single-precision floating-point values from <em>xmm2/m128</em> to <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xD0 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE3"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/AESDEC.html

                    { { "de", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "de /r, AESDEC, xmm1, xmm2/m128 | Perform One Round of an AES Decryption Flow | Perform one round of an AES decryption flow, using the Equivalent Inverse Cipher, operating on a 128-bit data (state) from xmm1 with a 128-bit round key from xmm2/m128.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x38,0xDE },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["AES"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/AESDECLAST.html

                    { { "aesdeclast", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "aesdeclast xmm1, xmm2/m128 | Perform Last Round of an AES Decryption Flow | Perform the last round of an AES decryption flow, using the Equivalent Inverse Cipher, operating on a 128-bit data (state) from xmm1 with a 128-bit round key from xmm2/m128.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x38,0xDF },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["AES"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/AESENC.html

                    { { "aesenc", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "aesenc xmm1, xmm2/m128 | Perform One Round of an AES Encryption Flow | Perform one round of an AES encryption flow, operating on a 128-bit data (state) from xmm1 with a 128-bit round key from xmm2/m128.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x38,0xDC },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["AES"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/AESENCLAST.html

                    { { "aesenclast", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "aesenclast xmm1, xmm2/m128 | Perform Last Round of an AES Encryption Flow | Perform the last round of an AES encryption flow, operating on a 128-bit data (state) from xmm1 with a 128-bit round key from xmm2/m128.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x38,0xDD },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["AES"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/AESIMC.html

                    { { "aesimc", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "aesimc xmm1, xmm2/m128 | Perform the AES InvMixColumn Transformation | Perform the InvMixColumn transformation on a 128-bit round key from xmm2/m128 and store the result in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x38,0xDB },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["AES"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/AESKEYGENASSIST.html

                    { { "aeskeygenassist", argtype_t::reg128, argtype_t::regmem128, argtype_t::imm8 },
                       {
                          0x66,
                          "aeskeygenassist xmm1, xmm2/m128, imm8 | AES Round Key Generation Assist | Assist in AES round key generation using an 8 bits Round Constant (RCON) specified in the immediate byte, operating on 128 bits of data specified in xmm2/m128 and stores the result in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x3A,0xDF },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["AES"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PALIGNR.html

                    { { "palignr", argtype_t::reg128, argtype_t::regmem128, argtype_t::imm8 },
                       {
                          0x66,
                          "palignr xmm1, xmm2/m128, imm8 | Packed Align Right | Concatenate destination and source operands, extract byte-aligned result shifted to the right by constant value in <em>imm8</em> into <em>xmm1.</em>",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x3A,0x0F },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSSE3"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/ANDPD.html

                    { { "andpd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "andpd xmm1, xmm2/m128 | Bitwise Logical AND of Packed Double Precision Floating-Point Values | Return the bitwise logical AND of packed double-precision floating-point values in xmm1 and xmm2/mem.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x54 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/ANDPS.html

                    { { "andps", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x0F,
                          "andps xmm1, xmm2/m128 | Bitwise Logical AND of Packed Single Precision Floating-Point Values | Return the bitwise logical AND of packed single-precision floating-point values in xmm1 and xmm2/mem.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 1,
                              ._f_opcode_extra = { 0x54 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PAND.html

                    { { "pand", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pand xmm1, xmm2/m128 | Logical AND | Bitwise AND of <em>xmm2/m128</em> and <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xDB },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/ANDNPD.html

                    { { "andnpd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "andnpd xmm1, xmm2/m128 | Bitwise Logical AND NOT of Packed Double Precision Floating-Point Values | Return the bitwise logical AND NOT of packed double-precision floating-point values in xmm1 and xmm2/mem.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x55 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/ANDNPS.html

                    { { "np", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x0F,
                          "np 0F, 55, /r, ANDNPS, xmm1, xmm2/m128 | Bitwise Logical AND NOT of Packed Single Precision Floating-Point Values | Return the bitwise logical AND NOT of packed single-precision floating-point values in xmm1 and xmm2/mem.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 1,
                              ._f_opcode_extra = { 0x55 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PANDN.html

                    { { "pandn", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pandn xmm1, xmm2/m128 | Logical AND NOT | Bitwise AND NOT of <em>xmm2/m128</em> and <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xDF },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PAVGB:PAVGW.html

                    { { "pavgb", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pavgb xmm1, xmm2/m128 | Average Packed Integers | Average packed unsigned byte integers from <em>xmm2/m128</em> and <em>xmm1</em> with rounding.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 1,
                              ._f_opcode_extra = { 0x0F },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },

                    { { "pavgw", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pavgw xmm1, xmm2/m128 | Average Packed Integers | Average packed unsigned word integers from <em>xmm2/m128</em> and <em>xmm1</em> with rounding.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xE3 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/BT.html
                    // https://www.felixcloutier.com/x86/VPBLENDD.html
                    // https://www.felixcloutier.com/x86/BLENDPD.html

                    { { "blendpd", argtype_t::reg128, argtype_t::regmem128, argtype_t::imm8 },
                       {
                          0x66,
                          "blendpd xmm1, xmm2/m128, imm8 | Blend Packed Double Precision Floating-Point Values | Select packed DP-FP values from <em>xmm1</em> and <em>xmm2/m128</em> from mask specified in imm8 and store the values into <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x3A,0x0D },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.1"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/BLENDPS.html

                    { { "blendps", argtype_t::reg128, argtype_t::regmem128, argtype_t::imm8 },
                       {
                          0x66,
                          "blendps xmm1, xmm2/m128, imm8 | Blend Packed Single Precision Floating-Point Values | Select packed single precision floating-point values from <em>xmm1</em> and <em>xmm2/m128</em> from mask specified in <em>imm8</em> and store the values into <em>xmm1.</em>",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x3A,0x0C },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.1"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PBLENDVB.html

                    { { "pblendvb", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pblendvb xmm1, xmm2/m128, &lt;XMM0&gt; | Variable Blend Packed Bytes | Select byte values from <em>xmm1</em> and <em>xmm2/m128</em> from mask specified in the high bit of each byte in <em>XMM0</em> and store the values into <em>xmm1.</em>",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x38,0x10 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.1"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/BLENDVPD.html

                    { { "blendvpd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "blendvpd xmm1, xmm2/m128, &lt;XMM0&gt; | Variable Blend Packed Double Precision Floating-Point Values | Select packed DP FP values from <em>xmm1</em> and <em>xmm2</em> from mask specified in <em>XMM0</em> and store the values in <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x38,0x15 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.1"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/BLENDVPS.html

                    { { "blendvps", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "blendvps xmm1, xmm2/m128, &lt;XMM0&gt; | Variable Blend Packed Single Precision Floating-Point Values | Select packed single precision floating-point values from <em>xmm1</em> and <em>xmm2/m128</em> from mask specified in <em>XMM0</em> and store the values into <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x38,0x14 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.1"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/VPBROADCASTB:VPBROADCASTW:VPBROADCASTD:VPBROADCASTQ.html
                    // https://www.felixcloutier.com/x86/MOVDDUP.html

                    { { "movddup", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF2,
                          "movddup xmm1, xmm2/m64 | Replicate Double FP Values | Move double-precision floating-point value from xmm2/m64 and duplicate into xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x12 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE3"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PSLLDQ.html

                    { { "pslldq", argtype_t::regmem128, argtype_t::imm8 },
                       {
                          0x66,
                          "pslldq xmm1, imm8 | Shift Double Quadword Left Logical | Shift <em>xmm1</em> left by <em>imm8</em> bytes while shifting in 0s.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x73 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PSRLDQ.html

                    { { "psrldq", argtype_t::regmem128, argtype_t::imm8 },
                       {
                          0x66,
                          "psrldq xmm1, imm8 | Shift Double Quadword Right Logical | Shift <em>xmm1</em> right by <em>imm8</em> while shifting in 0s.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x73 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/ROUNDPD.html

                    { { "roundpd", argtype_t::reg128, argtype_t::regmem128, argtype_t::imm8 },
                       {
                          0x66,
                          "roundpd xmm1, xmm2/m128, imm8 | Round Packed Double Precision Floating-Point Values | Round packed double precision floating-point values in <em>xmm2/m128</em> and place the result in <em>xmm1</em>. The rounding mode is determined by <em>imm8.</em>",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x3A,0x09 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.1"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/ROUNDPS.html

                    { { "roundps", argtype_t::reg128, argtype_t::regmem128, argtype_t::imm8 },
                       {
                          0x66,
                          "roundps xmm1, xmm2/m128, imm8 | Round Packed Single Precision Floating-Point Values | Round packed single precision floating-point values in <em>xmm2/m128</em> and place the result in <em>xmm1</em>. The rounding mode is determined by <em>imm8</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x3A,0x08 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.1"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/ROUNDSD.html

                    { { "roundsd", argtype_t::reg128, argtype_t::regmem128, argtype_t::imm8 },
                       {
                          0x66,
                          "roundsd xmm1, xmm2/m64, imm8 | Round Scalar Double Precision Floating-Point Values | Round the low packed double precision floating-point value in <em>xmm2/m64</em> and place the result in <em>xmm1.</em> The rounding mode is determined by <em>imm8</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x3A,0x0B },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.1"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/ROUNDSS.html

                    { { "roundss", argtype_t::reg128, argtype_t::regmem128, argtype_t::imm8 },
                       {
                          0x66,
                          "roundss xmm1, xmm2/m32, imm8 | Round Scalar Single Precision Floating-Point Values | Round the low packed single precision floating-point value in <em>xmm2/m32</em> and place the result in <em>xmm1</em>. The rounding mode is determined by <em>imm8</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x3A,0x0A },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.1"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/CLFLUSH.html
                    // https://www.felixcloutier.com/x86/PCMPEQB:PCMPEQW:PCMPEQD.html

                    { { "pcmpeqb", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pcmpeqb xmm1, xmm2/m128 | Compare Packed Data for Equal | Compare packed bytes in <em>xmm2/m128</em> and <em>xmm1</em> for equality.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x74 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },

                    { { "pcmpeqw", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pcmpeqw xmm1, xmm2/m128 | Compare Packed Data for Equal | Compare packed words in <em>xmm2/m128</em> and <em>xmm1</em> for equality.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x75 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },

                    { { "pcmpeqd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pcmpeqd xmm1, xmm2/m128 | Compare Packed Data for Equal | Compare packed doublewords in <em>xmm2/m128</em> and <em>xmm1</em> for equality.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x76 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PCMPEQQ.html

                    { { "pcmpeqq", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pcmpeqq xmm1, xmm2/m128 | Compare Packed Qword Data for Equal | Compare packed qwords in <em>xmm2/m128</em> and <em>xmm1</em> for equality.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x38,0x29 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.1"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/CMPPD.html

                    { { "cmppd", argtype_t::reg128, argtype_t::regmem128, argtype_t::imm8 },
                       {
                          0x66,
                          "cmppd xmm1, xmm2/m128, imm8 | Compare Packed Double-Precision Floating-Point Values | Compare packed double-precision floating-point values in xmm2/m128 and xmm1 using bits 2:0 of imm8 as a comparison predicate.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xC2 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/CMPPS.html

                    { { "cmpps", argtype_t::reg128, argtype_t::regmem128, argtype_t::imm8 },
                       {
                          0x0F,
                          "cmpps xmm1, xmm2/m128, imm8 | Compare Packed Single-Precision Floating-Point Values | Compare packed single-precision floating-point values in xmm2/m128 and xmm1 using bits 2:0 of imm8 as a comparison predicate.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 1,
                              ._f_opcode_extra = { 0xC2 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/CMPSD.html

                    { { "cmpsd", argtype_t::reg128, argtype_t::regmem128, argtype_t::imm8 },
                       {
                          0xF2,
                          "cmpsd xmm1, xmm2/m64, imm8 | Compare Scalar Double-Precision Floating-Point Value | Compare low double-precision floating-point value in xmm2/m64 and xmm1 using bits 2:0 of imm8 as comparison predicate.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xC2 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/CMPSS.html

                    { { "cmpss", argtype_t::reg128, argtype_t::regmem128, argtype_t::imm8 },
                       {
                          0xF3,
                          "cmpss xmm1, xmm2/m32, imm8 | Compare Scalar Single-Precision Floating-Point Value | Compare low single-precision floating-point value in xmm2/m32 and xmm1 using bits 2:0 of imm8 as comparison predicate.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xC2 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PCMPESTRI.html

                    { { "pcmpestri", argtype_t::reg128, argtype_t::regmem128, argtype_t::imm8 },
                       {
                          0x66,
                          "pcmpestri xmm1, xmm2/m128, imm8 | Packed Compare Explicit Length Strings, Return Index | Perform a packed comparison of string data with explicit lengths, generating an index, and storing the result in ECX.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x3A,0x61 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PCMPESTRM.html

                    { { "pcmpestrm", argtype_t::reg128, argtype_t::regmem128, argtype_t::imm8 },
                       {
                          0x66,
                          "pcmpestrm xmm1, xmm2/m128, imm8 | Packed Compare Explicit Length Strings, Return Mask | Perform a packed comparison of string data with explicit lengths, generating a mask, and storing the result in <em>XMM0.</em>",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x3A,0x60 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PCMPGTB:PCMPGTW:PCMPGTD.html

                    { { "pcmpgtb", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pcmpgtb xmm1, xmm2/m128 | Compare Packed Signed Integers for Greater Than | Compare packed signed byte integers in <em>xmm1</em> and <em>xmm2/m128</em> for greater than.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x64 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },

                    { { "pcmpgtw", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pcmpgtw xmm1, xmm2/m128 | Compare Packed Signed Integers for Greater Than | Compare packed signed word integers in <em>xmm1</em> and <em>xmm2/m128</em> for greater than.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x65 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },

                    { { "pcmpgtd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pcmpgtd xmm1, xmm2/m128 | Compare Packed Signed Integers for Greater Than | Compare packed signed doubleword integers in <em>xmm1</em> and <em>xmm2/m128</em> for greater than.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x66 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PCMPGTQ.html

                    { { "pcmpgtq", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pcmpgtq xmm1,xmm2/m128 | Compare Packed Data for Greater Than | Compare packed signed qwords in <em>xmm2/m128</em> and <em>xmm1</em> for greater than.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x38,0x37 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PCMPISTRI.html

                    { { "pcmpistri", argtype_t::reg128, argtype_t::regmem128, argtype_t::imm8 },
                       {
                          0x66,
                          "pcmpistri xmm1, xmm2/m128, imm8 | Packed Compare Implicit Length Strings, Return Index | Perform a packed comparison of string data with implicit lengths, generating an index, and storing the result in ECX.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x3A,0x63 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PCMPISTRM.html

                    { { "pcmpistrm", argtype_t::reg128, argtype_t::regmem128, argtype_t::imm8 },
                       {
                          0x66,
                          "pcmpistrm xmm1, xmm2/m128, imm8 | Packed Compare Implicit Length Strings, Return Mask | Perform a packed comparison of string data with implicit lengths, generating a mask, and storing the result in <em>XMM0.</em>",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x3A,0x62 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/COMISD.html

                    { { "comisd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "comisd xmm1, xmm2/m64 | Compare Scalar Ordered Double-Precision Floating-Point Values and Set EFLAGS | Compare low double-precision floating-point values in xmm1 and xmm2/mem64 and set the EFLAGS flags accordingly.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x2F },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/COMISS.html

                    { { "comiss", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x0F,
                          "comiss xmm1, xmm2/m32 | Compare Scalar Ordered Single-Precision Floating-Point Values and Set EFLAGS | Compare low single-precision floating-point values in xmm1 and xmm2/mem32 and set the EFLAGS flags accordingly.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 1,
                              ._f_opcode_extra = { 0x2F },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/CRC32.html
                    // https://www.felixcloutier.com/x86/CVTPI2PS.html
                    // https://www.felixcloutier.com/x86/CVTPS2PI.html
                    // https://www.felixcloutier.com/x86/CVTSI2SS.html

                    { { "cvtsi2ss", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF3,
                          "cvtsi2ss xmm1, r/m32 | Convert Doubleword Integer to Scalar Single-Precision Floating-Point Value | Convert one signed doubleword integer from r/m32 to one single-precision floating-point value in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x2A },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE"] }
                          }
                       }
                    },

                    { { "cvtsi2ss", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF3,
                          "cvtsi2ss xmm1, r/m64 | Convert Doubleword Integer to Scalar Single-Precision Floating-Point Value | Convert one signed quadword integer from r/m64 to one single-precision floating-point value in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x2A },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/CVTSS2SI.html

                    { { "cvtss2si", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF3,
                          "cvtss2si r32, xmm1/m32 | Convert Scalar Single-Precision Floating-Point Value to Doubleword Integer | Convert one single-precision floating-point value from xmm1/m32 to one signed doubleword integer in r32.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x2D },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE"] }
                          }
                       }
                    },

                    { { "cvtss2si", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF3,
                          "cvtss2si r64, xmm1/m32 | Convert Scalar Single-Precision Floating-Point Value to Doubleword Integer | Convert one single-precision floating-point value from xmm1/m32 to one signed quadword integer in r64.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x2D },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/CVTDQ2PD.html

                    { { "cvtdq2pd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF3,
                          "cvtdq2pd xmm1, xmm2/m64 | Convert Packed Doubleword Integers to Packed Double-Precision Floating-Point Values | Convert two packed signed doubleword integers from xmm2/mem to two packed double-precision floating-point values in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xE6 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/CVTDQ2PS.html

                    { { "cvtdq2ps", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x0F,
                          "cvtdq2ps xmm1, xmm2/m128 | Convert Packed Doubleword Integers to Packed Single-Precision Floating-Point Values | Convert four packed signed doubleword integers from xmm2/mem to four packed single-precision floating-point values in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 1,
                              ._f_opcode_extra = { 0x5B },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/CVTPD2DQ.html

                    { { "cvtpd2dq", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF2,
                          "cvtpd2dq xmm1, xmm2/m128 | Convert Packed Double-Precision Floating-Point Values to Packed Doubleword Integers | Convert two packed double-precision floating-point values in xmm2/mem to two signed doubleword integers in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xE6 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/CVTPD2PI.html
                    // https://www.felixcloutier.com/x86/CVTPD2PS.html

                    { { "cvtpd2ps", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "cvtpd2ps xmm1, xmm2/m128 | Convert Packed Double-Precision Floating-Point Values to Packed Single-Precision Floating-Point Values | Convert two packed double-precision floating-point values in xmm2/mem to two single-precision floating-point values in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x5A },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/CVTPI2PD.html
                    // https://www.felixcloutier.com/x86/CVTPS2DQ.html

                    { { "cvtps2dq", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "cvtps2dq xmm1, xmm2/m128 | Convert Packed Single-Precision Floating-Point Values to Packed Signed Doubleword Integer Values | Convert four packed single-precision floating-point values from xmm2/mem to four packed signed doubleword values in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x5B },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/CVTPS2PD.html

                    { { "cvtps2pd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x0F,
                          "cvtps2pd xmm1, xmm2/m64 | Convert Packed Single-Precision Floating-Point Values to Packed Double-Precision Floating-Point Values | Convert two packed single-precision floating-point values in xmm2/m64 to two packed double-precision floating-point values in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 1,
                              ._f_opcode_extra = { 0x5A },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/MOVSD.html

                    { { "movsd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF2,
                          "movsd xmm1, xmm2 | Move or Merge Scalar Double-Precision Floating-Point Value | Move scalar double-precision floating-point value from xmm2 to xmm1 register.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x10 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },

                    { { "movsd", argtype_t::regmem128, argtype_t::reg128 },
                       {
                          0xF2,
                          "movsd xmm1/m64, xmm2 | Move or Merge Scalar Double-Precision Floating-Point Value | Move scalar double-precision floating-point value from xmm2 register to xmm1/m64.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x11 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/CVTSD2SI.html

                    { { "cvtsd2si", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF2,
                          "cvtsd2si r32, xmm1/m64 | Convert Scalar Double-Precision Floating-Point Value to Doubleword Integer | Convert one double-precision floating-point value from xmm1/m64 to one signed doubleword integer r32.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x2D },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },

                    { { "cvtsd2si", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF2,
                          "cvtsd2si r64, xmm1/m64 | Convert Scalar Double-Precision Floating-Point Value to Doubleword Integer | Convert one double-precision floating-point value from xmm1/m64 to one signed quadword integer sign-extended into r64.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x2D },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/CVTSD2SS.html

                    { { "cvtsd2ss", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF2,
                          "cvtsd2ss xmm1, xmm2/m64 | Convert Scalar Double-Precision Floating-Point Value to Scalar Single-Precision Floating-Point Value | Convert one double-precision floating-point value in xmm2/m64 to one single-precision floating-point value in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x5A },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/MOVQ.html

                    { { "movq", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF3,
                          "movq xmm1, xmm2/m64 | Move Quadword | Move quadword from <em>xmm2/mem64</em> to <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x7E },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },

                    { { "movq", argtype_t::regmem128, argtype_t::reg128 },
                       {
                          0x66,
                          "movq xmm2/m64, xmm1 | Move Quadword | Move quadword from <em>xmm1</em> to <em>xmm2/mem64</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xD6 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/CVTSI2SD.html

                    { { "cvtsi2sd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF2,
                          "cvtsi2sd xmm1, r32/m32 | Convert Doubleword Integer to Scalar Double-Precision Floating-Point Value | Convert one signed doubleword integer from r32/m32 to one double-precision floating-point value in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x2A },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },

                    { { "cvtsi2sd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF2,
                          "cvtsi2sd xmm1, r/m64 | Convert Doubleword Integer to Scalar Double-Precision Floating-Point Value | Convert one signed quadword integer from r/m64 to one double-precision floating-point value in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x2A },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/MOVD:MOVQ.html

                    { { "movd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "movd xmm, r/m32 | Move Doubleword/Move Quadword | Move doubleword from <em>r/m32</em> to <em>xmm</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x6E },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },

                    { { "movq", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "movq xmm, r/m64 | Move Doubleword/Move Quadword | Move quadword from <em>r/m64</em> to <em>xmm</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x6E },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },

                    { { "movd", argtype_t::regmem128, argtype_t::reg128 },
                       {
                          0x66,
                          "movd r/m32, xmm | Move Doubleword/Move Quadword | Move doubleword from <em>xmm</em> register to <em>r/m32</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x7E },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },

                    { { "movq", argtype_t::regmem128, argtype_t::reg128 },
                       {
                          0x66,
                          "movq r/m64, xmm | Move Doubleword/Move Quadword | Move quadword from <em>xmm</em> register to <em>r/m64</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x7E },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/MOVSS.html

                    { { "movss", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF3,
                          "movss xmm1, xmm2 | Move or Merge Scalar Single-Precision Floating-Point Value | Merge scalar single-precision floating-point value from xmm2 to xmm1 register.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x10 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE"] }
                          }
                       }
                    },

                    { { "movss", argtype_t::regmem128, argtype_t::reg128 },
                       {
                          0xF3,
                          "movss xmm2/m32, xmm1 | Move or Merge Scalar Single-Precision Floating-Point Value | Move scalar single-precision floating-point value from xmm1 register to xmm2/m32.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x11 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/CVTSS2SD.html

                    { { "cvtss2sd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF3,
                          "cvtss2sd xmm1, xmm2/m32 | Convert Scalar Single-Precision Floating-Point Value to Scalar Double-Precision Floating-Point Value | Convert one single-precision floating-point value in xmm2/m32 to one double-precision floating-point value in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x5A },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/CVTTPS2PI.html
                    // https://www.felixcloutier.com/x86/CVTTSS2SI.html

                    { { "cvttss2si", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF3,
                          "cvttss2si r32, xmm1/m32 | Convert with Truncation Scalar Single-Precision Floating-Point Value to Integer | Convert one single-precision floating-point value from xmm1/m32 to one signed doubleword integer in r32 using truncation.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x2C },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE"] }
                          }
                       }
                    },

                    { { "cvttss2si", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF3,
                          "cvttss2si r64, xmm1/m32 | Convert with Truncation Scalar Single-Precision Floating-Point Value to Integer | Convert one single-precision floating-point value from xmm1/m32 to one signed quadword integer in r64 using truncation.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x2C },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/CVTTPD2DQ.html

                    { { "cvttpd2dq", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "cvttpd2dq xmm1, xmm2/m128 | Convert with Truncation Packed Double-Precision Floating-Point Values to Packed Doubleword Integers | Convert two packed double-precision floating-point values in xmm2/mem to two signed doubleword integers in xmm1 using truncation.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xE6 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/CVTTPD2PI.html
                    // https://www.felixcloutier.com/x86/CVTTPS2DQ.html

                    { { "cvttps2dq", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF3,
                          "cvttps2dq xmm1, xmm2/m128 | Convert with Truncation Packed Single-Precision Floating-Point Values to Packed Signed Doubleword Integer Values | Convert four packed single-precision floating-point values from xmm2/mem to four packed signed doubleword values in xmm1 using truncation.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x5B },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/CVTTSD2SI.html

                    { { "cvttsd2si", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF2,
                          "cvttsd2si r32, xmm1/m64 | Convert with Truncation Scalar Double-Precision Floating-Point Value to Signed Integer | Convert one double-precision floating-point value from xmm1/m64 to one signed doubleword integer in r32 using truncation.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x2C },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },

                    { { "cvttsd2si", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF2,
                          "cvttsd2si r64, xmm1/m64 | Convert with Truncation Scalar Double-Precision Floating-Point Value to Signed Integer | Convert one double-precision floating-point value from xmm1/m64 to one signed quadword integer in r64 using truncation.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x2C },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/DIVPD.html

                    { { "divpd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "divpd xmm1, xmm2/m128 | Divide Packed Double-Precision Floating-Point Values | Divide packed double-precision floating-point values in xmm1 by packed double-precision floating-point values in xmm2/mem.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x5E },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/DIVPS.html

                    { { "divps", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x0F,
                          "divps xmm1, xmm2/m128 | Divide Packed Single-Precision Floating-Point Values | Divide packed single-precision floating-point values in xmm1 by packed single-precision floating-point values in xmm2/mem.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 1,
                              ._f_opcode_extra = { 0x5E },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/DIVSD.html

                    { { "divsd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF2,
                          "divsd xmm1, xmm2/m64 | Divide Scalar Double-Precision Floating-Point Value | Divide low double-precision floating-point value in xmm1 by low double-precision floating-point value in xmm2/m64.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x5E },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/DIVSS.html

                    { { "divss", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF3,
                          "divss xmm1, xmm2/m32 | Divide Scalar Single-Precision Floating-Point Values | Divide low single-precision floating-point value in xmm1 by low single-precision floating-point value in xmm2/m32.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x5E },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/DPPD.html

                    { { "dppd", argtype_t::reg128, argtype_t::regmem128, argtype_t::imm8 },
                       {
                          0x66,
                          "dppd xmm1, xmm2/m128, imm8 | Dot Product of Packed Double Precision Floating-Point Values | Selectively multiply packed DP floating-point values from <em>xmm1</em> with packed DP floating-point values from <em>xmm2</em>, add and selectively store the packed DP floating-point values to <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x3A,0x41 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.1"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/DPPS.html

                    { { "dpps", argtype_t::reg128, argtype_t::regmem128, argtype_t::imm8 },
                       {
                          0x66,
                          "dpps xmm1, xmm2/m128, imm8 | Dot Product of Packed Single Precision Floating-Point Values | Selectively multiply packed SP floating-point values from <em>xmm1</em> with packed SP floating-point values from <em>xmm2</em>, add and selectively store the packed SP floating-point values or zero values to <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x3A,0x40 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.1"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/ENCLS.html

                    { { "encls" },
                       {
                          0x0F,
                          "encls  | Execute an Enclave System Function of Specified Leaf Number | This instruction is used to execute privileged Intel SGX leaf functions that are used for managing and debugging the enclaves.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x01,0xCF },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["NA"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PEXTRW.html

                    { { "pextrw", argtype_t::reg128, argtype_t::regmem128, argtype_t::imm8 },
                       {
                          0x66,
                          "pextrw reg, xmm, imm8 | Extract Word | Extract the word specified by <em>imm8</em> from <em>xmm</em> and move it to <em>reg</em>, bits 15-0. The upper bits of r32 or r64 is zeroed.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xC5 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },

                    { { "pextrw", argtype_t::regmem128, argtype_t::reg128, argtype_t::imm8 },
                       {
                          0x66,
                          "pextrw reg/m16, xmm, imm8 | Extract Word | Extract the word specified by <em>imm8</em> from <em>xmm</em> and copy it to lowest 16 bits of <em>reg or m16</em>. Zero-extend the result in the destination, r32 or r64.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x3A,0x15 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.1"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PEXTRB:PEXTRD:PEXTRQ.html

                    { { "pextrb", argtype_t::regmem128, argtype_t::reg128, argtype_t::imm8 },
                       {
                          0x66,
                          "pextrb reg/m8, xmm2, imm8 | Extract Byte/Dword/Qword | Extract a byte integer value from <em>xmm2</em> at the source byte offset specified by <em>imm8</em> into <em>reg or m8.</em> The upper bits of r32 or r64 are zeroed.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x3A,0x14 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.1"] }
                          }
                       }
                    },

                    { { "pextrd", argtype_t::regmem128, argtype_t::reg128, argtype_t::imm8 },
                       {
                          0x66,
                          "pextrd r/m32, xmm2, imm8 | Extract Byte/Dword/Qword | Extract a dword integer value from <em>xmm2</em> at the source dword offset specified by <em>imm8</em> into <em>r/m32</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x3A,0x16 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.1"] }
                          }
                       }
                    },

                    { { "pextrq", argtype_t::regmem128, argtype_t::reg128, argtype_t::imm8 },
                       {
                          0x66,
                          "pextrq r/m64, xmm2, imm8 | Extract Byte/Dword/Qword | Extract a qword integer value from <em>xmm2</em> at the source qword offset specified by <em>imm8</em> into <em>r/m64</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x3A,0x16 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.1"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/EXTRACTPS.html

                    { { "extractps", argtype_t::regmem128, argtype_t::reg128, argtype_t::imm8 },
                       {
                          0x66,
                          "extractps reg/m32, xmm1, imm8 | Extract Packed Floating-Point Values | Extract one single-precision floating-point value from xmm1 at the offset specified by imm8 and store the result in reg or m32. Zero extend the results in 64-bit register if applicable.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x3A,0x17 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.1"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/VEXTRACTF128:VEXTRACTF32x4:VEXTRACTF64x2:VEXTRACTF32x8:VEXTRACTF64x4.html
                    // https://www.felixcloutier.com/x86/VEXTRACTI128:VEXTRACTI32x4:VEXTRACTI64x2:VEXTRACTI32x8:VEXTRACTI64x4.html
                    // https://www.felixcloutier.com/x86/VFMADD132PD:VFMADD213PD:VFMADD231PD.html
                    // https://www.felixcloutier.com/x86/VFMADD132PS:VFMADD213PS:VFMADD231PS.html
                    // https://www.felixcloutier.com/x86/VFMADD132SD:VFMADD213SD:VFMADD231SD.html
                    // https://www.felixcloutier.com/x86/VFMADD132SS:VFMADD213SS:VFMADD231SS.html
                    // https://www.felixcloutier.com/x86/VFMADDSUB132PD:VFMADDSUB213PD:VFMADDSUB231PD.html
                    // https://www.felixcloutier.com/x86/VFMADDSUB132PS:VFMADDSUB213PS:VFMADDSUB231PS.html
                    // https://www.felixcloutier.com/x86/VFMSUB132PD:VFMSUB213PD:VFMSUB231PD.html
                    // https://www.felixcloutier.com/x86/VFMSUB132PS:VFMSUB213PS:VFMSUB231PS.html
                    // https://www.felixcloutier.com/x86/VFMSUB132SD:VFMSUB213SD:VFMSUB231SD.html
                    // https://www.felixcloutier.com/x86/VFMSUB132SS:VFMSUB213SS:VFMSUB231SS.html
                    // https://www.felixcloutier.com/x86/VFMSUBADD132PD:VFMSUBADD213PD:VFMSUBADD231PD.html
                    // https://www.felixcloutier.com/x86/VFMSUBADD132PS:VFMSUBADD213PS:VFMSUBADD231PS.html
                    // https://www.felixcloutier.com/x86/VFNMADD132PD:VFNMADD213PD:VFNMADD231PD.html
                    // https://www.felixcloutier.com/x86/VFNMADD132PS:VFNMADD213PS:VFNMADD231PS.html
                    // https://www.felixcloutier.com/x86/VFNMADD132SD:VFNMADD213SD:VFNMADD231SD.html
                    // https://www.felixcloutier.com/x86/VFNMADD132SS:VFNMADD213SS:VFNMADD231SS.html
                    // https://www.felixcloutier.com/x86/VFNMSUB132PD:VFNMSUB213PD:VFNMSUB231PD.html
                    // https://www.felixcloutier.com/x86/VFNMSUB132PS:VFNMSUB213PS:VFNMSUB231PS.html
                    // https://www.felixcloutier.com/x86/VFNMSUB132SD:VFNMSUB213SD:VFNMSUB231SD.html
                    // https://www.felixcloutier.com/x86/VFNMSUB132SS:VFNMSUB213SS:VFNMSUB231SS.html
                    // https://www.felixcloutier.com/x86/STMXCSR.html
                    // https://www.felixcloutier.com/x86/PHADDW:PHADDD.html

                    { { "phaddw", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "phaddw xmm1, xmm2/m128 | Packed Horizontal Add | Add 16-bit integers horizontally, pack to <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x38,0x01 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSSE3"] }
                          }
                       }
                    },

                    { { "phaddd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "phaddd xmm1, xmm2/m128 | Packed Horizontal Add | Add 32-bit integers horizontally, pack to <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x38,0x02 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSSE3"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/HADDPD.html

                    { { "haddpd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "haddpd xmm1, xmm2/m128 | Packed Double-FP Horizontal Add | Horizontal add packed double-precision floating-point values from <em>xmm2/m128</em> to <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x7C },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE3"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/HADDPS.html

                    { { "haddps", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF2,
                          "haddps xmm1, xmm2/m128 | Packed Single-FP Horizontal Add | Horizontal add packed single-precision floating-point values from <em>xmm2/m128</em> to <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x7C },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE3"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PHADDSW.html

                    { { "phaddsw", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "phaddsw xmm1, xmm2/m128 | Packed Horizontal Add and Saturate | Add 16-bit signed integers horizontally, pack saturated integers to <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x38,0x03 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSSE3"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PHSUBW:PHSUBD.html

                    { { "phsubw", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "phsubw xmm1, xmm2/m128 | Packed Horizontal Subtract | Subtract 16-bit signed integers horizontally, pack to <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x38,0x05 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSSE3"] }
                          }
                       }
                    },

                    { { "phsubd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "phsubd xmm1, xmm2/m128 | Packed Horizontal Subtract | Subtract 32-bit signed integers horizontally, pack to <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x38,0x06 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSSE3"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/HSUBPD.html

                    { { "hsubpd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "hsubpd xmm1, xmm2/m128 | Packed Double-FP Horizontal Subtract | Horizontal subtract packed double-precision floating-point values from <em>xmm2/m128</em> to <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x7D },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE3"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/HSUBPS.html

                    { { "hsubps", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF2,
                          "hsubps xmm1, xmm2/m128 | Packed Single-FP Horizontal Subtract | Horizontal subtract packed single-precision floating-point values from <em>xmm2/m128</em> to <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x7D },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE3"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PHSUBSW.html

                    { { "phsubsw", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "phsubsw xmm1, xmm2/m128 | Packed Horizontal Subtract and Saturate | Subtract 16-bit signed integer horizontally, pack saturated integers to <em>xmm1.</em>",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x38,0x07 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSSE3"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/VPGATHERDD:VPGATHERDQ.html
                    // https://www.felixcloutier.com/x86/VPGATHERDQ:VPGATHERQQ.html
                    // https://www.felixcloutier.com/x86/VGATHERDPS:VGATHERDPD.html
                    // https://www.felixcloutier.com/x86/VPGATHERQD:VPGATHERQQ.html
                    // https://www.felixcloutier.com/x86/VGATHERQPS:VGATHERQPD.html
                    // https://www.felixcloutier.com/x86/PINSRW.html

                    { { "pinsrw", argtype_t::reg128, argtype_t::regmem128, argtype_t::imm8 },
                       {
                          0x66,
                          "pinsrw xmm, r32/m16, imm8 | Insert Word | Move the low word of <em>r32</em> or from <em>m16</em> into <em>xmm</em> at the word position specified by <em>imm8</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xC4 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PINSRB:PINSRD:PINSRQ.html

                    { { "pinsrb", argtype_t::reg128, argtype_t::regmem128, argtype_t::imm8 },
                       {
                          0x66,
                          "pinsrb xmm1, r32/m8, imm8 | Insert Byte/Dword/Qword | Insert a byte integer value from <em>r32/m8</em> into <em>xmm1</em> at the destination element in <em>xmm1</em> specified by <em>imm8.</em>",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x3A,0x20 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.1"] }
                          }
                       }
                    },

                    { { "pinsrd", argtype_t::reg128, argtype_t::regmem128, argtype_t::imm8 },
                       {
                          0x66,
                          "pinsrd xmm1, r/m32, imm8 | Insert Byte/Dword/Qword | Insert a dword integer value from <em>r/m32</em> into the <em>xmm1</em> at the destination element specified by <em>imm8.</em>",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x3A,0x22 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.1"] }
                          }
                       }
                    },

                    { { "pinsrq", argtype_t::reg128, argtype_t::regmem128, argtype_t::imm8 },
                       {
                          0x66,
                          "pinsrq xmm1, r/m64, imm8 | Insert Byte/Dword/Qword | Insert a qword integer value from <em>r/m64 i</em>nto the <em>xmm1</em> at the destination element specified by <em>imm8.</em>",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x3A,0x22 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.1"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/INSERTPS.html

                    { { "insertps", argtype_t::reg128, argtype_t::regmem128, argtype_t::imm8 },
                       {
                          0x66,
                          "insertps xmm1, xmm2/m32, imm8 | Insert Scalar Single-Precision Floating-Point Value | Insert a single-precision floating-point value selected by imm8 from xmm2/m32 into xmm1 at the specified destination element specified by imm8 and zero out destination elements in xmm1 as indicated in imm8.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x3A,0x21 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.1"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/VINSERTF128:VINSERTF32x4:VINSERTF64x2:VINSERTF32x8:VINSERTF64x4.html
                    // https://www.felixcloutier.com/x86/VINSERTI128:VINSERTI32x4:VINSERTI64x2:VINSERTI32x8:VINSERTI64x4.html
                    // https://www.felixcloutier.com/x86/LDDQU.html
                    // https://www.felixcloutier.com/x86/LFENCE.html
                    // https://www.felixcloutier.com/x86/MOVAPD.html

                    { { "movapd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "movapd xmm1, xmm2/m128 | Move Aligned Packed Double-Precision Floating-Point Values | Move aligned packed double-precision floating-point values from xmm2/mem to xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x28 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },

                    { { "movapd", argtype_t::regmem128, argtype_t::reg128 },
                       {
                          0x66,
                          "movapd xmm2/m128, xmm1 | Move Aligned Packed Double-Precision Floating-Point Values | Move aligned packed double-precision floating-point values from xmm1 to xmm2/mem.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x29 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/MOVAPS.html

                    { { "movaps", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x0F,
                          "movaps xmm1, xmm2/m128 | Move Aligned Packed Single-Precision Floating-Point Values | Move aligned packed single-precision floating-point values from xmm2/mem to xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 1,
                              ._f_opcode_extra = { 0x28 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE"] }
                          }
                       }
                    },

                    { { "movaps", argtype_t::regmem128, argtype_t::reg128 },
                       {
                          0x0F,
                          "movaps xmm2/m128, xmm1 | Move Aligned Packed Single-Precision Floating-Point Values | Move aligned packed single-precision floating-point values from xmm1 to xmm2/mem.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 1,
                              ._f_opcode_extra = { 0x29 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/MOVDQA:VMOVDQA32:VMOVDQA64.html

                    { { "movdqa", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "movdqa xmm1, xmm2/m128 | Move Aligned Packed Integer Values | Move aligned packed integer values from xmm2/mem to xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x6F },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },

                    { { "movdqa", argtype_t::regmem128, argtype_t::reg128 },
                       {
                          0x66,
                          "movdqa xmm2/m128, xmm1 | Move Aligned Packed Integer Values | Move aligned packed integer values from xmm1 to xmm2/mem.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x7F },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/MOVHPD.html
                    // https://www.felixcloutier.com/x86/MOVHPS.html
                    // https://www.felixcloutier.com/x86/MOVLPD.html
                    // https://www.felixcloutier.com/x86/MOVLPS.html
                    // https://www.felixcloutier.com/x86/MOVUPD.html

                    { { "movupd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "movupd xmm1, xmm2/m128 | Move Unaligned Packed Double-Precision Floating-Point Values | Move unaligned packed double-precision floating-point from xmm2/mem to xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x10 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },

                    { { "movupd", argtype_t::regmem128, argtype_t::reg128 },
                       {
                          0x66,
                          "movupd xmm2/m128, xmm1 | Move Unaligned Packed Double-Precision Floating-Point Values | Move unaligned packed double-precision floating-point from xmm1 to xmm2/mem.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x11 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/MOVUPS.html

                    { { "movups", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x0F,
                          "movups xmm1, xmm2/m128 | Move Unaligned Packed Single-Precision Floating-Point Values | Move unaligned packed single-precision floating-point from xmm2/mem to xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 1,
                              ._f_opcode_extra = { 0x10 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE"] }
                          }
                       }
                    },

                    { { "movups", argtype_t::regmem128, argtype_t::reg128 },
                       {
                          0x0F,
                          "movups xmm2/m128, xmm1 | Move Unaligned Packed Single-Precision Floating-Point Values | Move unaligned packed single-precision floating-point from xmm1 to xmm2/mem.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 1,
                              ._f_opcode_extra = { 0x11 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/MOVDQU:VMOVDQU8:VMOVDQU16:VMOVDQU32:VMOVDQU64.html

                    { { "movdqu", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF3,
                          "movdqu xmm1, xmm2/m128 | Move Unaligned Packed Integer Values | Move unaligned packed integer values from xmm2/m128 to xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x6F },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },

                    { { "movdqu", argtype_t::regmem128, argtype_t::reg128 },
                       {
                          0xF3,
                          "movdqu xmm2/m128, xmm1 | Move Unaligned Packed Integer Values | Move unaligned packed integer values from xmm1 to xmm2/m128.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x7F },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PMADDWD.html

                    { { "pmaddwd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pmaddwd xmm1, xmm2/m128 | Multiply and Add Packed Integers | Multiply the packed word integers in <em>xmm1</em> by the packed word integers in <em>xmm2/m128</em>, add adjacent doubleword results, and store in <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xF5 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PMADDUBSW.html

                    { { "pmaddubsw", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pmaddubsw xmm1, xmm2/m128 | Multiply and Add Packed Signed and Unsigned Bytes | Multiply signed and unsigned bytes, add horizontal pair of signed words, pack saturated signed-words to <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x38,0x04 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSSE3"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/MASKMOVQ.html
                    // https://www.felixcloutier.com/x86/MASKMOVDQU.html

                    { { "maskmovdqu", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "maskmovdqu xmm1, xmm2 | Store Selected Bytes of Double Quadword | Selectively write bytes from <em>xmm1</em> to memory location using the byte mask in <em>xmm2</em>. The default memory location is specified by DS:DI/EDI/RDI.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xF7 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PMAXSB:PMAXSW:PMAXSD:PMAXSQ.html

                    { { "pmaxsb", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pmaxsb xmm1, xmm2/m128 | Maximum of Packed Signed Integers | Compare packed signed byte integers in xmm1 and xmm2/m128 and store packed maximum values in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x38,0x3C },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.1"] }
                          }
                       }
                    },

                    { { "pmaxsw", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pmaxsw xmm1, xmm2/m128 | Maximum of Packed Signed Integers | Compare packed signed word integers in xmm2/m128 and xmm1 and stores maximum packed values in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xEE },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },

                    { { "pmaxsd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pmaxsd xmm1, xmm2/m128 | Maximum of Packed Signed Integers | Compare packed signed dword integers in xmm1 and xmm2/m128 and store packed maximum values in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x38,0x3D },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.1"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PMAXUB:PMAXUW.html

                    { { "pmaxub", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pmaxub xmm1, xmm2/m128 | Maximum of Packed Unsigned Integers | Compare packed unsigned byte integers in xmm1 and xmm2/m128 and store packed maximum values in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xDE },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },

                    { { "pmaxuw", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pmaxuw xmm1, xmm2/m128 | Maximum of Packed Unsigned Integers | Compare packed unsigned word integers in xmm2/m128 and xmm1 and stores maximum packed values in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x38 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.1"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PMAXUD:PMAXUQ.html

                    { { "pmaxud", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pmaxud xmm1, xmm2/m128 | Maximum of Packed Unsigned Integers | Compare packed unsigned dword integers in xmm1 and xmm2/m128 and store packed maximum values in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x38,0x3F },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.1"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/MAXPD.html

                    { { "maxpd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "maxpd xmm1, xmm2/m128 | Maximum of Packed Double-Precision Floating-Point Values | Return the maximum double-precision floating-point values between xmm1 and xmm2/m128.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x5F },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/MAXPS.html

                    { { "maxps", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x0F,
                          "maxps xmm1, xmm2/m128 | Maximum of Packed Single-Precision Floating-Point Values | Return the maximum single-precision floating-point values between xmm1 and xmm2/mem.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 1,
                              ._f_opcode_extra = { 0x5F },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/MAXSD.html

                    { { "maxsd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF2,
                          "maxsd xmm1, xmm2/m64 | Return Maximum Scalar Double-Precision Floating-Point Value | Return the maximum scalar double-precision floating-point value between xmm2/m64 and xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x5F },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/MAXSS.html

                    { { "maxss", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF3,
                          "maxss xmm1, xmm2/m32 | Return Maximum Scalar Single-Precision Floating-Point Value | Return the maximum scalar single-precision floating-point value between xmm2/m32 and xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x5F },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PMINSB:PMINSW.html

                    { { "pminsb", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pminsb xmm1, xmm2/m128 | Minimum of Packed Signed Integers | Compare packed signed byte integers in xmm1 and xmm2/m128 and store packed minimum values in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x38,0x38 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.1"] }
                          }
                       }
                    },

                    { { "pminsw", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pminsw xmm1, xmm2/m128 | Minimum of Packed Signed Integers | Compare packed signed word integers in xmm2/m128 and xmm1 and store packed minimum values in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xEA },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PMINSD:PMINSQ.html

                    { { "pminsd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pminsd xmm1, xmm2/m128 | Minimum of Packed Signed Integers | Compare packed signed dword integers in xmm1 and xmm2/m128 and store packed minimum values in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x38,0x39 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.1"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PMINUB:PMINUW.html

                    { { "pminub", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pminub xmm1, xmm2/m128 | Minimum of Packed Unsigned Integers | Compare packed unsigned byte integers in xmm1 and xmm2/m128 and store packed minimum values in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xDA },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },

                    { { "pminuw", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pminuw xmm1, xmm2/m128 | Minimum of Packed Unsigned Integers | Compare packed unsigned word integers in xmm2/m128 and xmm1 and store packed minimum values in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x38 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.1"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PMINUD:PMINUQ.html

                    { { "pminud", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pminud xmm1, xmm2/m128 | Minimum of Packed Unsigned Integers | Compare packed unsigned dword integers in xmm1 and xmm2/m128 and store packed minimum values in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x38,0x3B },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.1"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/MINPD.html

                    { { "minpd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "minpd xmm1, xmm2/m128 | Minimum of Packed Double-Precision Floating-Point Values | Return the minimum double-precision floating-point values between xmm1 and xmm2/mem",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x5D },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/MINPS.html

                    { { "np", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x0F,
                          "np 0F, 5D, /r, MINPS, xmm1, xmm2/m128 | Minimum of Packed Single-Precision Floating-Point Values | Return the minimum single-precision floating-point values between xmm1 and xmm2/mem.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 1,
                              ._f_opcode_extra = { 0x5D },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/MINSD.html

                    { { "minsd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF2,
                          "minsd xmm1, xmm2/m64 | Return Minimum Scalar Double-Precision Floating-Point Value | Return the minimum scalar double-precision floating-point value between xmm2/m64 and xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x5D },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/MINSS.html

                    { { "minss", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF3,
                          "minss xmm1,xmm2/m32 | Return Minimum Scalar Single-Precision Floating-Point Value | Return the minimum scalar single-precision floating-point value between xmm2/m32 and xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x5D },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PHMINPOSUW.html

                    { { "phminposuw", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "phminposuw xmm1, xmm2/m128 | Packed Horizontal Word Minimum | Find the minimum unsigned word in <em>xmm2/m128</em> and place its value in the low word of <em>xmm1</em> and its index in the second-lowest word of <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x38,0x41 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.1"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/MOVSHDUP.html

                    { { "movshdup", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF3,
                          "movshdup xmm1, xmm2/m128 | Replicate Single FP Values | Move odd index single-precision floating-point values from xmm2/mem and duplicate each element into xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x16 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE3"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/MOVHLPS.html

                    { { "movhlps", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x0F,
                          "movhlps xmm1, xmm2 | Move Packed Single-Precision Floating-Point Values High to Low | Move two packed single-precision floating-point values from high quadword of xmm2 to low quadword of xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 1,
                              ._f_opcode_extra = { 0x12 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/MOVSLDUP.html

                    { { "movsldup", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF3,
                          "movsldup xmm1, xmm2/m128 | Replicate Single FP Values | Move even index single-precision floating-point values from xmm2/mem and duplicate each element into xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x12 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE3"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/MOVLHPS.html

                    { { "movlhps", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x0F,
                          "movlhps xmm1, xmm2 | Move Packed Single-Precision Floating-Point Values Low to High | Move two packed single-precision floating-point values from low quadword of xmm2 to high quadword of xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 1,
                              ._f_opcode_extra = { 0x16 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PMOVMSKB.html

                    { { "pmovmskb", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pmovmskb reg, xmm | Move Byte Mask | Move a byte mask of <em>xmm</em> to <em>reg</em>. The upper bits of r32 or r64 are zeroed",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xD7 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/MOVMSKPD.html

                    { { "movmskpd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "movmskpd reg, xmm | Extract Packed Double-Precision Floating-Point Sign Mask | Extract 2-bit sign mask from <em>xmm</em> and store in <em>reg</em>. The upper bits of <em>r32</em> or <em>r64</em> are filled with zeros.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x50 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/MOVMSKPS.html

                    { { "movmskps", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x0F,
                          "movmskps reg, xmm | Extract Packed Single-Precision Floating-Point Sign Mask | Extract 4-bit sign mask from <em>xmm</em> and store in <em>reg</em>. The upper bits of <em>r32</em> or <em>r64</em> are filled with zeros.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 1,
                              ._f_opcode_extra = { 0x50 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/MOVQ2DQ.html
                    // https://www.felixcloutier.com/x86/MPSADBW.html

                    { { "mpsadbw", argtype_t::reg128, argtype_t::regmem128, argtype_t::imm8 },
                       {
                          0x66,
                          "mpsadbw xmm1, xmm2/m128, imm8 | Compute Multiple Packed Sums of Absolute Difference | Sums absolute 8-bit integer difference of adjacent groups of 4 byte integers in <em>xmm1</em> and <em>xmm2/m128</em> and writes the results in <em>xmm1</em>. Starting offsets within <em>xmm1</em> and <em>xmm2/m128</em> are determined by <em>imm8</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x3A,0x42 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.1"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PMULDQ.html

                    { { "pmuldq", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pmuldq xmm1, xmm2/m128 | Multiply Packed Doubleword Integers | Multiply packed signed doubleword integers in xmm1 by packed signed doubleword integers in xmm2/m128, and store the quadword results in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x38,0x28 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.1"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PMULUDQ.html

                    { { "pmuludq", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pmuludq xmm1, xmm2/m128 | Multiply Packed Unsigned Doubleword Integers | Multiply packed unsigned doubleword integers in <em>xmm1</em> by packed unsigned doubleword integers in <em>xmm2/m128</em>, and store the quadword results in <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xF4 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/MULPD.html

                    { { "mulpd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "mulpd xmm1, xmm2/m128 | Multiply Packed Double-Precision Floating-Point Values | Multiply packed double-precision floating-point values in xmm2/m128 with xmm1 and store result in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x59 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/MULPS.html

                    { { "mulps", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x0F,
                          "mulps xmm1, xmm2/m128 | Multiply Packed Single-Precision Floating-Point Values | Multiply packed single-precision floating-point values in xmm2/m128 with xmm1 and store result in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 1,
                              ._f_opcode_extra = { 0x59 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/MULSD.html

                    { { "mulsd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF2,
                          "mulsd xmm1,xmm2/m64 | Multiply Scalar Double-Precision Floating-Point Value | Multiply the low double-precision floating-point value in xmm2/m64 by low double-precision floating-point value in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x59 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/MULSS.html

                    { { "mulss", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF3,
                          "mulss xmm1,xmm2/m32 | Multiply Scalar Single-Precision Floating-Point Values | Multiply the low single-precision floating-point value in xmm2/m32 by the low single-precision floating-point value in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x59 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PMULHW.html

                    { { "pmulhw", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pmulhw xmm1, xmm2/m128 | Multiply Packed Signed Integers and Store High Result | Multiply the packed signed word integers in <em>xmm1</em> and <em>xmm2/m128</em>, and store the high 16 bits of the results in <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xE5 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PMULHUW.html

                    { { "pmulhuw", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pmulhuw xmm1, xmm2/m128 | Multiply Packed Unsigned Integers and Store High Result | Multiply the packed unsigned word integers in <em>xmm1</em> and <em>xmm2/m128</em>, and store the high 16 bits of the results in <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xE4 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PMULHRSW.html

                    { { "pmulhrsw", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pmulhrsw xmm1, xmm2/m128 | Packed Multiply High with Round and Scale | Multiply 16-bit signed words, scale and round signed doublewords, pack high 16 bits to <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x38,0x0B },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSSE3"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PMULLW.html

                    { { "pmullw", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pmullw xmm1, xmm2/m128 | Multiply Packed Signed Integers and Store Low Result | Multiply the packed signed word integers in <em>xmm1</em> and <em>xmm2/m128</em>, and store the low 16 bits of the results in <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xD5 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PMULLD:PMULLQ.html

                    { { "pmulld", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "pmulld xmm1, xmm2/m128 | Multiply Packed Integers and Store Low Result | Multiply the packed dword signed integers in xmm1 and xmm2/m128 and store the low 32 bits of each product in xmm1.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x38,0x40 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.1"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/ORPD.html

                    { { "orpd", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "orpd xmm1, xmm2/m128 | Bitwise Logical OR of Packed Double Precision Floating-Point Values | Return the bitwise logical OR of packed double-precision floating-point values in xmm1 and xmm2/mem.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 1,
                              ._f_opcode_extra = { 0x0F },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/ORPS.html

                    { { "orps", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x0F,
                          "orps xmm1, xmm2/m128 | Bitwise Logical OR of Packed Single Precision Floating-Point Values | Return the bitwise logical OR of packed single-precision floating-point values in xmm1 and xmm2/mem.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 1,
                              ._f_opcode_extra = { 0x56 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/POR.html

                    { { "por", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "por xmm1, xmm2/m128 | Bitwise Logical OR | Bitwise OR of <em>xmm2/m128</em> and <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xEB },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PACKSSWB:PACKSSDW.html

                    { { "packsswb", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "packsswb xmm1, xmm2/m128 | Pack with Signed Saturation | Converts 8 packed signed word integers from <em>xmm1</em> and from <em>xxm2/m128</em> into 16 packed signed byte integers in <em>xxm1</em> using signed saturation.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x63 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },

                    { { "packssdw", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "packssdw xmm1, xmm2/m128 | Pack with Signed Saturation | Converts 4 packed signed doubleword integers from <em>xmm1</em> and from <em>xxm2/m128</em> into 8 packed signed word integers in <em>xxm1</em> using signed saturation.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x6B },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PACKUSWB.html

                    { { "packuswb", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "packuswb xmm1, xmm2/m128 | Pack with Unsigned Saturation | Converts 8 signed word integers from <em>xmm1</em> and 8 signed word integers from <em>xmm2/m128</em> into 16 unsigned byte integers in <em>xmm1</em> using unsigned saturation.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x67 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PACKUSDW.html

                    { { "packusdw", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "packusdw xmm1, xmm2/m128 | Pack with Unsigned Saturation | Convert 4 packed signed doubleword integers from <em>xmm1</em> and 4 packed signed doubleword integers from <em>xmm2/m128</em> into 8 packed unsigned word integers in <em>xmm1</em> using unsigned saturation.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 3,
                              ._f_opcode_extra = { 0x0F,0x38,0x2B },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE4.1"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PAUSE.html
                    // https://www.felixcloutier.com/x86/VPERMILPD.html
                    // https://www.felixcloutier.com/x86/VPERMILPS.html
                    // https://www.felixcloutier.com/x86/VPERM2F128.html
                    // https://www.felixcloutier.com/x86/VPERM2I128.html
                    // https://www.felixcloutier.com/x86/VPERMQ.html
                    // https://www.felixcloutier.com/x86/VPERMPD.html
                    // https://www.felixcloutier.com/x86/VPERMD:VPERMW.html
                    // https://www.felixcloutier.com/x86/VPERMPS.html
                    // https://www.felixcloutier.com/x86/PSADBW.html

                    { { "psadbw", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x66,
                          "psadbw xmm1, xmm2/m128 | Compute Sum of Absolute Differences | Computes the absolute differences of the packed unsigned byte integers from <em>xmm2 /m128</em> and <em>xmm1</em>; the 8 low differences and 8 high differences are then summed separately to produce two unsigned word integer results.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup | opcode_flags_t::operand64size_override,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0xF6 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/PSHUFW.html
                    // https://www.felixcloutier.com/x86/RCPPS.html

                    { { "rcpps", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0x0F,
                          "rcpps xmm1, xmm2/m128 | Compute Reciprocals of Packed Single-Precision Floating-Point Values | Computes the approximate reciprocals of the packed single-precision floating-point values in <em>xmm2/m128</em> and stores the results in <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 1,
                              ._f_opcode_extra = { 0x53 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE"] }
                          }
                       }
                    },
                    // https://www.felixcloutier.com/x86/RCPSS.html

                    { { "rcpss", argtype_t::reg128, argtype_t::regmem128 },
                       {
                          0xF3,
                          "rcpss xmm1, xmm2/m32 | Compute Reciprocal of Scalar Single-Precision Floating-Point Values | Computes the approximate reciprocal of the scalar single-precision floating-point value in <em>xmm2/m32</em> and stores the result in <em>xmm1</em>.",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                              ._f_opcode_count = 2,
                              ._f_opcode_extra = { 0x0F,0x53 },
                              ._f_cpuid_reqs = 1,
                              ._f_cpuid_lookups = { &cpuid_queries()["SSE"] }
                          }
                       }
                    },

                };
                for (auto& instruction : ext)
                {
                    opcode_map().try_emplace(std::move(instruction.first), std::move(instruction.second));
                }
            };
            __static_initialize(__add_extops, add_ext_ops);
        }
    }
}