#pragma once

#include "structures.h"
#include "cpuid.h"

#include <containers/svector>

namespace cgengine
{
    namespace assembler
    {
        _inline umap<signature_t, opcode_t, value_type_hash<signature_t>>& opcode_map()
        {
            static umap<signature_t, opcode_t, value_type_hash<signature_t>>* popcodes_core = statics::get< umap<signature_t, opcode_t, value_type_hash<signature_t>>*>(_FUNC);
            return *popcodes_core;
        }
        namespace ___internal 
        {
            _inline void add_core_ops()
            {
                vector<std::pair<signature_t, opcode_t>> core
                {
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
                    { { "adc",  argtype_t::regmem32, argtype_t::imm32    }, { 0x81, ("adc dst, src | Add with Carry | Adds the carry flag (CF), the value in a register or memory location (first operand), and an immediate value or the value in a register or memory location (second operand), and stores the result in the first operand location. "),               opcode_flags_t::regopcode_ext, {._f_regopcode_ext = 2 } } },
                    { { "adc",  argtype_t::regmem64, argtype_t::imm32    }, { 0x81, ("adc dst, src | Add with Carry | Adds the carry flag (CF), the value in a register or memory location (first operand), and an immediate value or the value in a register or memory location (second operand), and stores the result in the first operand location. "), opcode_flags_t::regopcode_ext, {._f_regopcode_ext = 2 } } },
                    { { "adc",  argtype_t::regmem32, argtype_t::imm8     }, { 0x83, ("adc dst, src | Add with Carry | Adds the carry flag (CF), the value in a register or memory location (first operand), and an immediate value or the value in a register or memory location (second operand), and stores the result in the first operand location. "),  opcode_flags_t::regopcode_ext, {._f_regopcode_ext = 2 } } },
                    { { "adc",  argtype_t::regmem64, argtype_t::imm8     }, { 0x83, ("adc dst, src | Add with Carry | Adds the carry flag (CF), the value in a register or memory location (first operand), and an immediate value or the value in a register or memory location (second operand), and stores the result in the first operand location. "),  opcode_flags_t::regopcode_ext, {._f_regopcode_ext = 2 } } },
                    { { "adc",  argtype_t::regmem32, argtype_t::reg32    }, { 0x11, ("adc dst, src | Add with Carry | Adds the carry flag (CF), the value in a register or memory location (first operand), and an immediate value or the value in a register or memory location (second operand), and stores the result in the first operand location. ") } },
                    { { "adc",  argtype_t::regmem64, argtype_t::reg64    }, { 0x11, ("adc dst, src | Add with Carry | Adds the carry flag (CF), the value in a register or memory location (first operand), and an immediate value or the value in a register or memory location (second operand), and stores the result in the first operand location. ") } },
                    { { "adc",  argtype_t::reg32,    argtype_t::regmem32 }, { 0x13, ("adc dst, src | Add with Carry | Adds the carry flag (CF), the value in a register or memory location (first operand), and an immediate value or the value in a register or memory location (second operand), and stores the result in the first operand location. ") } },
                    { { "adc",  argtype_t::reg64,    argtype_t::regmem64 }, { 0x13, ("adc dst, src | Add with Carry | Adds the carry flag (CF), the value in a register or memory location (first operand), and an immediate value or the value in a register or memory location (second operand), and stores the result in the first operand location. ") } },

                    { { "adox", argtype_t::reg32,    argtype_t::regmem32 }, { 0xF3, "adox dst, src | Unsigned add with overflow flag | Adds the value in a register (first operand) with a register or memory (second operand) and the overflow flag,and stores the result in the first operand location.This instruction sets the OF based on the unsigned additionand whether there is a carry out.This instruction is useful in multi - precision addition algorithms.", opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                        {._f_opcode_count = 3, ._f_opcode_extra = { 0x0F, 0x38, 0xF6 }, ._f_cpuid_reqs = 1, ._f_cpuid_lookups = { &cpuid_queries()["ADX"] } } } },
                    { { "adox", argtype_t::reg64,    argtype_t::regmem64 }, { 0xF3, "adox dst, src | Unsigned add with overflow flag | Adds the value in a register (first operand) with a register or memory (second operand) and the overflow flag,and stores the result in the first operand location.This instruction sets the OF based on the unsigned additionand whether there is a carry out.This instruction is useful in multi - precision addition algorithms.", opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                        {._f_opcode_count = 3, ._f_opcode_extra = { 0x0F, 0x38, 0xF6 }, ._f_cpuid_reqs = 1, ._f_cpuid_lookups = { &cpuid_queries()["ADX"] } } } },


                    { { "and",  argtype_t::EAX,      argtype_t::imm32    }, { 0x25, ("and dst, src | AND | and the contents of EAX with an immediate 32-bit value and store the result in EAX.") } },
                    { { "and",  argtype_t::RAX,      argtype_t::imm32    }, { 0x25, ("and dst, src | AND | and the contents of RAX with an immediate 32-bit value and store the result in RAX.") } },
                    { { "and",  argtype_t::regmem32, argtype_t::imm32    }, { 0x81, ("and dst, src | AND | and the contents of reg/mem32 with imm32."),                 opcode_flags_t::regopcode_ext, {._f_regopcode_ext = 4 } } },
                    { { "and",  argtype_t::regmem64, argtype_t::imm32    }, { 0x81, ("and dst, src | AND | and the contents of reg/mem64 with a sign-extended imm32."), opcode_flags_t::regopcode_ext, {._f_regopcode_ext = 4 } } },
                    { { "and",  argtype_t::regmem32, argtype_t::imm8     }, { 0x83, ("and dst, src | AND | and the contents of reg/mem32 with a sign-extended imm8"),   opcode_flags_t::regopcode_ext, {._f_regopcode_ext = 4 } } },
                    { { "and",  argtype_t::regmem64, argtype_t::imm8     }, { 0x83, ("and dst, src | AND | and the contents of reg/mem64 with a sign-extended imm8"),   opcode_flags_t::regopcode_ext, {._f_regopcode_ext = 4 } } },
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
                                &cpuid_queries()["BMI1"]
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
                                &cpuid_queries()["BMI1"]
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
                                &cpuid_queries()["BMI1"]
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
                                &cpuid_queries()["BMI1"]
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
                                &cpuid_queries()["TBM"]
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
                                &cpuid_queries()["TBM"]
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
                                &cpuid_queries()["BMI1"]
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
                                &cpuid_queries()["BMI1"]
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
                                &cpuid_queries()["BMI1"]
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
                                &cpuid_queries()["BMI1"]
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
                                &cpuid_queries()["BMI1"]
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
                                &cpuid_queries()["BMI1"]
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
                                &cpuid_queries()["BMI2"]
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
                                &cpuid_queries()["BMI2"]
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
                                    &cpuid_queries()["CLFSH"]
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
                                    &cpuid_queries()["CLFLOPT"]
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
                                    &cpuid_queries()["CLWB"]
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
                                    &cpuid_queries()["CLZERO"]
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
                                    &cpuid_queries()["CMOV"]
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
                                    &cpuid_queries()["CMOV"]
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
                                    &cpuid_queries()["CMOV"]
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
                                    &cpuid_queries()["CMOV"]
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
                                    &cpuid_queries()["CMOV"]
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
                                    &cpuid_queries()["CMOV"]
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
                                    &cpuid_queries()["CMOV"]
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
                                    &cpuid_queries()["CMOV"]
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
                                    &cpuid_queries()["CMOV"]
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
                                    &cpuid_queries()["CMOV"]
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
                                    &cpuid_queries()["CMOV"]
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
                                    &cpuid_queries()["CMOV"]
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
                                    &cpuid_queries()["CMOV"]
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
                                    &cpuid_queries()["CMOV"]
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
                                    &cpuid_queries()["CMOV"]
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
                                    &cpuid_queries()["CMOV"]
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
                                    &cpuid_queries()["CMOV"]
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
                                    &cpuid_queries()["CMOV"]
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
                                    &cpuid_queries()["CMOV"]
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
                                    &cpuid_queries()["CMOV"]
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
                                    &cpuid_queries()["CMOV"]
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
                                    &cpuid_queries()["CMOV"]
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
                                    &cpuid_queries()["CMOV"]
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
                                    &cpuid_queries()["CMOV"]
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
                                    &cpuid_queries()["CMOV"]
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
                                    &cpuid_queries()["CMOV"]
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
                                    &cpuid_queries()["CMOV"]
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
                                    &cpuid_queries()["CMOV"]
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
                                    &cpuid_queries()["CMOV"]
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
                                    &cpuid_queries()["CMOV"]
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
                                    &cpuid_queries()["CMOV"]
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
                                    &cpuid_queries()["CMOV"]
                                }
                           }
                        } },


                    { { "cmp",  argtype_t::EAX,      argtype_t::imm32    }, { 0x3D, "cmp a b | Compare | Compares the contents of a register or memory location (first operand) with an immediate value or the contents of a register or memory location(second operand),and sets or clears the status flags in the rFLAGS register to reflect the results.To perform the comparison, the instruction subtracts the second operand from the first operandand sets the status flags in the same manner as the SUB instruction, but does not alter the first operand.If the second operand is an immediate value, the instruction signextends the value to the length of the first operand. Use the CMP instruction to set the condition codes for a subsequent conditional jump(Jcc), conditional move(CMOVcc), or conditional SETcc instruction.Appendix F, \"Instruction Effects on RFLAGS\" shows how instructions affect the rFLAGS status flags." } },
                    { { "cmp",  argtype_t::RAX,      argtype_t::imm32    }, { 0x3D, "cmp a b | Compare | Compares the contents of a register or memory location (first operand) with an immediate value or the contents of a register or memory location(second operand),and sets or clears the status flags in the rFLAGS register to reflect the results.To perform the comparison, the instruction subtracts the second operand from the first operandand sets the status flags in the same manner as the SUB instruction, but does not alter the first operand.If the second operand is an immediate value, the instruction signextends the value to the length of the first operand. Use the CMP instruction to set the condition codes for a subsequent conditional jump(Jcc), conditional move(CMOVcc), or conditional SETcc instruction.Appendix F, \"Instruction Effects on RFLAGS\" shows how instructions affect the rFLAGS status flags." } },

                    { { "cmp",  argtype_t::regmem32, argtype_t::imm32    },
                        { 0x81,
                          "cmp a b | Compare | Compares the contents of a register or memory location (first operand) with an immediate value or the contents of a register or memory location(second operand),and sets or clears the status flags in the rFLAGS register to reflect the results.To perform the comparison, the instruction subtracts the second operand from the first operandand sets the status flags in the same manner as the SUB instruction, but does not alter the first operand.If the second operand is an immediate value, the instruction signextends the value to the length of the first operand. Use the CMP instruction to set the condition codes for a subsequent conditional jump(Jcc), conditional move(CMOVcc), or conditional SETcc instruction.Appendix F, \"Instruction Effects on RFLAGS\" shows how instructions affect the rFLAGS status flags.",
                          opcode_flags_t::regopcode_ext,
                          {._f_regopcode_ext = 7 }
                        } },
                    { { "cmp",  argtype_t::regmem64, argtype_t::imm32    },
                        { 0x81,
                          "cmp a b | Compare | Compares the contents of a register or memory location (first operand) with an immediate value or the contents of a register or memory location(second operand),and sets or clears the status flags in the rFLAGS register to reflect the results.To perform the comparison, the instruction subtracts the second operand from the first operandand sets the status flags in the same manner as the SUB instruction, but does not alter the first operand.If the second operand is an immediate value, the instruction signextends the value to the length of the first operand. Use the CMP instruction to set the condition codes for a subsequent conditional jump(Jcc), conditional move(CMOVcc), or conditional SETcc instruction.Appendix F, \"Instruction Effects on RFLAGS\" shows how instructions affect the rFLAGS status flags.",
                          opcode_flags_t::regopcode_ext,
                          {._f_regopcode_ext = 7 }
                        } },


                    { { "cmp",  argtype_t::regmem32, argtype_t::imm8    },
                        { 0x83,
                          "cmp a b | Compare | Compares the contents of a register or memory location (first operand) with an immediate value or the contents of a register or memory location(second operand),and sets or clears the status flags in the rFLAGS register to reflect the results.To perform the comparison, the instruction subtracts the second operand from the first operandand sets the status flags in the same manner as the SUB instruction, but does not alter the first operand.If the second operand is an immediate value, the instruction signextends the value to the length of the first operand. Use the CMP instruction to set the condition codes for a subsequent conditional jump(Jcc), conditional move(CMOVcc), or conditional SETcc instruction.Appendix F, \"Instruction Effects on RFLAGS\" shows how instructions affect the rFLAGS status flags.",
                          opcode_flags_t::regopcode_ext,
                          {._f_regopcode_ext = 7 }
                        } },
                    { { "cmp",  argtype_t::regmem64, argtype_t::imm8    },
                        { 0x83,
                          "cmp a b | Compare | Compares the contents of a register or memory location (first operand) with an immediate value or the contents of a register or memory location(second operand),and sets or clears the status flags in the rFLAGS register to reflect the results.To perform the comparison, the instruction subtracts the second operand from the first operandand sets the status flags in the same manner as the SUB instruction, but does not alter the first operand.If the second operand is an immediate value, the instruction signextends the value to the length of the first operand. Use the CMP instruction to set the condition codes for a subsequent conditional jump(Jcc), conditional move(CMOVcc), or conditional SETcc instruction.Appendix F, \"Instruction Effects on RFLAGS\" shows how instructions affect the rFLAGS status flags.",
                          opcode_flags_t::regopcode_ext,
                          {._f_regopcode_ext = 7 }
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
                            ._f_cpuid_lookups = { &cpuid_queries()["CMPXCHG16B"] }
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
                            ._f_cpuid_lookups = { &cpuid_queries()["SSE4.2"] }
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
                            ._f_cpuid_lookups = { &cpuid_queries()["SSE4.2"] }
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
                    { { "int 3" },
                      {
                          0xCC,
                          "int 3 | Interrupt to Debug Vector | Calls the debug exception handler."
                      }
                    },
                    { { "iret" },
                      {
                          0xCF,
                          "iret | Return from Interrupt",
                          opcode_flags_t::operand64size_override
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
                                &cpuid_queries()["LahfSahf"]
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
                            ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
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
                            ._f_cpuid_lookups = { &cpuid_queries()["ABM"] }
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
                            ._f_cpuid_lookups = { &cpuid_queries()["ABM"] }
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
                            ._f_cpuid_lookups = { &cpuid_queries()["MCOMMIT"] }
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
                            ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
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
                            ._f_cpuid_lookups = { &cpuid_queries()["MONITORX"] }
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
                            ._f_cpuid_lookups = { &cpuid_queries()["MOVBE"] }
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
                            ._f_cpuid_lookups = { &cpuid_queries()["MOVBE"] }
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
                            ._f_cpuid_lookups = { &cpuid_queries()["MOVBE"] }
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
                            ._f_cpuid_lookups = { &cpuid_queries()["MOVBE"] }
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
                            ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
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
                            ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
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
                            ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
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
                            ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
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
                            ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
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
                            ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
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
                            ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
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
                            ._f_cpuid_lookups = { &cpuid_queries()["SSE2"] }
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
                            ._f_cpuid_lookups = { &cpuid_queries()["BMI2"] },
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
                            ._f_cpuid_lookups = { &cpuid_queries()["BMI2"] },
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
                            ._f_cpuid_lookups = { &cpuid_queries()["BMI2"] },
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
                            ._f_cpuid_lookups = { &cpuid_queries()["BMI2"] },
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
                            ._f_cpuid_lookups = { &cpuid_queries()["BMI2"] },
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
                            ._f_cpuid_lookups = { &cpuid_queries()["BMI2"] },
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
                            ._f_cpuid_lookups = { &cpuid_queries()["POPCNT"] }
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
                            ._f_cpuid_lookups = { &cpuid_queries()["3DNowPrefetch"], &cpuid_queries()["LM"], &cpuid_queries()["3DNow"] }
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
                            ._f_cpuid_lookups = { &cpuid_queries()["3DNowPrefetch"], &cpuid_queries()["LM"], &cpuid_queries()["3DNow"] }
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
                            ._f_cpuid_lookups = { &cpuid_queries()["3DNowPrefetch"], &cpuid_queries()["LM"], &cpuid_queries()["3DNow"] }
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
                            ._f_cpuid_lookups = { &cpuid_queries()["3DNowPrefetch"], &cpuid_queries()["LM"], &cpuid_queries()["3DNow"] }
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
                            ._f_cpuid_lookups = { &cpuid_queries()["3DNowPrefetch"], &cpuid_queries()["LM"], &cpuid_queries()["3DNow"] }
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
                            ._f_cpuid_lookups = { &cpuid_queries()["3DNowPrefetch"], &cpuid_queries()["LM"], &cpuid_queries()["3DNow"] }
                          }
                      }
                    },

                    { { "push", argtype_t::regmem32, }, { 0xFF, ("Push the contents of a 32-bit register or memory operand onto the stack (No prefix for encoding this in 64-bit mode)."), opcode_flags_t::regopcode_ext | opcode_flags_t::operand64size_override, {._f_regopcode_ext = 6 } } },
                    { { "push", argtype_t::regmem64, }, { 0xFF, ("Push the contents of a 64-bit register or memory operand onto the stack."), opcode_flags_t::regopcode_ext, {._f_regopcode_ext = 6 } } },
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

                    { { "rdpmc" },
                      {
                          0x0F,
                          "rdpmc | Read Performance-Monitoring Counter | Reads the contents of a 64-bit performance counter and returns it in the registers EDX:EAX. The ECX register is used to specify the index of the performance counter to be read. The EDX register receives the high-order 32 bits and the EAX register receives the low order 32 bits of the counter. The RDPMC instruction ignores operand size; the index and the return values are all 32 bits ",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                            ._f_opcode_count = 1,
                            ._f_opcode_extra = { 0x33 },
                            ._f_cpuid_reqs = 1,
                            ._f_cpuid_lookups = { &cpuid_queries()["PerfCtrExtCore"] }
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
                            ._f_cpuid_lookups = { &cpuid_queries()["RDRAND"] }
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
                            ._f_cpuid_lookups = { &cpuid_queries()["RDRAND"] }
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
                            ._f_cpuid_lookups = { &cpuid_queries()["RDRAND"] }
                          }
                      }
                    },

                    { { "rdtsc" },
                      {
                          0x0F,
                          "rdtsc | Read Time-Stamp Counter | Copy the time-stamp counter into EDX:EAX. The behavior of the RDTSC instruction is implementation dependent. The TSC counts at a constant rate, but may be affected by power management events (such as frequency changes), depending on the processor implementation. If CPUID Fn8000_0007_EDX[TscInvariant] = 1, then the TSC rate is ensured to be invariant across all P-States, C-States, and stop-grant transitions (such as STPCLK Throttling); therefore, the TSC is suitable for use as a source of time. Consult the BIOS and Kernel Developer’s Guide applicable to your product for information concerning the effect of power management on the TSC",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                            ._f_opcode_count = 1,
                            ._f_opcode_extra = { 0x31 },
                            ._f_cpuid_reqs = 1,
                            ._f_cpuid_lookups = { &cpuid_queries()["TSC"] }
                          }
                      }
                    },
                    { { "rdtscp" },
                      {
                          0x0F,
                          "rdtscp | Read Time-Stamp Counter and Process ID | Copy the time-stamp counter into EDX:EAX and the TSC_AUX register into ECX. Unlike the RDTSC instruction, RDTSCP forces all older instructions to retire before reading the timestamp counter. The behavior of the RDTSC instruction is implementation dependent. The TSC counts at a constant rate, but may be affected by power management events (such as frequency changes), depending on the processor implementation. If CPUID Fn8000_0007_EDX[TscInvariant] = 1, then the TSC rate is ensured to be invariant across all P-States, C-States, and stop-grant transitions (such as STPCLK Throttling); therefore, the TSC is suitable for use as a source of time. Consult the BIOS and Kernel Developer’s Guide applicable to your product for information concerning the effect of power management on the TSC",
                          opcode_flags_t::multibyte_opcode | opcode_flags_t::requires_cpuid_lookup,
                          {
                            ._f_opcode_count = 1,
                            ._f_opcode_extra = { 0x31 },
                            ._f_cpuid_reqs = 1,
                            ._f_cpuid_lookups = { &cpuid_queries()["TSC"] }
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
                            ._f_cpuid_lookups = { &cpuid_queries()["BMI2"] },
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
                            ._f_cpuid_lookups = { &cpuid_queries()["BMI2"] },
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
                            ._f_cpuid_lookups = { &cpuid_queries()["LahfSahf"] }
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
                            ._f_cpuid_lookups = { &cpuid_queries()["BMI2"] },
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
                            ._f_cpuid_lookups = { &cpuid_queries()["SSE"] }
                          }
                      }
                    },

                    { { "sidt", argtype_t::mem64 },
                      {
                          0x0F,
                          "sidt mem | Store Interrupt Descriptor Table Register | Stores the interrupt descriptor table register (IDTR) in the destination operand. In legacy and compatibility mode, the destination operand is 6 bytes; in 64-bit mode it is 10 bytes. In all modes, operand-size prefixes are ignored. In non-64-bit mode, the lower two bytes of the operand specify the 16-bit limit and the upper 4 bytes specify the 32-bit base address. In 64-bit mode, the lower two bytes of the operand specify the 16-bit limit and the upper 8 bytes specify the 64-bit base address. ",
                          opcode_flags_t::regopcode_ext | opcode_flags_t::multibyte_opcode,
                          {
                            ._f_regopcode_ext = 1,
                            ._f_opcode_count = 1,
                            ._f_opcode_extra = { 0x01 }
                          }
                      }
                    },
                    { { "sgdt", argtype_t::mem64 },
                      {
                          0x0F,
                          "sgdt mem | Store Global Descriptor Table Register | Stores the global descriptor table register (GDTR) into the destination operand. In legacy and compatibility mode, the destination operand is 6 bytes; in 64-bit mode, it is 10 bytes. In all modes, operand-size prefixes are ignored. In non-64-bit mode, the lower two bytes of the operand specify the 16-bit limit and the upper 4 bytes specify the 32-bit base address. In 64-bit mode, the lower two bytes of the operand specify the 16-bit limit and the upper 8 bytes specify the 64-bit base address.",
                          opcode_flags_t::regopcode_ext | opcode_flags_t::multibyte_opcode,
                          {
                            ._f_regopcode_ext = 0,
                            ._f_opcode_count = 1,
                            ._f_opcode_extra = { 0x01 }
                          }
                      }
                    },
                    { { "sldt", argtype_t::reg64 },
                      {
                          0x0F,
                          "sldt dst | Store Local Descriptor Table Register | Stores the local descriptor table (LDT) selector to a register or memory destination operand. If the destination is a register, the selector is zero-extended into a 16-, 32-, or 64-bit general purpose register, depending on operand size. If the destination operand is a memory location, the segment selector is written to memory as a 16-bit value, regardless of operand size",
                          opcode_flags_t::regopcode_ext | opcode_flags_t::multibyte_opcode,
                          {
                            ._f_regopcode_ext = 0,
                            ._f_opcode_count = 1,
                            ._f_opcode_extra = { 0x00 }
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
                { { "str", argtype_t::reg32 },
                  { 0x0F,
                    "str dst | Store Task Register | Stores the task register (TR) selector to a register or memory destination operand. If the destination is a register, the selector is zero-extended into a 16-, 32-, or 64-bit general purpose register, depending on the operand size. If the destination is a memory location, the segment selector is written to memory as a 16-bit value, regardless of operand size.",
                    opcode_flags_t::multibyte_opcode | opcode_flags_t::regopcode_ext,
                    {
                      ._f_regopcode_ext = 1,
                      ._f_opcode_count = 1,
                      ._f_opcode_extra = { 0x00 }
                    }
                } },
                { { "str", argtype_t::reg64 },
                  { 0x0F,
                    "str dst | Store Task Register | Stores the task register (TR) selector to a register or memory destination operand. If the destination is a register, the selector is zero-extended into a 16-, 32-, or 64-bit general purpose register, depending on the operand size. If the destination is a memory location, the segment selector is written to memory as a 16-bit value, regardless of operand size.",
                    opcode_flags_t::multibyte_opcode | opcode_flags_t::regopcode_ext,
                    {
                      ._f_regopcode_ext = 1,
                      ._f_opcode_count = 1,
                      ._f_opcode_extra = { 0x00 }
                    }
                } },
                { { "str", argtype_t::mem64 },
                  { 0x0F,
                    "str dst | Store Task Register | Stores the task register (TR) selector to a register or memory destination operand. If the destination is a register, the selector is zero-extended into a 16-, 32-, or 64-bit general purpose register, depending on the operand size. If the destination is a memory location, the segment selector is written to memory as a 16-bit value, regardless of operand size.",
                    opcode_flags_t::multibyte_opcode | opcode_flags_t::regopcode_ext,
                    {
                      ._f_regopcode_ext = 1,
                      ._f_opcode_count = 1,
                      ._f_opcode_extra = { 0x00 }
                    }
                } },



                { { "sub",  argtype_t::EAX,      argtype_t::imm32    }, { 0x2D, ("Subtract imm32 to EAX") } },
                { { "sub",  argtype_t::RAX,      argtype_t::imm32    }, { 0x2D, ("Subtract sign-extended imm32 to RAX") } },
                { { "sub",  argtype_t::regmem32, argtype_t::imm32    }, { 0x81, ("Subtract imm32 to reg/mem32"),               opcode_flags_t::regopcode_ext, {._f_regopcode_ext = 5 } } },
                { { "sub",  argtype_t::regmem64, argtype_t::imm32    }, { 0x81, ("Subtract sign-extended imm32 to reg/mem64"), opcode_flags_t::regopcode_ext, {._f_regopcode_ext = 5 } } },
                { { "sub",  argtype_t::regmem32, argtype_t::imm8     }, { 0x83, ("Subtract sign-extended imm8 to reg/mem32"),  opcode_flags_t::regopcode_ext, {._f_regopcode_ext = 5 } } },
                { { "sub",  argtype_t::regmem64, argtype_t::imm8     }, { 0x83, ("Subtract sign-extended imm8 to reg/mem64"),  opcode_flags_t::regopcode_ext, {._f_regopcode_ext = 5 } } },
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
                        ._f_cpuid_lookups = { &cpuid_queries()["BMI1"] }
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
                        ._f_cpuid_lookups = { &cpuid_queries()["BMI1"] }
                      }
                  }
                },

                { { "xadd", argtype_t::regmem32, argtype_t::reg32 },
                  {
                      0x0F,
                      "xadd dst, src | Exchange and Add | Exchanges the contents of a register (second operand) with the contents of a register or memory location (first operand), computes the sum of the two values, and stores the result in the first operand location. The forms of the XADD instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see “Lock Prefix” on page 11. ",
                      opcode_flags_t::multibyte_opcode,
                      {
                        ._f_opcode_count = 1,
                        ._f_opcode_extra = { 0xC1 }
                      }
                  }
                },
                { { "xadd", argtype_t::regmem64, argtype_t::reg64 },
                  {
                      0x0F,
                      "xadd dst, src | Exchange and Add | Exchanges the contents of a register (second operand) with the contents of a register or memory location (first operand), computes the sum of the two values, and stores the result in the first operand location. The forms of the XADD instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see “Lock Prefix” on page 11. ",
                      opcode_flags_t::multibyte_opcode,
                      {
                        ._f_opcode_count = 1,
                        ._f_opcode_extra = { 0xC1 }
                      }
                  }
                },


                { { "xchg", argtype_t::EAX, argtype_t::reg32 },
                  {
                      0x90,
                      "xchg a, b | Exchange | Exchanges the contents of the two operands. The operands can be two general-purpose registers or a register and a memory location. If either operand references memory, the processor locks automatically, whether or not the LOCK prefix is used and independently of the value of IOPL. For details about the LOCK prefix, see “Lock Prefix” on page 11. The x86 architecture commonly uses the XCHG EAX, EAX instruction (opcode 90h) as a one-byte NOP. In 64-bit mode, the processor treats opcode 90h as a true NOP only if it would exchange rAX with itself. Without this special handling, the instruction would zero-extend the upper 32 bits of RAX, and thus it would not be a true no-operation. Opcode 90h can still be used to exchange rAX and r8 if the appropriate REX prefix is used. This special handling does not apply to the two-byte ModRM form of the XCHG instruction. ",
                      opcode_flags_t::register_adjusted
                  }
                },
                { { "xchg", argtype_t::reg32, argtype_t::EAX },
                  {
                      0x90,
                      "xchg a, b | Exchange | Exchanges the contents of the two operands. The operands can be two general-purpose registers or a register and a memory location. If either operand references memory, the processor locks automatically, whether or not the LOCK prefix is used and independently of the value of IOPL. For details about the LOCK prefix, see “Lock Prefix” on page 11. The x86 architecture commonly uses the XCHG EAX, EAX instruction (opcode 90h) as a one-byte NOP. In 64-bit mode, the processor treats opcode 90h as a true NOP only if it would exchange rAX with itself. Without this special handling, the instruction would zero-extend the upper 32 bits of RAX, and thus it would not be a true no-operation. Opcode 90h can still be used to exchange rAX and r8 if the appropriate REX prefix is used. This special handling does not apply to the two-byte ModRM form of the XCHG instruction. ",
                      opcode_flags_t::register_adjusted
                  }
                },

                { { "xchg", argtype_t::RAX, argtype_t::reg64 },
                  {
                      0x90,
                      "xchg a, b | Exchange | Exchanges the contents of the two operands. The operands can be two general-purpose registers or a register and a memory location. If either operand references memory, the processor locks automatically, whether or not the LOCK prefix is used and independently of the value of IOPL. For details about the LOCK prefix, see “Lock Prefix” on page 11. The x86 architecture commonly uses the XCHG EAX, EAX instruction (opcode 90h) as a one-byte NOP. In 64-bit mode, the processor treats opcode 90h as a true NOP only if it would exchange rAX with itself. Without this special handling, the instruction would zero-extend the upper 32 bits of RAX, and thus it would not be a true no-operation. Opcode 90h can still be used to exchange rAX and r8 if the appropriate REX prefix is used. This special handling does not apply to the two-byte ModRM form of the XCHG instruction. ",
                      opcode_flags_t::register_adjusted
                  }
                },
                { { "xchg", argtype_t::reg64, argtype_t::RAX },
                  {
                      0x90,
                      "xchg a, b | Exchange | Exchanges the contents of the two operands. The operands can be two general-purpose registers or a register and a memory location. If either operand references memory, the processor locks automatically, whether or not the LOCK prefix is used and independently of the value of IOPL. For details about the LOCK prefix, see “Lock Prefix” on page 11. The x86 architecture commonly uses the XCHG EAX, EAX instruction (opcode 90h) as a one-byte NOP. In 64-bit mode, the processor treats opcode 90h as a true NOP only if it would exchange rAX with itself. Without this special handling, the instruction would zero-extend the upper 32 bits of RAX, and thus it would not be a true no-operation. Opcode 90h can still be used to exchange rAX and r8 if the appropriate REX prefix is used. This special handling does not apply to the two-byte ModRM form of the XCHG instruction. ",
                      opcode_flags_t::register_adjusted
                  }
                },


                { { "xchg", argtype_t::regmem32, argtype_t::reg32 },
                  {
                      0x87,
                      "xchg a, b | Exchange | Exchanges the contents of the two operands. The operands can be two general-purpose registers or a register and a memory location. If either operand references memory, the processor locks automatically, whether or not the LOCK prefix is used and independently of the value of IOPL. For details about the LOCK prefix, see “Lock Prefix” on page 11. The x86 architecture commonly uses the XCHG EAX, EAX instruction (opcode 90h) as a one-byte NOP. In 64-bit mode, the processor treats opcode 90h as a true NOP only if it would exchange rAX with itself. Without this special handling, the instruction would zero-extend the upper 32 bits of RAX, and thus it would not be a true no-operation. Opcode 90h can still be used to exchange rAX and r8 if the appropriate REX prefix is used. This special handling does not apply to the two-byte ModRM form of the XCHG instruction. "
                  }
                },
                { { "xchg", argtype_t::reg32, argtype_t::regmem32 },
                  {
                      0x87,
                      "xchg a, b | Exchange | Exchanges the contents of the two operands. The operands can be two general-purpose registers or a register and a memory location. If either operand references memory, the processor locks automatically, whether or not the LOCK prefix is used and independently of the value of IOPL. For details about the LOCK prefix, see “Lock Prefix” on page 11. The x86 architecture commonly uses the XCHG EAX, EAX instruction (opcode 90h) as a one-byte NOP. In 64-bit mode, the processor treats opcode 90h as a true NOP only if it would exchange rAX with itself. Without this special handling, the instruction would zero-extend the upper 32 bits of RAX, and thus it would not be a true no-operation. Opcode 90h can still be used to exchange rAX and r8 if the appropriate REX prefix is used. This special handling does not apply to the two-byte ModRM form of the XCHG instruction. "
                  }
                },
                { { "xchg", argtype_t::regmem64, argtype_t::reg64 },
                  {
                      0x87,
                      "xchg a, b | Exchange | Exchanges the contents of the two operands. The operands can be two general-purpose registers or a register and a memory location. If either operand references memory, the processor locks automatically, whether or not the LOCK prefix is used and independently of the value of IOPL. For details about the LOCK prefix, see “Lock Prefix” on page 11. The x86 architecture commonly uses the XCHG EAX, EAX instruction (opcode 90h) as a one-byte NOP. In 64-bit mode, the processor treats opcode 90h as a true NOP only if it would exchange rAX with itself. Without this special handling, the instruction would zero-extend the upper 32 bits of RAX, and thus it would not be a true no-operation. Opcode 90h can still be used to exchange rAX and r8 if the appropriate REX prefix is used. This special handling does not apply to the two-byte ModRM form of the XCHG instruction. "
                  }
                },
                { { "xchg", argtype_t::reg64, argtype_t::regmem64 },
                  {
                      0x87,
                      "xchg a, b | Exchange | Exchanges the contents of the two operands. The operands can be two general-purpose registers or a register and a memory location. If either operand references memory, the processor locks automatically, whether or not the LOCK prefix is used and independently of the value of IOPL. For details about the LOCK prefix, see “Lock Prefix” on page 11. The x86 architecture commonly uses the XCHG EAX, EAX instruction (opcode 90h) as a one-byte NOP. In 64-bit mode, the processor treats opcode 90h as a true NOP only if it would exchange rAX with itself. Without this special handling, the instruction would zero-extend the upper 32 bits of RAX, and thus it would not be a true no-operation. Opcode 90h can still be used to exchange rAX and r8 if the appropriate REX prefix is used. This special handling does not apply to the two-byte ModRM form of the XCHG instruction. "
                  }
                },

                { { "xor",  argtype_t::EAX,      argtype_t::imm32    }, { 0x35, ("xor dst, src | Logical Exclusive OR | Performs a bit-wise logical xor operation on both operands and stores the result in the first operand location. The first operand can be a register or memory location. The second operand can be an immediate value, a register, or a memory location. XOR-ing a register with itself clears the register. The forms of the XOR instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see “Lock Prefix” on page 11. ") } },
                { { "xor",  argtype_t::RAX,      argtype_t::imm32    }, { 0x35, ("xor dst, src | Logical Exclusive OR | Performs a bit-wise logical xor operation on both operands and stores the result in the first operand location. The first operand can be a register or memory location. The second operand can be an immediate value, a register, or a memory location. XOR-ing a register with itself clears the register. The forms of the XOR instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see “Lock Prefix” on page 11. ") } },
                { { "xor",  argtype_t::regmem32, argtype_t::imm32    }, { 0x81, ("xor dst, src | Logical Exclusive OR | Performs a bit-wise logical xor operation on both operands and stores the result in the first operand location. The first operand can be a register or memory location. The second operand can be an immediate value, a register, or a memory location. XOR-ing a register with itself clears the register. The forms of the XOR instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see “Lock Prefix” on page 11. "), opcode_flags_t::regopcode_ext, {._f_regopcode_ext = 6 } } },
                { { "xor",  argtype_t::regmem64, argtype_t::imm32    }, { 0x81, ("xor dst, src | Logical Exclusive OR | Performs a bit-wise logical xor operation on both operands and stores the result in the first operand location. The first operand can be a register or memory location. The second operand can be an immediate value, a register, or a memory location. XOR-ing a register with itself clears the register. The forms of the XOR instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see “Lock Prefix” on page 11. "), opcode_flags_t::regopcode_ext, {._f_regopcode_ext = 6 } } },
                { { "xor",  argtype_t::regmem32, argtype_t::imm8     }, { 0x83, ("xor dst, src | Logical Exclusive OR | Performs a bit-wise logical xor operation on both operands and stores the result in the first operand location. The first operand can be a register or memory location. The second operand can be an immediate value, a register, or a memory location. XOR-ing a register with itself clears the register. The forms of the XOR instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see “Lock Prefix” on page 11. "), opcode_flags_t::regopcode_ext, {._f_regopcode_ext = 6 } } },
                { { "xor",  argtype_t::regmem64, argtype_t::imm8     }, { 0x83, ("xor dst, src | Logical Exclusive OR | Performs a bit-wise logical xor operation on both operands and stores the result in the first operand location. The first operand can be a register or memory location. The second operand can be an immediate value, a register, or a memory location. XOR-ing a register with itself clears the register. The forms of the XOR instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see “Lock Prefix” on page 11. "), opcode_flags_t::regopcode_ext, {._f_regopcode_ext = 6 } } },
                { { "xor",  argtype_t::regmem32, argtype_t::reg32    }, { 0x31, ("xor dst, src | Logical Exclusive OR | Performs a bit-wise logical xor operation on both operands and stores the result in the first operand location. The first operand can be a register or memory location. The second operand can be an immediate value, a register, or a memory location. XOR-ing a register with itself clears the register. The forms of the XOR instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see “Lock Prefix” on page 11. ") } },
                { { "xor",  argtype_t::regmem64, argtype_t::reg64    }, { 0x31, ("xor dst, src | Logical Exclusive OR | Performs a bit-wise logical xor operation on both operands and stores the result in the first operand location. The first operand can be a register or memory location. The second operand can be an immediate value, a register, or a memory location. XOR-ing a register with itself clears the register. The forms of the XOR instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see “Lock Prefix” on page 11. ") } },
                { { "xor",  argtype_t::reg32,    argtype_t::regmem32 }, { 0x33, ("xor dst, src | Logical Exclusive OR | Performs a bit-wise logical xor operation on both operands and stores the result in the first operand location. The first operand can be a register or memory location. The second operand can be an immediate value, a register, or a memory location. XOR-ing a register with itself clears the register. The forms of the XOR instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see “Lock Prefix” on page 11. ") } },
                { { "xor",  argtype_t::reg64,    argtype_t::regmem64 }, { 0x33, ("xor dst, src | Logical Exclusive OR | Performs a bit-wise logical xor operation on both operands and stores the result in the first operand location. The first operand can be a register or memory location. The second operand can be an immediate value, a register, or a memory location. XOR-ing a register with itself clears the register. The forms of the XOR instruction that write to memory support the LOCK prefix. For details about the LOCK prefix, see “Lock Prefix” on page 11. ") } },


                };
                for (auto& instruction : core)
                {
                    opcode_map().try_emplace(std::move(instruction.first), std::move(instruction.second));
                }
            };

            __static_initialize(__add_coreops, add_core_ops);
        }
    }
}