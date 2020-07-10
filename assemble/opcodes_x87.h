#pragma once

#include "opcodes_core.h"

namespace cgengine
{
    namespace assembler
    {
        namespace ___internal
        {
            _inline void add_x87_ops()
            {
                vector<std::pair<signature_t, opcode_t>> core
                {
                    { { "f2xm1" }, 
                      {
                          0xD9,
                          "f2xm1 | Floating-Point Compute 2^x - 1 | Raises 2 to the power specified by the value in ST(0), subtracts 1, and stores the result in ST(0). The source value must be in the range –1.0 to +1.0. The result is undefined for source values outside this range. This instruction, when used in conjunction with the FYL2X instruction, can be applied to calculate z=xy by taking advantage of the log property xy = 2y*log 2 x.",
                          opcode_flags_t::multibyte_opcode,
                          {
                            ._f_opcode_count = 1,
                            ._f_opcode_extra = { 0xF0 }
                          }
                      } 
                    },
                    { { "fld" },
                      {
                          0xD9,
                          "f2xm1 | Floating-Point Compute 2^x - 1 | Raises 2 to the power specified by the value in ST(0), subtracts 1, and stores the result in ST(0). The source value must be in the range –1.0 to +1.0. The result is undefined for source values outside this range. This instruction, when used in conjunction with the FYL2X instruction, can be applied to calculate z=xy by taking advantage of the log property xy = 2y*log 2 x.",
                          opcode_flags_t::multibyte_opcode,
                          {
                            ._f_opcode_count = 1,
                            ._f_opcode_extra = { 0xF0 }
                          }
                      }
                    },
                };
                for (auto& instruction : core)
                {
                     opcode_map().try_emplace(std::move(instruction.first), std::move(instruction.second));
                }
            };
            __static_initialize(__add_87ops, add_x87_ops);
        }
    }
}