#pragma once
#include <regex>
#include "structures.h"
#include "cpuid.h"
#include "opcodes_core.h"

namespace cgengine
{
    namespace assembler
    {

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
                            ret.base = register_t(buffer<char>::from_ptr(matches[2].first, matches[2].second - matches[2].first));
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
                            ret.base = register_t(buffer<char>::from_ptr(matches[8].first, matches[8].second - matches[8].first));
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
                    return instruction_t{ .opcode = {.flags = opcode_flags_t::label } };
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
                        if (auto op = opcode_map().find(test); op != opcode_map().end())
                        {
                            ret.signature = test;
                            ret.args[0] = argument_t{
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
                if (auto op = opcode_map().find(test); op != opcode_map().end())
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
            thread_local static void* mem = nullptr;
            if (mem == nullptr)
            {
                mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            }

            __checkedinto(assembly, assemble(header + "mov eax, " + fn + "\nmov ecx, " + subfn + "\n" + footer));
            memcpy(mem, assembly.ptr(), assembly.size());

            using cd = int(*)(uint32_t* rax, uint32_t* rbx, uint32_t* rcx, uint32_t* rdx);

            uint32_t result[4];
            ((cd)mem)(result, result + 1, result + 2, result + 3);

            return (result[(int32_t)regpos] >> bit_start) & mask(bit_end - bit_start);
        }
    }

}
