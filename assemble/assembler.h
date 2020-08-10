#pragma once
#include <regex>
#include <json.h>
#include "structures.h"
#include "cpuid.h"
#include "opcodes_core.h"
#include "linktable_core.h"

namespace cgengine
{
    namespace assembler
    {

        struct asmexe
        {
            void* pexecutable = nullptr;
            json::token asmmeta;

            _executeinline asmexe() {}
            __nocopy(asmexe);
            _executeinline asmexe(asmexe&& other) noexcept :
                pexecutable(other.pexecutable),
                asmmeta(std::move(other.asmmeta))
            {
                other.pexecutable = nullptr;
            }
            __move(asmexe);
            ~asmexe()
            {
                if (pexecutable != nullptr)
                {
                    VirtualFree(pexecutable, 0, MEM_RELEASE);
                }
            }

            _executeinline void* operator[](__referencestring const string& fnname) const noexcept
            {
                __referencestring__assert(fnname);

                if (auto& f = asmmeta[s("export-procs")][&fnname]; f.type() == json::value_type::none)
                {
                    return nullptr;
                }
                else
                {
                    return (void*)(((uint8_t*)pexecutable) + ((int64_t)f[s("rip")]));
                }
            }
        };

        struct data_type
        {
            enum vt : uint32_t
            {
                __none = 0,
                __uint8_t = 0xFFFFFFFF,
                __uint32_t = 0xFFFFFFFF - 1,
                __uint64_t = 0xFFFFFFFF - 2,
                __int8_t = 0xFFFFFFFF - 3,
                __int32_t = 0xFFFFFFFF - 4,
                __int64_t = 0xFFFFFFFF - 5,
                __single_float_t = 0xFFFFFFFF - 6,
                __double_float_t = 0xFFFFFFFF - 7,
                __data_t = 0xFFFFFFFF - 8
            } value;
            __enum(data_type);
            data_type(const buffer<char>& name) noexcept :
                value(__none)
            {
                if (name == "__uint8") value = __uint8_t;
                else if (name == "__uint32") value = __uint32_t;
                else if (name == "__uint64") value = __uint64_t;
                else if (name == "__int8") value = __int8_t;
                else if (name == "__int32") value = __int32_t;
                else if (name == "__int64") value = __int64_t;
                else if (name == "__single_float") value = __single_float_t;
                else if (name == "__double_float") value = __double_float_t;
                else if (name == "__data") value = __data_t;
            }

            error parse(buffervec<uint8_t>& assembly, nextany_tokenizer::const_iterator_t& b, const nextany_tokenizer::const_iterator_t& e) const noexcept
            {
                int64_t vi64;
                uint64_t vui64;
                float vs;
                double vd;
                switch (value)
                {
                case __uint8_t:
                    __checkedinto(vui64, parse::uinteger64(b->value.view<uint8_t>()));
                    if (vui64 >= 256)
                    {
                        return __error_msg(errors::assembler::invalid_argument, "Value "_s + to_string(b->value) + " is too large for declaration `uint8`");
                    }
                    assembly.push((uint8_t)vui64);
                    break;
                case __uint32_t:
                    __checkedinto(vui64, parse::uinteger64(b->value.view<uint8_t>()));
                    if (vui64 >= std::numeric_limits<uint32_t>::max())
                    {
                        return __error_msg(errors::assembler::invalid_argument, "Value "_s + to_string(b->value) + " is too large for declaration `uint32`");
                    }
                    assembly.push((uint32_t)vui64);
                    break;
                case __uint64_t:
                    __checkedinto(vui64, parse::uinteger64(b->value.view<uint8_t>()));
                    assembly.push(vui64);
                    break;


                case __int8_t:
                    __checkedinto(vi64, parse::integer64(b->value.view<uint8_t>()));
                    if (vi64 >= std::numeric_limits<int8_t>::max())
                    {
                        return __error_msg(errors::assembler::invalid_argument, "Value "_s + to_string(b->value) + " is too large for declaration `int8`");
                    }
                    else if (vi64 <= std::numeric_limits<int8_t>::lowest())
                    {
                        return __error_msg(errors::assembler::invalid_argument, "Value "_s + to_string(b->value) + " is too small for declaration `int8`");
                    }

                    assembly.push((int8_t)vi64);
                    break;
                case __int32_t:
                    __checkedinto(vi64, parse::integer64(b->value.view<uint8_t>()));
                    if (vi64 >= std::numeric_limits<int32_t>::max())
                    {
                        return __error_msg(errors::assembler::invalid_argument, "Value "_s + to_string(b->value) + " is too large for declaration `int32`");
                    }
                    else if (vi64 <= std::numeric_limits<int32_t>::lowest())
                    {
                        return __error_msg(errors::assembler::invalid_argument, "Value "_s + to_string(b->value) + " is too small for declaration `int32`");
                    }

                    assembly.push((int32_t)vi64);
                    break;
                case __int64_t:
                    __checkedinto(vi64, parse::integer64(b->value.view<uint8_t>()));
                    assembly.push(vi64);
                    break;


                case __single_float_t:
                    __checkedinto(vs, parse::single(b->value.view<uint8_t>()));
                    assembly.push(vs);
                    break;
                case __double_float_t:
                    __checkedinto(vd, parse::single(b->value.view<uint8_t>()));
                    assembly.push(vd);
                    break;


                default: return __error_msg(errors::assembler::invalid_argument, "Data type is invalid");
                }

                return error();
            }
            error reserve(buffervec<uint8_t>& assembly, uint32_t count = 1)
            {
                switch (value)
                {
                case __uint8_t: case __int8_t: for (uint32_t i = 0; i < count; ++i) if (!assembly.push((uint8_t)0)) return __error(errors::out_of_memory); break;
                case __uint32_t: case __int32_t: case __single_float_t: for (uint32_t i = 0; i < count; ++i) if (!assembly.push((uint32_t)0)) return __error(errors::out_of_memory); break;
                case __uint64_t: case __int64_t: case __double_float_t: for (uint32_t i = 0; i < count; ++i) if (!assembly.push((uint64_t)0)) return __error(errors::out_of_memory); break;
                default: for (uint32_t i = 0; i < count; ++i) if (!assembly.push_empty(value)) return __error(errors::out_of_memory);
                }
                return error();
            }
            uint32_t size() const noexcept
            {
                switch (value)
                {
                case __uint8_t: case __int8_t: return 1;
                case __uint32_t: case __int32_t: case __single_float_t: return 4;
                case __uint64_t: case __int64_t: case __double_float_t: return 8;
                }
                return (uint32_t)value;
            }
            argtype_t argtype() const noexcept
            {
                switch (value)
                {
                case __uint8_t: case __int8_t: case __data_t: return argtype_t::mem8;
                case __uint32_t: case __int32_t: case __single_float_t: return argtype_t::mem32;
                case __uint64_t: case __int64_t: case __double_float_t: return argtype_t::mem64;
                }
                return argtype_t::unused;
            }
        };
        struct data_info
        {
            data_type type;
            uint32_t count = 1;
            int64_t rip;
        };

        struct flags
        {
            enum vt
            {
                __none = 0,
                __export = 0b00000001,
                __proc = 0b00000010,
                __data = 0b00000100,
            } value;
            __enum(flags);
            __enumflags(flags);
        };

        struct delay_resolve
        {
            string label;

        };

        _inline bool clear_whitespace_inline(nextany_tokenizer::const_iterator_t& b, const nextany_tokenizer::const_iterator_t& e)
        {
            while (b->value.size == 0)
            {
                if (b->delimiter == '\n' || b->delimiter == '\r')
                {
                    ++b;
                    return false;
                }
                if (++b == e) return false;
            }
            return true;
        }
        _inline bool clear_whitespace(nextany_tokenizer::const_iterator_t& b, const nextany_tokenizer::const_iterator_t& e)
        {
            if (b == e) return false;
            while (b->value.size == 0 && (b->delimiter == ' ' || b->delimiter == '\n' || b->delimiter == '\r' || b->delimiter == '\0'))
            {
                if (++b == e) return false;
            }
            return true;
        }
        _inline bool clear_line(nextany_tokenizer::const_iterator_t& b, const nextany_tokenizer::const_iterator_t& e)
        {
            while (b->value.size != 0 || b->delimiter != '\n')
            {
                if (++b == e) return false;
            }
            return (++b != e);
        }

        _inline optional<argument_t> parse_argument(instruction_t* pinstruction, argtype_t* parg, nextany_tokenizer::const_iterator_t& iter, const nextany_tokenizer::const_iterator_t& end, int64_t pos, const umap<string, int64_t>& labels, umap<string, data_info>& data)
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
                        *parg = argtype_t::imm32;
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
                    *parg = argtype_t::imm32;
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
                if (auto mem = data.find(string(iter->value.ptr + 1, iter->value.ptr + iter->value.size - 1)); mem != data.end())
                {
                    *parg = mem->second.type.argtype();
                    ret.mode = modrm_t::mode_t::rip_relative;
                    ret.reg = register_t::RBP;
                    *((int64_t*)&ret.disp) = mem->second.rip - pos;
                }
                else if (auto reg = register_t(buffer<char>::from_ptr(iter->value.ptr + 1, iter->value.size - 2)); reg != register_t::invalid)
                {
                    if (reg == register_t::RBP || reg == register_t::EBP)
                    {
                        // RBP indirect addressing requires base+offset syntax, where offset = 0
                        ret.disp = 0;
                        ret.base = reg;
                        ret.mode = modrm_t::mode_t::indirect_disp8;
                        ret.scale = 0;
                    }
                    else
                    {
                        ret.reg = reg;
                        ret.mode = modrm_t::mode_t::register_indirect;
                    }

                    *parg = argtype_t::mem;
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
                            // [base+disp32]
                            register_t reg = register_t(buffer<char>::from_ptr(matches[4].first, matches[4].second - matches[4].first));

                            __checkedinto(ret.disp, parse::uinteger32(buffer<char>::from_ptr(matches[5].first, matches[5].second - matches[5].first)));

                            if (ret.disp <= std::numeric_limits<uint8_t>::max())
                            {
                                ret.mode = modrm_t::mode_t::indirect_disp8;
                            }
                            else
                            {
                                ret.mode = modrm_t::mode_t::indirect_disp32;
                            }

                            ret.index = register_t::RSP;
                            ret.base = reg;
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
                        else return __error_msg(errors::assembler::invalid_indirect_address_scheme, "Addressing: "_s + to_string(iter->value) + " is invalid, no format match found");
                        *parg = argtype_t::mem;
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
                    string name = to_string(iter->value);
                    if (auto label = labels.find(name); label != labels.end())
                    {
                        ret.islabel = true;

                        int64_t voff = label->second - pos;
                        *((int64_t*)&ret.imm) = voff;
                        if (std::numeric_limits<int8_t>::lowest() <= voff && voff <= std::numeric_limits<int8_t>::max())
                        {
                            *parg = argtype_t::imm8;
                        }
                        else if (std::numeric_limits<int32_t>::lowest() <= voff && voff <= std::numeric_limits<int32_t>::max())
                        {
                            *parg = argtype_t::imm32;
                        }
                        else
                        {
                            __assert(false);
                            *parg = argtype_t::imm64;
                        }
                        return ret;
                    }
                    else if (auto ptr = linkmap().find(name); ptr != linkmap().end())
                    {
                        *parg = argtype_t::imm64;
                        ret.imm = (uint64_t)ptr->second;
                        return ret;
                    }
                    else
                    {
                        ret.islabel = true;
                        *parg = argtype_t::imm32;
                        ret.imm = 0;
                        ret.label = name;
                        return ret;
                    }
                    return __error_msg(errors::assembler::invalid_argument, "Argument "_s + to_string(iter->value) + " not recognized");
                }

                ret.mode = modrm_t::mode_t::register_direct;
                ret.reg = reg;

                if (reg.size() == 256)
                {
                    *parg = argtype_t::reg256;
                }
                else if (reg.size() == 128)
                {
                    *parg = argtype_t::reg128;
                }
                else if (reg.size() == 64)
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
        _inline optional<instruction_t> parse_instruction(nextany_tokenizer::const_iterator_t& iter, const nextany_tokenizer::const_iterator_t& end, int64_t pos, umap<string, int64_t>& labels, umap<string, data_info>& data) noexcept
        {
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
            if ((iter->delimiter != '\r' && iter->delimiter != '\n') && ++iter != end && clear_whitespace_inline(iter, end))
            {

                do
                {
                    if (argcount == 4)
                    {
                        return __error_msg(errors::assembler::invalid_argument, "Argument count cannot exceed 4");
                    }

                    argnames[argcount] = iter->value.view();
                    __checkedinto(ret.args[argcount], parse_argument(&ret, &ret.signature.types[argcount], iter, end, pos, labels, data));
                    ++argcount;

                    if (iter->delimiter == ',')
                    {
                        if (++iter == end || !clear_whitespace_inline(iter, end)) return __error_msg(errors::assembler::unexpected_end_of_statment, "Label "_s + to_string(iter->value) + ": Ended in a ','");
                    }
                    else break;

                } while (true);
            }
            if (iter != end) ++iter;

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
                if (argcount == 0) 
                    return __error_msg(errors::assembler::instruction_overload_not_found, "Could not find overload for label "_s + (test.label));

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
                                    err += " " + to_string(argnames[j]) + "/" + to_string(ret.signature.types[j]);
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
                            && ret.signature.types[i] != argtype_t::imm8
                            && ret.signature.types[i] != argtype_t::mem)
                        {
                            valid_overload = false;
                            break;
                        }
                    }
                } while (!valid_overload);

            } while (true);

            return ret;
        }

        _executeinline optional<asmexe> assemble(const buffer<char>& code) noexcept
        {
            buffervec<uint8_t> ret;
            umap<string, int64_t> labels;
            umap<string, data_info> data;
            umap<string, vector<int64_t>> delay_labels;

            json::token asmmeta;

            data_type ctype = data_type::__uint8_t;
            string declname;

            flags cflags = flags::__none;

            nextany_tokenizer tokenizer;
            single_tokenizer brackettok;
            tokenizer.add(" \n\r,{}\"\\=");
            tokenizer.set(code);
            auto b = tokenizer.begin();
            auto e = tokenizer.end();
            while (b != e && clear_whitespace(b, e))
            {
                if (b == e) break;

                if (b->value.size > 0 && b->value[0] == '#')
                {
                    if (!clear_line(b, e)) break;
                    else continue;
                }

                if (b->value == "__export")
                {
                    cflags |= flags::__export;
                    ++b;
                }
                else if (b->value == "__proc")
                {
                    cflags |= flags::__proc;
                    ++b;
                }
                else if (ctype = data_type(b->value); ctype != data_type::__none)
                {
                    if (ctype == data_type::__data_t) return __error_msg(errors::assembler::data_declaration_incomplete, "__data declaractions must be `Array` types and must include an element count which defines the size of the block");
                    if (cflags.has(flags::__proc))
                    {
                        return __error_msg(errors::assembler::invalid_instruction, "__proc specifier MUST precede a label and not data");
                    }

                    ++b;
                    if (!clear_whitespace(b, e)) return __error_msg(errors::assembler::data_declaration_incomplete, "");
                    const string name = to_string(b->value);

                    data[name] = {
                        .type = ctype,
                        .rip = ret.size()
                    };

                    if (cflags.has(flags::__export))
                    {
                        asmmeta[s("export-data")][name] = json::token{
                            { "rip", ret.size() }
                        };
                    }
                    cflags.clear(flags::__export);

                    if (b->delimiter != '=') ++b;
                    if (clear_whitespace(b, e))
                    {
                        if (b->delimiter == '=')
                        {
                            ++b;
                            if (!clear_whitespace(b, e)) return __error_msg(errors::assembler::data_declaration_incomplete, "Data name `" + name + "` has assignment operator, missing value");
                            __checked(ctype.parse(ret, b, e));
                            ++b;
                        }
                        else
                        {
                            __checked(ctype.reserve(ret));
                        }
                    }
                }
                else if (brackettok.set(b->value, '[') && data_type(brackettok.value()) != data_type::__none)
                {
                    data_type type(brackettok.value());
                    ++brackettok;

                    brackettok.set(brackettok.value(), ']');
                    if (type == data_type::__data_t)
                    {
                        uint32_t count;
                        __checkedinto_msg(count, parse::uinteger32trim(brackettok.value()), "__data type declarations must include element count");

                        ++b;
                        if (!clear_whitespace(b, e)) return __error_msg(errors::assembler::data_declaration_incomplete, "Data declaration must include a name");
                        string name = to_string(b->value);

                        data[name] = {
                            .type = type,
                            .count = count,
                            .rip = ret.size()
                        };

                        if (!ret.push_empty(count)) return __error(errors::out_of_memory);
                        ++b;
                    }
                    else if (brackettok.value().size == 0)
                    {
                        ++b;
                        if (!clear_whitespace(b, e)) return __error_msg(errors::assembler::data_declaration_incomplete, "Data declaration must include a name");
                        const string name = to_string(b->value);

                        if (cflags.has(flags::__export))
                        {
                            asmmeta[s("export-data")][name] = json::token{
                                { "rip", ret.size() }
                            };
                        }
                        cflags.clear(flags::__export);

                        if (b->delimiter != '=') ++b;
                        if (!clear_whitespace(b, e) || b->delimiter != '=') return __error_msg(errors::assembler::data_declaration_incomplete, "Array declarations without a count specifier must include an initializer");

                        ++b;
                        if (!clear_whitespace(b, e)) return __error_msg(errors::assembler::data_declaration_incomplete, "Data name `" + name + "` has assignment operator, missing value");

                        if (b->delimiter == '"')
                        {
                            int64_t rip = ret.size();
                            uint32_t count = 0;
                            bool escaped = false;
                            do
                            {
                                if (++b == e) return __error_msg(errors::assembler::data_declaration_incomplete, "Data name `" + name + "`: Unterminated string literal");

                                if (escaped)
                                {
                                    if (b->value.size == 0)
                                    {
                                        if (b->delimiter == '"')
                                        {
                                            ++count;
                                            ret.push('"');
                                        }
                                        else if (b->delimiter == '\\')
                                        {
                                            ++count;
                                            ret.push('\\');
                                        }
                                        else
                                        {
                                            return __error_msg(errors::assembler::data_declaration_incomplete, "Data name `" + name + "`: Invalid escape sequence \\" + b->delimiter);
                                        }
                                        escaped = false;
                                    }
                                    else
                                    {
                                        switch (b->value[0])
                                        {
                                        case 't': ++count; ret.push('\t'); break;
                                        case 'n': ++count; ret.push('\n'); break;
                                        case '0': ++count; ret.push('\0'); break;
                                        default: return __error_msg(errors::assembler::data_declaration_incomplete, "Data name `" + name + "`: Invalid escape sequence \\" + b->value[0]);
                                        }

                                        if (b->value.size > 1)
                                        {
                                            count += (uint32_t)(b->value.size - 1);
                                            ret.push(b->value.offset_view(1));
                                        }

                                        if (b->delimiter == '\\')
                                        {
                                            escaped = true;
                                        }
                                        else if (b->delimiter == '"')
                                        {
                                            break;
                                        }
                                        else
                                        {
                                            escaped = false;
                                            ++count;
                                            ret.push(b->delimiter);
                                        }
                                    }
                                }
                                else
                                {
                                    if (b->value.size > 0)
                                    {
                                        count += (uint32_t)b->value.size;
                                        ret.push(b->value);
                                    }

                                    if (b->delimiter == '\\')
                                    {
                                        escaped = true;
                                    }
                                    else if (b->delimiter == '"')
                                    {
                                        break;
                                    }
                                    else
                                    {
                                        ++count;
                                        ret.push(b->delimiter);
                                    }
                                }
                            } while (true);

                            data[name] = {
                                .type = type,
                                .count = count,
                                .rip = rip
                            };
                        }
                        else
                        {
                            if (b->delimiter != '{') return __error_msg(errors::assembler::data_declaration_incomplete, "Array types' (`" + name + "`) assignment must be enclosed in curly braces: `{` data[,..] `}`");
                            __assert(false);
                        }
                        ++b;
                    }
                    else
                    {
                        uint32_t count;
                        __checkedinto_msg(count, parse::uinteger32trim(brackettok.value()), "Array declaration must include element count");

                        ++b;
                        if (!clear_whitespace(b, e)) return __error_msg(errors::assembler::data_declaration_incomplete, "Data declaration must include a name");
                        string name = to_string(b->value);

                        data[name] = {
                            .type = type,
                            .count = count,
                            .rip = ret.size()
                        };

                        if (cflags.has(flags::__export))
                        {
                            asmmeta[s("export-data")][name] = json::token{
                                { "rip", ret.size() }
                            };
                        }
                        cflags.clear(flags::__export);

                        if (b->delimiter != '=') ++b;
                        if (clear_whitespace(b, e))
                        {
                            if (b->delimiter == '=')
                            {
                                ++b;
                                if (!clear_whitespace(b, e)) return __error_msg(errors::assembler::data_declaration_incomplete, "Data name `" + name + "` has assignment operator, missing value");
                                if (b->delimiter != '{') return __error_msg(errors::assembler::data_declaration_incomplete, "Array types' (`" + name + "`) assignment must be enclosed in curly braces: `{` data[,..] `}`");

                                for (uint32_t i = 0; i < count; ++i)
                                {
                                    if (!clear_whitespace(++b, e)) return __error_msg(errors::assembler::data_declaration_incomplete, "Data name `" + name + "` initialization does not contain enough elements. Count=" + i);
                                    __checked(type.parse(ret, b, e));
                                }
                                if (b->delimiter != '}' && (!clear_whitespace(++b, e) && b->delimiter == '}')) return __error_msg(errors::assembler::data_declaration_incomplete, "Array types' (`" + name + "`) assignment must be enclosed in curly braces: `{` data[,..] `}`");

                                ++b;
                            }
                            else
                            {
                                __checked(type.reserve(ret, count));
                            }
                        }
                    }
                }
                else
                {
                    if (b->delimiter == '\n' || b->delimiter == '\r')
                    {
                        if (b->value.size == 0)
                        {
                            return __error_msg(errors::assembler::instruction_incomplete, "Empty statement");
                        }
                        if (b->value.back() == ':')
                        {
                            string label = to_string(b->value);
                            label.pop_back();

                            if (cflags.has(flags::__proc | flags::__export))
                            {
                                asmmeta[s("export-procs")][label] = json::token{
                                    { "rip", ret.size() }
                                };
                            }
                            cflags.clear(flags::__proc | flags::__export);

                            labels[label] = ret.size();

                            if (auto f = delay_labels.find(label); f != delay_labels.end())
                            {
                                for (auto p : f->second)
                                {
                                    *((int32_t*)(ret.ptr() + p)) = (int32_t)(ret.size() - p - 4);
                                }
                                delay_labels.erase(f);
                            }

                            ++b;
                            continue;
                        }
                    }

                    if (cflags.has(flags::__proc | flags::__export))
                    {
                        return __error_msg(errors::assembler::invalid_instruction, "__proc or __export specifiers MUST precede a label and not an instruction");
                    }

                    if (b == e || !clear_whitespace(b, e)) break;

                    instruction_t instruction;
                    __checkedinto(instruction, parse_instruction(b, e, ret.size(), labels, data));
                    __checked(instruction.emit(ret, delay_labels));
                }
            }

            if (delay_labels.size() > 0)
            {
                string invalid_labels;
                for (const auto& l : delay_labels)
                {
                    invalid_labels += l.first + ", ";
                }
                invalid_labels.pop_back();
                invalid_labels.pop_back();

                return __error_msg(errors::assembler::invalid_argument, "Unresolved labels or invalid arguments: "_s + invalid_labels);
            }

            asmexe _ret;

            _ret.asmmeta = std::move(asmmeta);
            _ret.pexecutable = VirtualAlloc(nullptr, ((ret.size() + 4095) >> 12) << 12, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            if (_ret.pexecutable == nullptr) return __error(errors::out_of_memory);
            memcpy(_ret.pexecutable, ret.ptr(), ret.size());

            return _ret;
        }
        _executeinline optional<asmexe> assemble(const buffer<uint8_t>& code) noexcept
        {
            return assemble(code.view<char>());
        }
        _inline optional<asmexe> assemble(const string& code) noexcept
        {
            return assemble(buffer<char>::from_ptr(code.c_str(), code.length()));
        }




        optional<uint32_t> cpuq_t::execute()
        {

            using cd = int(*)(uint32_t* rax, uint32_t* rbx, uint32_t* rcx, uint32_t* rdx, uint32_t fn, uint32_t subfn);
            thread_local static asmexe mem;
            thread_local static cd cpuid = nullptr;
            if (cpuid == nullptr)
            {
                __checkedinto(mem, assemble(R"(
__export
__proc 
    f__cpuid:
        push rsi
        push rdi
        push rcx
        push ebx
        push rbp

        push r9
        push r8
        push rdx
        push rcx

        mov eax, [rsp+112]
        mov ecx, [rsp+120]
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
)"));


                cpuid = (cd)mem[s("f__cpuid")];
            }



            uint32_t result[4];
            cpuid(result, result + 1, result + 2, result + 3, fn, subfn);

            return (result[(int32_t)regpos] >> bit_start) & mask(bit_end - bit_start);
        }
    }

}
