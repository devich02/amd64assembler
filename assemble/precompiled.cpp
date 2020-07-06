#include "precompiled.h"

namespace cgengine
{
    namespace statics
    {
        namespace ___internal
        {
            extern "C"
            __declspec(dllexport) _noinline  std::unordered_map<std::string, __pointer>& __cdecl ___statics___store() noexcept
            {
                static std::unordered_map<std::string, __pointer>* pstore = new std::unordered_map<std::string, __pointer>();
                return *pstore;
            }

            extern "C"
            __declspec(dllexport) _noinline  std::recursive_mutex& __cdecl ___statics___storelock() noexcept
            {
                static std::recursive_mutex* plock = new std::recursive_mutex();
                return *plock;
            }
        }
    }
}