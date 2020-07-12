#pragma once

#include "structures.h"
#include "cpuid.h"

#include <containers/svector>

namespace cgengine
{
    namespace assembler
    {
        _inline umap<string, void*>& linkmap()
        {
            static umap<string, void*>* plinkmap_core = statics::get<umap<string, void*>*>(_FUNC);
            return *plinkmap_core;
        }
        namespace ___internal
        {
            _inline void add_core_linkmap()
            {
                vector<std::pair<const char*, void*>> core
                {
                    { "printf", printf }
                };
                for (auto& link : core)
                {
                    linkmap().try_emplace(link.first, link.second);
                }
            };

            __static_initialize(__add_corelinkmap, add_core_linkmap);
        }
    }
}