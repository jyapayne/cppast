// Copyright (C) 2017 Jonathan Müller <jonathanmueller.dev@gmail.com>
// This file is subject to the license terms in the LICENSE file
// found in the top-level directory of this distribution.

#include <cppast/cpp_entity_type.hpp>

using namespace cppast;

bool cppast::is_scope(cpp_entity_type type) noexcept
{
    switch (type)
    {
    case cpp_entity_type::namespace_t:
        return true;

    case cpp_entity_type::file_t:
    case cpp_entity_type::namespace_alias_t:
    case cpp_entity_type::using_directive_t:
        break;
    }

    return false;
}