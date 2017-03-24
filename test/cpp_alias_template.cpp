// Copyright (C) 2017 Jonathan Müller <jonathanmueller.dev@gmail.com>
// This file is subject to the license terms in the LICENSE file
// found in the top-level directory of this distribution.

#include <cppast/cpp_alias_template.hpp>

#include "test_parser.hpp"

using namespace cppast;

TEST_CASE("cpp_alias_template")
{
    // no need to check advanced types here nor template parameters
    auto code = R"(
template <typename T>
using a = int;

template <int I, typename T = void>
using b = T;

template <typename T>
using c = const T*;

template <typename T>
using d = a<void>;

template <int I>
using e = const b<I>;

template <int I>
using f = b<I < a<int>{(0,1)}, int>;

template <typename T, template <typename> class Templ>
using g = Templ<T>;

template <typename T>
using h = g<T, a>;
)";

    auto check_parameters =
        [](const cpp_alias_template& alias,
           std::initializer_list<std::pair<cpp_entity_kind, const char*>> params) {
            // no need to check more
            auto cur = params.begin();
            for (auto& param : alias.parameters())
            {
                REQUIRE(cur != params.end());
                REQUIRE(param.kind() == cur->first);
                REQUIRE(param.name() == cur->second);
                ++cur;
            }
            REQUIRE(cur == params.end());
        };

    cpp_entity_index idx;
    auto             file = parse(idx, "cpp_alias_template.cpp", code);
    auto count = test_visit<cpp_alias_template>(*file, [&](const cpp_alias_template& alias) {
        if (alias.name() == "a")
        {
            check_parameters(alias, {{cpp_entity_kind::template_type_parameter_t, "T"}});
            REQUIRE(equal_types(idx, alias.type_alias().underlying_type(),
                                *cpp_builtin_type::build("int")));
        }
        else if (alias.name() == "b")
        {
            check_parameters(alias, {{cpp_entity_kind::non_type_template_parameter_t, "I"},
                                     {cpp_entity_kind::template_type_parameter_t, "T"}});
            REQUIRE(equal_types(idx, alias.type_alias().underlying_type(),
                                *cpp_template_parameter_type::build(
                                    cpp_template_type_parameter_ref(cpp_entity_id(""), "T"))));
        }
        else if (alias.name() == "c")
        {
            check_parameters(alias, {{cpp_entity_kind::template_type_parameter_t, "T"}});
            auto param = cpp_template_parameter_type::build(
                cpp_template_type_parameter_ref(cpp_entity_id(""), "T"));
            REQUIRE(equal_types(idx, alias.type_alias().underlying_type(),
                                *cpp_pointer_type::build(
                                    cpp_cv_qualified_type::build(std::move(param), cpp_cv_const))));
        }
        else if (alias.name() == "d")
        {
            check_parameters(alias, {{cpp_entity_kind::template_type_parameter_t, "T"}});

            cpp_template_instantiation_type::builder builder(
                cpp_template_ref(cpp_entity_id(""), "a"));
            builder.add_argument(cpp_unexposed_type::build("void"));
            REQUIRE(equal_types(idx, alias.type_alias().underlying_type(), *builder.finish()));
        }
        else if (alias.name() == "e")
        {
            check_parameters(alias, {{cpp_entity_kind::non_type_template_parameter_t, "I"}});

            cpp_template_instantiation_type::builder builder(
                cpp_template_ref(cpp_entity_id(""), "b"));
            builder.add_argument(
                cpp_unexposed_expression::build(cpp_builtin_type::build("int"), "I"));
            REQUIRE(equal_types(idx, alias.type_alias().underlying_type(),
                                *cpp_cv_qualified_type::build(builder.finish(), cpp_cv_const)));
        }
        else if (alias.name() == "f")
        {
            check_parameters(alias, {{cpp_entity_kind::non_type_template_parameter_t, "I"}});

            cpp_template_instantiation_type::builder builder(
                cpp_template_ref(cpp_entity_id(""), "b"));
            builder.add_argument(cpp_unexposed_expression::build(cpp_builtin_type::build("int"),
                                                                 "I < a<int>{(0 , 1)}"));
            builder.add_argument(cpp_unexposed_type::build("int"));
            REQUIRE(equal_types(idx, alias.type_alias().underlying_type(), *builder.finish()));
        }
        else if (alias.name() == "g")
        {
            check_parameters(alias, {{cpp_entity_kind::template_type_parameter_t, "T"},
                                     {cpp_entity_kind::template_template_parameter_t, "Templ"}});

            cpp_template_instantiation_type::builder builder(
                cpp_template_ref(cpp_entity_id(""), "Templ"));
            builder.add_argument(cpp_unexposed_type::build("T"));
            REQUIRE(equal_types(idx, alias.type_alias().underlying_type(), *builder.finish()));
        }
        else if (alias.name() == "h")
        {
            check_parameters(alias, {{cpp_entity_kind::template_type_parameter_t, "T"}});

            cpp_template_instantiation_type::builder builder(
                cpp_template_ref(cpp_entity_id(""), "g"));
            builder.add_argument(cpp_unexposed_type::build("T"));
            builder.add_argument(cpp_template_ref(cpp_entity_id("magic-allow-empty"), "a"));
            REQUIRE(equal_types(idx, alias.type_alias().underlying_type(), *builder.finish()));
        }
        else
            REQUIRE(false);
    });
    REQUIRE(count == 8u);
}