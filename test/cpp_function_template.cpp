// Copyright (C) 2017 Jonathan Müller <jonathanmueller.dev@gmail.com>
// This file is subject to the license terms in the LICENSE file
// found in the top-level directory of this distribution.

#include <cppast/cpp_function_template.hpp>

#include <cppast/cpp_member_function.hpp>

#include "test_parser.hpp"

using namespace cppast;

TEST_CASE("cpp_function_template")
{
    // only check templated related stuff
    auto code = R"(
template <typename T>
T a(const T& t);

template <int I>
using type = int;

struct d
{
    template <int I, typename T>
    static type<I> b(T);

    template <typename T = const int>
    auto c() -> T;

    template <typename T>
    operator T() const;

    template <typename T>
    d(const T&);
};
)";

    cpp_entity_index idx;
    auto             file = parse(idx, "cpp_function_template.cpp", code);
    auto count = test_visit<cpp_function_template>(*file, [&](const cpp_function_template& tfunc) {
        if (tfunc.name() == "a")
        {
            check_template_parameters(tfunc, {{cpp_entity_kind::template_type_parameter_t, "T"}});

            REQUIRE(tfunc.function().kind() == cpp_entity_kind::function_t);
            auto& func = static_cast<const cpp_function&>(tfunc.function());

            auto parameter = cpp_template_type_parameter_ref(cpp_entity_id(""), "T");
            REQUIRE(equal_types(idx, func.return_type(),
                                *cpp_template_parameter_type::build(parameter)));

            auto count = 0u;
            for (auto& param : func)
            {
                ++count;
                REQUIRE(
                    equal_types(idx, param.type(),
                                *cpp_reference_type::
                                    build(cpp_cv_qualified_type::
                                              build(cpp_template_parameter_type::build(parameter),
                                                    cpp_cv_const),
                                          cpp_ref_lvalue)));
            }
            REQUIRE(count == 1u);
        }
        else if (tfunc.name() == "b")
        {
            check_parent(tfunc, "d", "d::b");
            check_template_parameters(tfunc, {{cpp_entity_kind::non_type_template_parameter_t, "I"},
                                              {cpp_entity_kind::template_type_parameter_t, "T"}});

            REQUIRE(tfunc.function().kind() == cpp_entity_kind::function_t);
            auto& func = static_cast<const cpp_function&>(tfunc.function());

            cpp_template_instantiation_type::builder builder(
                cpp_template_ref(cpp_entity_id(""), "type"));
            builder.add_argument(
                cpp_unexposed_expression::build(cpp_builtin_type::build("int"), "I"));
            REQUIRE(equal_types(idx, func.return_type(), *builder.finish()));

            auto type_parameter = cpp_template_type_parameter_ref(cpp_entity_id(""), "T");
            auto count          = 0u;
            for (auto& param : func)
            {
                ++count;
                REQUIRE(equal_types(idx, param.type(),
                                    *cpp_template_parameter_type::build(type_parameter)));
            }
            REQUIRE(count == 1u);
        }
        else if (tfunc.name() == "c")
        {
            check_template_parameters(tfunc, {{cpp_entity_kind::template_type_parameter_t, "T"}});

            REQUIRE(tfunc.function().kind() == cpp_entity_kind::member_function_t);
            auto& func = static_cast<const cpp_member_function&>(tfunc.function());
            REQUIRE(func.cv_qualifier() == cpp_cv_none);

            auto parameter = cpp_template_type_parameter_ref(cpp_entity_id(""), "T");
            REQUIRE(equal_types(idx, func.return_type(),
                                *cpp_template_parameter_type::build(parameter)));
        }
        else if (tfunc.name() == "operator T")
        {
            check_template_parameters(tfunc, {{cpp_entity_kind::template_type_parameter_t, "T"}});

            REQUIRE(tfunc.function().kind() == cpp_entity_kind::conversion_op_t);
            auto& func = static_cast<const cpp_conversion_op&>(tfunc.function());
            REQUIRE(func.cv_qualifier() == cpp_cv_const);

            auto parameter = cpp_template_type_parameter_ref(cpp_entity_id(""), "T");
            REQUIRE(equal_types(idx, func.return_type(),
                                *cpp_template_parameter_type::build(parameter)));
        }
        else if (tfunc.name() == "d")
        {
            check_template_parameters(tfunc, {{cpp_entity_kind::template_type_parameter_t, "T"}});

            REQUIRE(tfunc.function().kind() == cpp_entity_kind::constructor_t);
            auto& func = static_cast<const cpp_constructor&>(tfunc.function());

            auto parameter = cpp_template_type_parameter_ref(cpp_entity_id(""), "T");
            auto count     = 0u;
            for (auto& param : func)
            {
                ++count;
                REQUIRE(
                    equal_types(idx, param.type(),
                                *cpp_reference_type::
                                    build(cpp_cv_qualified_type::
                                              build(cpp_template_parameter_type::build(parameter),
                                                    cpp_cv_const),
                                          cpp_ref_lvalue)));
            }
            REQUIRE(count == 1u);
        }
        else
            REQUIRE(false);
    });
    REQUIRE(count == 5u);
}
