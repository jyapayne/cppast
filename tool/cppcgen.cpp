// Copyright (C) 2017-2022 Jonathan Müller and cppast contributors
// SPDX-License-Identifier: MIT

#include <fstream>
#include <string>
#include <list>
#include <regex>
#include <cppast/cpp_member_function.hpp>
#include <iostream>
#include <unordered_set>

#include <cxxopts.hpp>

#include <cppast/code_generator.hpp>         // for generate_code()
#include <cppast/cpp_type.hpp>         // for generate_code()
#include <cppast/cpp_type_alias.hpp>         // for generate_code()
#include <cppast/cpp_entity_kind.hpp>        // for the cpp_entity_kind definition
#include <cppast/cpp_forward_declarable.hpp> // for is_definition()
#include <cppast/cpp_namespace.hpp>          // for cpp_namespace
#include <cppast/libclang_parser.hpp> // for libclang_parser, libclang_compile_config, cpp_entity,...
#include <cppast/visitor.hpp>         // for visit()

std::string CLASS_SUFFIX = "Ext";
std::string FUNC_SUFFIX = "Func";
std::string FUNC_VAR_PREFIX = "m_";
std::string FUNC_PARAM_PREFIX = "a_";
std::string PREFIX_SPACING = "  ";

std::vector<std::string> resplit(const std::string &s, const std::regex &sep_regex = std::regex{"\\s+"}) {
  std::sregex_token_iterator iter(s.begin(), s.end(), sep_regex, -1);
  std::sregex_token_iterator end;
  return {iter, end};
}


namespace std
{

template<class BidirIt, class Traits, class CharT, class UnaryFunction>
std::basic_string<CharT> regex_replace_lambda(BidirIt first, BidirIt last,
    const std::basic_regex<CharT,Traits>& re, UnaryFunction f)
{
    std::basic_string<CharT> s;

    typename std::match_results<BidirIt>::difference_type
        positionOfLastMatch = 0;
    auto endOfLastMatch = first;

    auto callback = [&](const std::match_results<BidirIt>& match)
    {
        auto positionOfThisMatch = match.position(0);
        auto diff = positionOfThisMatch - positionOfLastMatch;

        auto startOfThisMatch = endOfLastMatch;
        std::advance(startOfThisMatch, diff);

        s.append(endOfLastMatch, startOfThisMatch);
        s.append(f(match));

        auto lengthOfMatch = match.length(0);

        positionOfLastMatch = positionOfThisMatch + lengthOfMatch;

        endOfLastMatch = startOfThisMatch;
        std::advance(endOfLastMatch, lengthOfMatch);
    };

    std::regex_iterator<BidirIt> begin(first, last, re), end;
    std::for_each(begin, end, callback);

    s.append(endOfLastMatch, last);

    return s;
}

template<class Traits, class CharT, class UnaryFunction>
std::string regex_replace_lambda(const std::string& s,
    const std::basic_regex<CharT,Traits>& re, UnaryFunction f)
{
    return regex_replace_lambda(s.cbegin(), s.cend(), re, f);
}

} // namespace std

bool is_excluded_synopsis(const cppast::cpp_entity& e, cppast::cpp_access_specifier_kind access)
{
    // exclude privates and those marked for exclusion
    return access == cppast::cpp_private || cppast::has_attribute(e, "documentation::exclude");
}

// print help options
void print_help(const cxxopts::Options& options)
{
    std::cout << options.help({"", "compilation"}) << '\n';
}

const std::map<std::string, std::string> operator_map{
    {"+", "_plus"},
    {"-", "_minus"},
    {"*", "_mul"},
    {"/", "_div"},
    {"%", "_mod"},
    {"^", "_xor"},
    {"&", "_and"},
    {"|", "_or"},
    {"~", "_complement"},
    {"!", "_not"},
    {"=", "_eq"},
    {"<", "_lt"},
    {">", "_gt"},
    {"+=", "_plus_eq"},
    {"-=", "_minus_eq"},
    {"*=", "_mul_eq"},
    {"/=", "_div_eq"},
    {"%=", "_mod_eq"},
    {"^=", "_xor_eq"},
    {"&=", "_and_eq"},
    {"|=", "_or_eq"},
    {"<<", "_shl"},
    {">>", "_shr"},
    {">>=", "_shr_eq"},
    {"<<=", "_shl_eq"},
    {"==", "_dbl_eq"},
    {"!=", "_neq"},
    {"<=", "_lt_eq"},
    {">=", "_gt_eq"},
    {"<=>", "_three_way_comp"},
    {"&&", "_dbl_and"},
    {"||", "_dbl_or"},
    {"++", "_increment"},
    {"--", "_decrement"},
    {",", "_comma"},
    {"->*", "_ptr_accessor_star"},
    {"->", "_ptr_accessor"},
    {"()", "_call"},
    {"[]", "_index"},
    {"co_await", "_co_await"},
    {"new", "_new"},
    {"new []", "_new_index"},
    {"delete", "_delete"},
    {"delete []", "_delete_index"},
};

std::string sanitize_method_name(const std::string& str) {

    std::string result;
    auto reg = R"(operator\s*(\+|-|\*|/|%|\^|&|\||~|\!|\=|<|>|\+\=|-=|\*\=|/\=|%\=|\^\=|&\=|\|=|<<|>>|>>\=|<<\=|\=\=|\!\=|<\=|>\=|<\=>|&&|\|\||\+\+|--|,|->\*|->|\(\s*\)|\[\s*\]|new|new\s*\[\]|delete|delete\s*\[\]|\"\"\s*_\w+|co_await|\w+)\s*$)";
    result = std::regex_replace_lambda(
        str,
        std::regex(reg),
        [](const std::smatch& m){
            std::string match = m.str(1);
            //std::cerr << "MATCH: " << match << std::endl;
            if (operator_map.find(match) == operator_map.end()) {
                // doesn't exist
                if (match[0] == '"') {
                    std::string suffix = resplit(match).back();
                    return "_operator_suffix_" + suffix;
                }
                return "_operator_type_" + match;
            }
            return "_operator" + operator_map.at(match);
        }
    );

    return result;
}

// print error message
void print_error(const std::string& msg)
{
    std::cerr << msg << '\n';
}

std::string generate_synopsis(const cppast::cpp_entity& e)
{
    // the generator for the synopsis
    class synopsis_generator final : public cppast::code_generator
    {
    public:
        // get the resulting string
        std::string result()
        {
            return std::move(str_);
        }

    private:
        // whether or not the entity is the main entity that is being documented
        bool is_main_entity(const cppast::cpp_entity& e)
        {
            if (cppast::is_templated(e) || cppast::is_friended(e))
                // need to ask the real entity
                return is_main_entity(e.parent().value());
            else
                return &e == &this->main_entity();
        }

        // get some nicer formatting
        cppast::formatting do_get_formatting() const override
        {
            return cppast::formatting_flags::brace_nl | cppast::formatting_flags::comma_ws
                   | cppast::formatting_flags::operator_ws;
        }

        // calculate generation options
        generation_options do_get_options(const cppast::cpp_entity&         e,
                                          cppast::cpp_access_specifier_kind access) override
        {
            if (!is_main_entity(e))
                // only generation declaration for the non-documented entity
                return cppast::code_generator::declaration;
            else
                // default options
                return {};
        }

        // update indendation level
        void do_indent() override
        {
            ++indent_;
        }
        void do_unindent() override
        {
            if (indent_)
                --indent_;
        }

        // write specified tokens
        // need to change indentation for each newline
        void do_write_token_seq(cppast::string_view tokens) override
        {
            if (was_newline_)
            {
                str_ += std::string(indent_ * 2u, ' ');
                was_newline_ = false;
            }

            str_ += tokens.c_str();
        }

        // write + remember newline
        void do_write_newline() override
        {
            str_ += "\n";
            was_newline_ = true;
        }

        std::string str_;
        unsigned    indent_      = 0;
        bool        was_newline_ = false;
    } generator;
    cppast::generate_code(generator, e);
    return generator.result();
}

// trim from end (in place)
static inline void rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), s.end());
}

std::string serialize_method_params(const cppast::cpp_member_function& mf) {
    std::stringstream stream;
    for (auto& param : mf.parameters()) {
        stream << cppast::to_string(param.type());
    }
    auto result = stream.str();
    auto reg = R"((const\s*|&|\*|::|\[\]|\s*|\w+))";
    result = std::regex_replace_lambda(
        result,
        std::regex(reg),
        [](const std::smatch& m){
            std::string match = m.str(1);
            if (match == "&") {
                return std::string("R");
            }
            else if (match == "*") {
                return std::string("P");
            }
            else if (match == "[]") {
                return std::string("B");
            }
            else if (match == "::") {
                return std::string("N");
            }
            else if (match.starts_with("const")) {
                return std::string("C");
            }
            else if (match.find_first_not_of(' ') == match.npos) {
                return std::string("");
            }
            else {
                return match;
            }
        }
    );

    return result;

}

void output_member_function_typedef(std::stringstream& out, const cppast::cpp_entity& e, std::string& current_class) {
    if (e.kind() != cppast::cpp_entity_kind::member_function_t) return;

    auto& mf = static_cast<const cppast::cpp_member_function&>(e);
    out << "typedef ";
    out << cppast::to_string(mf.return_type()) << " ";
    out << "(*"<< current_class << sanitize_method_name(mf.name()) << serialize_method_params(mf) << FUNC_SUFFIX << ")(const " << current_class << "*" << " self";
    for (auto& param : mf.parameters()) {
        out << ", " << cppast::to_string(param.type()) << " " << param.name();
    }
    out << ");\n";
}

void output_member_function_param(std::stringstream& out, const cppast::cpp_entity& e, std::string& current_class) {
    if (e.kind() != cppast::cpp_entity_kind::member_function_t) return;

    auto& mf = static_cast<const cppast::cpp_member_function&>(e);
    std::string mpar_name = FUNC_PARAM_PREFIX + sanitize_method_name(e.name()) + serialize_method_params(mf);
    out << current_class << sanitize_method_name(e.name()) << serialize_method_params(mf) << FUNC_SUFFIX << " " << mpar_name;
    out << ", ";
}

void output_member_function_var_init(std::stringstream& out, std::string& prefix, const cppast::cpp_entity& e, std::string& current_class) {
    if (e.kind() != cppast::cpp_entity_kind::member_function_t) return;
    auto& mf = static_cast<const cppast::cpp_member_function&>(e);

    std::string mpar_name = FUNC_PARAM_PREFIX + sanitize_method_name(e.name()) + serialize_method_params(mf);
    std::string mvar_name = FUNC_VAR_PREFIX + current_class + sanitize_method_name(e.name()) + serialize_method_params(mf);
    out << prefix << prefix << mvar_name << " = " << mpar_name << ";\n";
}

void output_member_function(std::stringstream& out, const cppast::cpp_entity& e, std::string& prefix, std::string& base_class, std::string& current_class) {
    if (e.kind() != cppast::cpp_entity_kind::member_function_t) return;

    auto& mf = static_cast<const cppast::cpp_member_function&>(e);
    int j = 0;
    for (auto& param : mf.parameters()) {
        if (param.name().empty()) {
            param.set_name("param" + std::to_string(j));
        }
        j++;
    }

    std::string method_stub = generate_synopsis(e);
    bool method_is_zero = false;
    if (method_stub.find("= 0;") != std::string::npos) {
        method_is_zero = true;
    }
        /* method_is_zero = false; */
    method_stub = std::regex_replace(method_stub, std::regex(R"((\s*=\s*[a-zA-Z0-9_]+)?;)"), "", std::regex_constants::format_first_only);
    rtrim(method_stub);

    std::string mvar_name = FUNC_VAR_PREFIX + current_class + sanitize_method_name(mf.name()) + serialize_method_params(mf);
    std::string func_type = current_class + sanitize_method_name(mf.name()) + serialize_method_params(mf) + FUNC_SUFFIX;
    std::stringstream all_params_stream;

    int i = 0;
    for (auto& param : mf.parameters()) {
        all_params_stream << ( i ? ", " : "" );
        all_params_stream << param.name();
        i++;
    }
    std::string all_params = all_params_stream.str();

    // generate class var
    out << prefix << func_type << " " << mvar_name << " = NULL;\n";

    // generate method
    out << prefix << method_stub;
    if (method_stub.find("override") == std::string::npos) {
        out << " override";
    }
    out << "\n";
    out << prefix << "{\n";
    out << prefix << PREFIX_SPACING;

    std::string ret_type = cppast::to_string(mf.return_type());
    bool is_void = ret_type == "void";

    if (!method_is_zero) {
        // call super
        if (!is_void) {
            out << ret_type << " res = ";
        }
        out << base_class << "::" << mf.name() << "(" << all_params << ");\n";
        out << prefix << PREFIX_SPACING;
    }

    out << "if (*" << mvar_name << " != NULL){\n";
    out << prefix << PREFIX_SPACING << PREFIX_SPACING;
    out << "return ";
    if (i > 0) {
        out << mvar_name << "(this, " << all_params << ");\n";
    }
    else {
        out << mvar_name << "(this);\n";
    }
    out << prefix << PREFIX_SPACING;
    out << "}\n"; // endif
    if (!is_void && !method_is_zero) {
        out << prefix << PREFIX_SPACING;
        out << "else {\n";
        out << prefix << PREFIX_SPACING << PREFIX_SPACING;
        out << "return res;\n";
        out << prefix << PREFIX_SPACING;
        out << "}\n";

    }
    else if (!is_void && method_is_zero) {
        out << prefix << PREFIX_SPACING;
        out << "else {\n";
        out << prefix << PREFIX_SPACING << PREFIX_SPACING;
        out << "return NULL;\n";
        out << prefix << PREFIX_SPACING;
        out << "}\n";
    }

    out << prefix << "}\n";
}

void output_consdes_typedef(std::stringstream& out, const cppast::cpp_entity& e, std::string& current_class) {
    bool is_destructor = e.kind() == cppast::cpp_entity_kind::destructor_t;
    bool is_constructor = e.kind() == cppast::cpp_entity_kind::constructor_t;
    if (!is_destructor && !is_constructor) return;

    auto& mf = static_cast<const cppast::cpp_function_base&>(e);
    out << "typedef ";
    out << "void" << " ";

    if (is_constructor) {
        out << "(*new";
    }
    else {
        out << "(*destroy";
    }
    out << current_class << FUNC_SUFFIX << ")(";
    int i = 0;
    for (auto& param : mf.parameters()) {
        out << ( i ? ", " : "" );
        out << cppast::to_string(param.type()) << " " << param.name();
        i++;
    }
    out << ");\n";
}

void output_constructor(std::stringstream& out, std::string& var_init_str, std::string& all_params, std::string& prefix, std::string& base_class, std::string& current_class) {
    if (all_params.length() == 0) return;
    out << prefix << current_class << "(" << all_params << "): " << base_class << "() {\n";
    out << var_init_str;
    out << prefix << "}\n";
}

void output_consdes(std::stringstream& out, const cppast::cpp_entity& e, std::string& prefix, std::string& base_class, std::string& current_class) {
    bool is_destructor = e.kind() == cppast::cpp_entity_kind::destructor_t;
    bool is_constructor = e.kind() == cppast::cpp_entity_kind::constructor_t;
    if (!is_destructor && !is_constructor) return;

    auto& mf = static_cast<const cppast::cpp_function&>(e);
    int j = 0;
    for (auto& param : mf.parameters()) {
        if (param.name().empty()) {
            param.set_name("param" + std::to_string(j));
        }
        j++;
    }

    std::string method_stub = generate_synopsis(e);
    // get rid of the ' = 0;' or ' = default;' in the constructor
    method_stub = std::regex_replace(method_stub, std::regex(R"((\s*=\s*[a-zA-Z0-9_]+)?;)"), "", std::regex_constants::format_first_only);
    rtrim(method_stub);

    /* std::string mvar_name = FUNC_VAR_PREFIX + (is_constructor ? "new" : "destroy") + current_class; */
    std::string func_type = current_class + FUNC_SUFFIX;
    std::stringstream all_params_stream;

    int i = 0;
    for (auto& param : mf.parameters()) {
        all_params_stream << ( i ? ", " : "" ) << param.name();
        i++;
    }
    std::string all_params = all_params_stream.str();

    // generate method
    auto new_stub = std::regex_replace(method_stub, std::regex(base_class), current_class, std::regex_constants::format_first_only);
    out << prefix << new_stub;
    // call super
    if (is_constructor) {
        out << ": " << base_class << "(" << all_params << ")";
    }
    out << prefix << "{";
    out << prefix << "}\n";
}

bool efilter(const cppast::cpp_entity& e, cppast::cpp_access_specifier_kind access) {
    // only visit non-templated class definitions
    return (!cppast::is_templated(e) && !cppast::is_template(e.kind()) && e.kind() != cppast::cpp_entity_kind::class_template_t &&
            access != cppast::cpp_private &&
            (
             (e.kind() == cppast::cpp_entity_kind::class_t && cppast::is_definition(e)) ||
             (e.kind() == cppast::cpp_entity_kind::member_function_t && static_cast<const cppast::cpp_member_function_base&>(e).is_virtual()) ||
             (e.kind() == cppast::cpp_entity_kind::constructor_t) ||
             (e.kind() == cppast::cpp_entity_kind::destructor_t && static_cast<const cppast::cpp_destructor&>(e).is_virtual()) ||
             e.kind() == cppast::cpp_entity_kind::base_class_t ||
             e.kind() == cppast::cpp_entity_kind::macro_definition_t ||
             e.kind() == cppast::cpp_entity_kind::type_alias_t
            )
           );
}

bool method_filter(const cppast::cpp_entity& e, cppast::cpp_access_specifier_kind access) {
    // only visit non-templated class definitions
    return (!cppast::is_templated(e) && !cppast::is_template(e.kind()) && e.kind() != cppast::cpp_entity_kind::class_template_t &&
            access != cppast::cpp_private &&
            (
             (e.kind() == cppast::cpp_entity_kind::member_function_t && static_cast<const cppast::cpp_member_function_base&>(e).is_virtual())
            )
           );
}

std::string hash_member_function(const cppast::cpp_member_function& mf) {
    std::stringstream stream;
    stream << sanitize_method_name(mf.name()) << "<";
    int i = 0;
    for (auto& param : mf.parameters()) {
        stream << (i != 0 ? ", " : "") << cppast::to_string(param.type());
        i++;
    }
    stream << ">";
    return stream.str();
}

// prints the AST of a file
void print_ast(std::ostream& out, const cppast::cpp_file& file, const cppast::cpp_entity_index& idx)
{
    // print file name
    std::cerr << "AST for '" << file.name() << "':\n";
    std::string prefix; // the current prefix string
    std::string current_class; // the current class
    std::string base_class; // the current base class
                            //
    std::string fname = file.name();
    auto pos = fname.rfind("wx/");
    auto len_to_end = fname.length() - pos;
    std::string include_path = fname.substr(pos, len_to_end);
    std::string guard_name = "_" + std::regex_replace(include_path, std::regex("/|\\."), "_") + "_EXT_";
    std::transform(guard_name.begin(), guard_name.end(), guard_name.begin(), [](char c) { return std::toupper(c); });
    //std::cerr << guard_name;

    out << "#ifndef " << guard_name << "\n";
    out << "#define " << guard_name << "\n\n";
    out << "#include <wx/wx.h>\n#include <wx/vidmode.h>\n\n";
    
    /* out << "namespace wxname {\n#include_next <" << include_path << ">\n};\n\n"; */

    std::stringstream forward_decls;
    // TODO: Allow specifying all params by constructor
    std::stringstream init_params;
    std::stringstream var_init;
    std::stringstream class_stream;
    std::stringstream class_close_stream;
    bool in_class = false;
    bool has_class_ending = false;

    std::map<std::string, const cppast::cpp_member_function*> members;

    // - Forward declare the class
    // - typedef all of the virtual methods with class as first arg
    // - declare the class with a postfix (class wxAppC: public wxApp)
    // - output variable and virtual method override
    //   check function pointer for null, then call it
    //
    cppast::visit(file, efilter,
        [&](const cppast::cpp_entity& e, cppast::visitor_info info) {
            if (info.event == cppast::visitor_info::container_entity_enter) {
                if (e.kind() == cppast::cpp_entity_kind::class_t && !in_class) {

                    if (e.name().empty()) {
                        // it was a fake exit event
                        //std::cerr << "FAAAAAAAAAAAKE\n";
                        //std::cerr << current_class << "\n\n";

                        in_class = true;
                        has_class_ending = true;
                        return true;
                    }
                    else if (has_class_ending) { // EXIT CLASS

                        for (auto const& kv : members) {
                            auto& mf = kv.second;
                            std::cerr << "OUTPUTTING: " << current_class << " " << mf->name() << std::endl;

                            int j = 0;
                            for (auto& param : mf->parameters()) {
                                if (param.name().empty()) {
                                    param.set_name("param" + std::to_string(j));
                                }
                                j++;
                            }
                            output_member_function_param(init_params, *mf, current_class);
                            output_member_function_var_init(var_init, prefix, *mf, current_class);
                            output_member_function_typedef(forward_decls, *mf, current_class);
                            output_member_function(class_stream, *mf, prefix, base_class, current_class);
                        }

                        auto param_str = init_params.str();
                        auto var_init_str = var_init.str();
                        if (param_str.length() >= 2) {
                            // delete comma and space
                            param_str.pop_back();
                            param_str.pop_back();
                        }
                        output_constructor(class_stream, var_init_str, param_str, prefix, base_class, current_class);
                        init_params.str(std::string()); // clear
                        var_init.str(std::string()); // clear
                        class_stream << "};\n\n";
                        // we have visited all children of a container,
                        // remove prefix
                        prefix.pop_back();
                        prefix.pop_back();
                        has_class_ending = false;
                        members.clear();
                        //std::cerr << "EXIT CLASS\n";
                        //std::cerr << current_class << "\n\n";
                    }
                    base_class = e.name();
                    current_class = e.name() + CLASS_SUFFIX;
                    //std::cerr << "ENTER CLASS\n";
                    //std::cerr << current_class << "\n\n";
                    forward_decls << "class " << current_class << ";\n";

                    class_stream << "class " << current_class << ": public " << base_class;
                    class_stream << "\n{\n";
                    class_stream << "public:\n";
                    prefix += PREFIX_SPACING;
                    in_class = true;

                    // Record the methods of the classes and base classes
                    auto& mf = static_cast<const cppast::cpp_class&>(e);
                    std::vector<const cppast::cpp_entity*> stack;

                    std::cerr << "\nCLASS: " << mf.name() << std::endl;

                    for (auto& base : mf.bases()) {
                        auto entity = idx.lookup(*static_cast<const cppast::cpp_user_defined_type&>(base.type()).entity().id().data());
                        std::cerr << "BASENAME: " << base.name() << std::endl;
                        if (entity.has_value()) {
                            stack.push_back(&entity.value());
                        }
                    }
                    while (!stack.empty()) {
                        auto entity = stack.back(); stack.pop_back();
                        auto& entclass = static_cast<const cppast::cpp_class&>(*entity);
                        if (entclass.name().empty()) continue;
                        std::cerr << "BASECLASS: " << entclass.name() << std::endl;
                        cppast::visit(entclass, method_filter,
                            [&](const cppast::cpp_entity& e, cppast::visitor_info info) {
                                auto& mf = static_cast<const cppast::cpp_member_function&>(e);
                                auto mname = hash_member_function(mf);
                                std::cerr << "METHOD NAME: " << mf.name() << " (" << mname << ")" << std::endl;
                                std::cerr << "IN MEMBERS: " << !members.count(mname) << std::endl;
                                if (!members.count(mname)) {
                                    members[mname] = &mf;
                                }
                            }
                        );
                        for (auto& entbase : entclass.bases()) {
                            auto ent = idx.lookup(*static_cast<const cppast::cpp_user_defined_type&>(entbase.type()).entity().id().data());
                            if (ent.has_value()) {
                                stack.push_back(&ent.value());
                            }
                        }

                    }
                }
            }
            else if (info.event == cppast::visitor_info::container_entity_exit)
            {
                if (e.kind() == cppast::cpp_entity_kind::class_t && !has_class_ending) {
                    has_class_ending = true;
                    in_class = false;
                }
            }
            else
            {
                if (!in_class) {
                    return true;
                }
                if (e.kind() == cppast::cpp_entity_kind::constructor_t) {
                    auto& mf = static_cast<const cppast::cpp_function&>(e);
                    int j = 0;
                    for (auto& param : mf.parameters()) {
                        if (param.name().empty()) {
                            param.set_name("param" + std::to_string(j));
                        }
                        j++;
                    }
                    // output_consdes_typedef(forward_decls, e, current_class);
                    output_consdes(class_stream, e, prefix, base_class, current_class);
                }
                else if (e.kind() == cppast::cpp_entity_kind::destructor_t) {
                    auto& mf = static_cast<const cppast::cpp_function&>(e);
                    int j = 0;
                    for (auto& param : mf.parameters()) {
                        if (param.name().empty()) {
                            param.set_name("param" + std::to_string(j));
                        }
                        j++;
                    }
                    // output_consdes_typedef(forward_decls, e, current_class);
                    output_consdes(class_stream, e, prefix, base_class, current_class);
                }
                else if (e.kind() == cppast::cpp_entity_kind::member_function_t) {
                    auto& mf = static_cast<const cppast::cpp_member_function&>(e);
                    auto mname = hash_member_function(mf);
                    if (!members.count(mname)) {
                        members[mname] = &mf;
                    }

                }
                /* else if (e.kind() == cppast::cpp_entity_kind::type_alias_t) { */
                /*     auto& alias = static_cast<const cppast::cpp_type_alias&>(e); */
                /*     std::cerr << "DFSFSDF " << alias.name() << "\n\n"; */
                /* } */
                /* else if (e.kind() == cppast::cpp_entity_kind::macro_definition_t) { */
                /*     auto& mf = static_cast<const cppast::cpp_macro_definition&>(e); */
                /*     std::cerr << e.name() << "\n"; */
                /* } */
            }

            return true;
    });

    if (has_class_ending) {
        std::cerr << "HAS CLASS ENDING!!!!!!!!!!" << std::endl;
        for (auto const& kv : members) {
            auto& mf = kv.second;
            std::cerr << "OUTPUTTING: " << current_class << " " << mf->name() << std::endl;

            int j = 0;
            for (auto& param : mf->parameters()) {
                if (param.name().empty()) {
                    param.set_name("param" + std::to_string(j));
                }
                j++;
            }
            output_member_function_param(init_params, *mf, current_class);
            output_member_function_var_init(var_init, prefix, *mf, current_class);
            output_member_function_typedef(forward_decls, *mf, current_class);
            output_member_function(class_stream, *mf, prefix, base_class, current_class);
        }
        auto param_str = init_params.str();
        auto var_init_str = var_init.str();
        if (param_str.length() >= 2) {
            // delete comma and space
            param_str.pop_back();
            param_str.pop_back();
        }
        output_constructor(class_stream, var_init_str, param_str, prefix, base_class, current_class);
        init_params.str(std::string()); // clear
        var_init.str(std::string()); // clear
        class_stream << "};\n\n";
        // we have visited all children of a container,
        // remove prefix
        prefix.pop_back();
        prefix.pop_back();
        has_class_ending = false;
        members.clear();
    }
    out << forward_decls.str() << "\n";
    out << class_stream.str() << "\n\n";
    out << "#endif" << "\n";

}

// parse a file
std::unique_ptr<cppast::cpp_file> parse_file(const cppast::libclang_compile_config& config,
                                             const cppast::diagnostic_logger&       logger,
                                             const std::string& filename, bool fatal_error,
                                             cppast::cpp_entity_index& idx)
{
    // the parser is used to parse the entity
    // there can be multiple parser implementations
    cppast::libclang_parser parser(type_safe::ref(logger));
    // parse the file
    auto file = parser.parse(idx, filename, config);
    if (fatal_error && parser.error())
        return nullptr;
    return file;
}

bool hasEnding (std::string const &fullString, std::string const &ending) {
    if (fullString.length() >= ending.length()) {
        return (0 == fullString.compare (fullString.length() - ending.length(), ending.length(), ending));
    } else {
        return false;
    }
}

template <class FileParser>
std::size_t resolve_includes2(FileParser& parser, const cppast::cpp_file& file,
                             typename FileParser::config config)
{
    auto count = 0u;
    for (auto& entity : file)
    {
        if (entity.kind() == cppast::cpp_include_directive::kind())
        {
            auto& include = static_cast<const cppast::cpp_include_directive&>(entity);
            auto& path = include.full_path();
            if (path.ends_with("button.h")) {
                parser.parse(path, config);
                ++count;

            }
        }
    }
    return count;
}

void readFile(std::string filename, std::list<std::string>& lines)
{
    lines.clear();
    std::ifstream file(filename);
    std::string s;
    while (getline(file, s))
        lines.push_back(s);
}

int main(int argc, char* argv[])
try
{
    cxxopts::Options option_list("cppast",
                                 "cppast - The commandline interface to the cppast library.\n");
    // clang-format off
    option_list.add_options()
        ("h,help", "display this help and exit")
        ("version", "display version information and exit")
        ("v,verbose", "be verbose when parsing")
        ("fatal_errors", "abort program when a parser error occurs, instead of doing error correction")
        ("file", "the file that is being parsed (last positional argument)",
         cxxopts::value<std::string>());
    option_list.add_options("compilation")
        ("database_dir", "set the directory where a 'compile_commands.json' file is located containing build information",
        cxxopts::value<std::string>())
        ("database_file", "set the file name whose configuration will be used regardless of the current file name",
        cxxopts::value<std::string>())
        ("file_list", "set the file name to get a list of files to process from, separated by newlines",
        cxxopts::value<std::string>())
        ("std", "set the C++ standard (c++98, c++03, c++11, c++14, c++1z (experimental), c++17, c++2a, c++20)",
         cxxopts::value<std::string>()->default_value(cppast::to_string(cppast::cpp_standard::cpp_latest)))
        ("I,include_directory", "add directory to include search path",
         cxxopts::value<std::vector<std::string>>())
        ("D,macro_definition", "define a macro on the command line",
         cxxopts::value<std::vector<std::string>>())
        ("U,macro_undefinition", "undefine a macro on the command line",
         cxxopts::value<std::vector<std::string>>())
        ("f,feature", "enable a custom feature (-fXX flag)",
         cxxopts::value<std::vector<std::string>>())
        ("gnu_extensions", "enable GNU extensions (equivalent to -std=gnu++XX)")
        ("msvc_extensions", "enable MSVC extensions (equivalent to -fms-extensions)")
        ("msvc_compatibility", "enable MSVC compatibility (equivalent to -fms-compatibility)")
        ("fast_preprocessing", "enable fast preprocessing, be careful, this breaks if you e.g. redefine macros in the same file!")
        ("remove_comments_in_macro", "whether or not comments generated by macro are kept, enable if you run into errors");
    // clang-format on
    option_list.parse_positional("file");

    auto options = option_list.parse(argc, argv);
    if (options.count("help"))
        print_help(option_list);
    else if (options.count("version"))
    {
        std::cout << "cppast version " << CPPAST_VERSION_STRING << "\n";
        std::cout << "Copyright (C) Jonathan Müller 2017-2019 <jonathanmueller.dev@gmail.com>\n";
        std::cout << '\n';
        std::cout << "Using libclang version " << CPPAST_CLANG_VERSION_STRING << '\n';
    }
    else if (!options.count("file") || options["file"].as<std::string>().empty())
    {
        print_error("missing file argument");
        return 1;
    }
    else
    {
        // the compile config stores compilation flags
        cppast::libclang_compile_config config;
        if (options.count("database_dir"))
        {
            cppast::libclang_compilation_database database(
                options["database_dir"].as<std::string>());
            if (options.count("database_file"))
                config
                    = cppast::libclang_compile_config(database,
                                                      options["database_file"].as<std::string>());
            else
                config
                    = cppast::libclang_compile_config(database, options["file"].as<std::string>());
        }

        if (options.count("verbose"))
            config.write_preprocessed(true);

        if (options.count("fast_preprocessing"))
            config.fast_preprocessing(true);

        if (options.count("remove_comments_in_macro"))
            config.remove_comments_in_macro(true);

        if (options.count("include_directory"))
            for (auto& include : options["include_directory"].as<std::vector<std::string>>())
                config.add_include_dir(include);
        if (options.count("macro_definition"))
            for (auto& macro : options["macro_definition"].as<std::vector<std::string>>())
            {
                auto equal = macro.find('=');
                auto name  = macro.substr(0, equal);
                if (equal == std::string::npos)
                    config.define_macro(std::move(name), "");
                else
                {
                    auto def = macro.substr(equal + 1u);
                    config.define_macro(std::move(name), std::move(def));
                }
            }
        if (options.count("macro_undefinition"))
            for (auto& name : options["macro_undefinition"].as<std::vector<std::string>>())
                config.undefine_macro(name);
        if (options.count("feature"))
            for (auto& name : options["feature"].as<std::vector<std::string>>())
                config.enable_feature(name);

        // the compile_flags are generic flags
        cppast::compile_flags flags;
        if (options.count("gnu_extensions"))
            flags |= cppast::compile_flag::gnu_extensions;
        if (options.count("msvc_extensions"))
            flags |= cppast::compile_flag::ms_extensions;
        if (options.count("msvc_compatibility"))
            flags |= cppast::compile_flag::ms_compatibility;

        if (options["std"].as<std::string>() == "c++98")
            config.set_flags(cppast::cpp_standard::cpp_98, flags);
        else if (options["std"].as<std::string>() == "c++03")
            config.set_flags(cppast::cpp_standard::cpp_03, flags);
        else if (options["std"].as<std::string>() == "c++11")
            config.set_flags(cppast::cpp_standard::cpp_11, flags);
        else if (options["std"].as<std::string>() == "c++14")
            config.set_flags(cppast::cpp_standard::cpp_14, flags);
        else if (options["std"].as<std::string>() == "c++1z")
            config.set_flags(cppast::cpp_standard::cpp_1z, flags);
        else if (options["std"].as<std::string>() == "c++17")
            config.set_flags(cppast::cpp_standard::cpp_17, flags);
        else if (options["std"].as<std::string>() == "c++2a")
            config.set_flags(cppast::cpp_standard::cpp_2a, flags);
        else if (options["std"].as<std::string>() == "c++20")
            config.set_flags(cppast::cpp_standard::cpp_20, flags);
        else
        {
            print_error("invalid value '" + options["std"].as<std::string>() + "' for std flag");
            return 1;
        }

        // the logger is used to print diagnostics
        cppast::stderr_diagnostic_logger logger;
        if (options.count("verbose"))
            logger.set_verbose(true);
        // the entity index is used to resolve cross references in the AST
        cppast::cpp_entity_index idx;
        /* auto file = parse_file(config, logger, options["file"].as<std::string>(), */
        /*                        options.count("fatal_errors") == 1, idx); */

        cppast::simple_file_parser<cppast::libclang_parser> parser(type_safe::ref(idx));

        std::list<std::string> fileList;
        if (options.count("file_list")) {
            auto fname = options["file_list"].as<std::string>();
            readFile(fname, fileList);
        }
        else {
            fileList.push_back(options["file"].as<std::string>());
        }

        std::unordered_set<std::string> to_visit;
        to_visit.insert(options["file"].as<std::string>());
        /* for (auto f : files) { */
        /*     to_visit.insert(f); */
        /* } */
        cppast::parse_files(parser, fileList, config);
        for (auto& f : parser.files()) {
            std::cerr << "PARSING: " << f.name() << std::endl;
            //resolve_includes2(parser, f, config);
            /* if (f.name().ends_with("/button.h")) { */
            /*     print_ast(std::cout, f, idx); */
            /* } */
            if (!to_visit.count(f.name())) continue;

            print_ast(std::cout, f, idx);
        }

    }
}
catch (const cppast::libclang_error& ex)
{
    print_error(std::string("[fatal parsing error] ") + ex.what());
    return 2;
}
