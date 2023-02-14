# Copyright (C) 2017-2022 Jonathan Müller and cppast contributors
# SPDX-License-Identifier: MIT
# found in the top-level directory of this distribution.

set (CMAKE_CXX_STANDARD 20)
add_executable(cppast_tool main.cpp)
target_link_libraries(cppast_tool PUBLIC cppast cxxopts)
set_target_properties(cppast_tool PROPERTIES CXX_STANDARD 20 OUTPUT_NAME cppast)

install(TARGETS cppast_tool)

add_executable(cppcgen cppcgen.cpp)
target_link_libraries(cppcgen PUBLIC cppast cxxopts)
set_target_properties(cppcgen PROPERTIES CXX_STANDARD 20 OUTPUT_NAME cppcgen)

install(TARGETS cppcgen)
