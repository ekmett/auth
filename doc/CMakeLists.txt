# SPDX-FileType: Source
# SPDX-FileCopyrightText: 2026 Edward Kmett <ekmett@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause OR Apache-2.0

find_package(Doxygen 1.18 REQUIRED)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(DOXYGEN_PROJECT_BRIEF "Authenticated computation with C++26 modules")
set(DOXYGEN_GENERATE_HTML YES)
set(DOXYGEN_GENERATE_XML YES)
set(DOXYGEN_GENERATE_LATEX NO)
set(DOXYGEN_EXTENSION_MAPPING "ccm=C++")
set(DOXYGEN_EXTRACT_ALL NO)
set(DOXYGEN_EXTRACT_PRIVATE NO)
set(DOXYGEN_HIDE_UNDOC_MEMBERS YES)
set(DOXYGEN_HIDE_UNDOC_CLASSES YES)
set(DOXYGEN_SEARCH_INCLUDES NO)
set(DOXYGEN_SOURCE_BROWSER YES)
set(DOXYGEN_INLINE_SOURCES NO)
set(DOXYGEN_GENERATE_TREEVIEW YES)
set(DOXYGEN_HTML_DYNAMIC_MENUS NO)
set(DOXYGEN_HTML_COLORSTYLE AUTO_LIGHT)
set(DOXYGEN_MARKDOWN_ID_STYLE GITHUB)
# Doxygen misreads source-file links and linked local SVG badges. Adapt only
# the rendering copy; GitHub keeps the original relative Markdown links.
set(docs_markdown_root "${CMAKE_CURRENT_BINARY_DIR}/markdown")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
  "${PROJECT_SOURCE_DIR}/README.md")
file(READ "${PROJECT_SOURCE_DIR}/README.md" docs_readme)
string(REPLACE "](CMakeLists.txt)"
  "](https://github.com/ekmett/auth/blob/main/CMakeLists.txt)"
  docs_readme "${docs_readme}")
string(REGEX REPLACE "\\[!\\[([^]]*)\\]\\((assets/badges/[^)]+)\\)\\]\\(([^)]+)\\)"
  "<a href=\"https://github.com/ekmett/auth/blob/main/\\3\"><img src=\"\\2\" alt=\"\\1\" /></a>"
  docs_readme "${docs_readme}")
file(MAKE_DIRECTORY "${docs_markdown_root}")
file(WRITE "${docs_markdown_root}/README.md" "${docs_readme}")
set(DOXYGEN_USE_MDFILE_AS_MAINPAGE "${docs_markdown_root}/README.md")
set(DOXYGEN_STRIP_FROM_PATH "${docs_markdown_root}" "${PROJECT_SOURCE_DIR}")
set(DOXYGEN_QUIET YES)
set(DOXYGEN_WARN_AS_ERROR FAIL_ON_WARNINGS)
set(DOXYGEN_WARN_IF_DOC_ERROR YES)
set(DOXYGEN_WARN_IF_UNDOCUMENTED YES)
set(DOXYGEN_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/docs")
set(DOXYGEN_WARN_LOGFILE "${PROJECT_BINARY_DIR}/docs/warnings.log")
doxygen_add_docs(auth_docs
  "${PROJECT_SOURCE_DIR}/src/auth.ccm"
  "${PROJECT_SOURCE_DIR}/src/auth/serialization.ccm"
  "${PROJECT_SOURCE_DIR}/src/auth/hash.ccm"
  "${PROJECT_SOURCE_DIR}/src/auth/error.ccm"
  "${docs_markdown_root}/README.md"
  "${PROJECT_SOURCE_DIR}/LICENSE.md"
  "${PROJECT_SOURCE_DIR}/CONTRIBUTING.md"
  "${PROJECT_SOURCE_DIR}/CODE_OF_CONDUCT.md"
  "${PROJECT_SOURCE_DIR}/SECURITY.md"
  WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
  COMMENT "Build auth API documentation")

# Remove stale pages when declarations or modules are renamed.
add_custom_target(auth_docs_clean
  COMMAND "${CMAKE_COMMAND}" -E rm -rf
    "${PROJECT_BINARY_DIR}/docs/html" "${PROJECT_BINARY_DIR}/docs/xml"
  VERBATIM)
add_dependencies(auth_docs auth_docs_clean)

# Doxygen 1.18's module indices link to anchors missing from the declaration rows.
add_custom_command(TARGET auth_docs POST_BUILD
  COMMAND "${CMAKE_COMMAND}" -E copy_directory
    "${PROJECT_SOURCE_DIR}/assets/badges" "${PROJECT_BINARY_DIR}/docs/html/assets/badges"
  COMMAND "${Python3_EXECUTABLE}" -B "${CMAKE_CURRENT_SOURCE_DIR}/fix_module_anchors.py"
    "${PROJECT_BINARY_DIR}/docs/html"
  VERBATIM)
