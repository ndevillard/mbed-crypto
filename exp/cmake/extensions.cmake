# SPDX-License-Identifier: Apache-2.0
# Based on https://github.com/zephyrproject-rtos/zephyr/blob/master/cmake/extensions.cmake

function(psa_crypto_sources)
  foreach(arg ${ARGV})
    if(IS_DIRECTORY ${arg})
      message(FATAL_ERROR "psa_crypto_sources() was called on a directory")
    endif()
    target_sources(psa_crypto PRIVATE ${arg})
  endforeach()
endfunction()

########################################################
# 1) Kconfig-aware extensions
########################################################
#
# Kconfig is a configuration language developed for the Linux
# kernel. The below functions integrate CMake with Kconfig.
#
# 1.1) *_if_kconfig
#
# Functions for conditionally including directories and source files
# that have matching KConfig values.
#
# psa_crypto_library_sources_if_kconfig(sha2.c)
# is the same as
# psa_crypto_library_sources_ifdef(CONFIG_SHA2 sha2.c)
#
# add_subdirectory_if_kconfig(serial)
# is the same as
# add_subdirectory_ifdef(CONFIG_SERIAL serial)
function(add_subdirectory_if_kconfig dir)
  string(TOUPPER config_${dir} UPPER_CASE_CONFIG)
  add_subdirectory_ifdef(${UPPER_CASE_CONFIG} ${dir})
endfunction()

function(target_sources_if_kconfig target scope item)
  get_filename_component(item_basename ${item} NAME_WE)
  string(TOUPPER CONFIG_${item_basename} UPPER_CASE_CONFIG)
  target_sources_ifdef(${UPPER_CASE_CONFIG} ${target} ${scope} ${item})
endfunction()

function(psa_crypto_library_sources_if_kconfig item)
  get_filename_component(item_basename ${item} NAME_WE)
  string(TOUPPER CONFIG_${item_basename} UPPER_CASE_CONFIG)
  psa_crypto_library_sources_ifdef(${UPPER_CASE_CONFIG} ${item})
endfunction()

function(psa_crypto_sources_if_kconfig item)
  get_filename_component(item_basename ${item} NAME_WE)
  string(TOUPPER CONFIG_${item_basename} UPPER_CASE_CONFIG)
  psa_crypto_sources_ifdef(${UPPER_CASE_CONFIG} ${item})
endfunction()

# 1.2) Misc
#
# import_kconfig(<prefix> <kconfig_fragment> [<keys>])
#
# Parse a KConfig fragment (typically with extension .config) and
# introduce all the symbols that are prefixed with 'prefix' into the
# CMake namespace. List all created variable names in the 'keys'
# output variable if present.
function(import_kconfig prefix kconfig_fragment)
  # Parse the lines prefixed with 'prefix' in ${kconfig_fragment}
  file(
    STRINGS
    ${kconfig_fragment}
    DOT_CONFIG_LIST
    REGEX "^${prefix}"
    ENCODING "UTF-8"
  )

  foreach (CONFIG ${DOT_CONFIG_LIST})
    # CONFIG could look like: CONFIG_NET_BUF=y

    # Match the first part, the variable name
    string(REGEX MATCH "[^=]+" CONF_VARIABLE_NAME ${CONFIG})

    # Match the second part, variable value
    string(REGEX MATCH "=(.+$)" CONF_VARIABLE_VALUE ${CONFIG})
    # The variable name match we just did included the '=' symbol. To just get the
    # part on the RHS we use match group 1
    set(CONF_VARIABLE_VALUE ${CMAKE_MATCH_1})

    if("${CONF_VARIABLE_VALUE}" MATCHES "^\"(.*)\"$") # Is surrounded by quotes
      set(CONF_VARIABLE_VALUE ${CMAKE_MATCH_1})
    endif()

    set("${CONF_VARIABLE_NAME}" "${CONF_VARIABLE_VALUE}" PARENT_SCOPE)
    list(APPEND keys "${CONF_VARIABLE_NAME}")
  endforeach()

  foreach(outvar ${ARGN})
    set(${outvar} "${keys}" PARENT_SCOPE)
  endforeach()
endfunction()


########################################################
# 2. CMake-generic extensions
########################################################
#
# These functions extend the CMake API in a way that is not particular
# to psa_crypto. Primarily they work around limitations in the CMake
# language to allow cleaner build scripts.

# 2.1. *_ifdef
#
# Functions for conditionally executing CMake functions with oneliners
# e.g.
#
# if(CONFIG_SHA2)
#   psa_crypto_library_source(
#     sha2_256.c
#     sha2_utils.c
#     )
# endif()
#
# Becomes
#
# psa_crypto_source_ifdef(
#   CONFIG_SHA2
#   sha2_32.c
#   sha2_utils.c
#   )
#
# More Generally
# "<function-name>_ifdef(CONDITION args)"
# Becomes
# """
# if(CONDITION)
#   <function-name>(args)
# endif()
# """
#
# ifdef functions are added on an as-need basis. See
# https://cmake.org/cmake/help/latest/manual/cmake-commands.7.html for
# a list of available functions.
function(add_subdirectory_ifdef feature_toggle dir)
  if(${${feature_toggle}})
    add_subdirectory(${dir})
  endif()
endfunction()

function(target_sources_ifdef feature_toggle target scope item)
  if(${${feature_toggle}})
    target_sources(${target} ${scope} ${item} ${ARGN})
  endif()
endfunction()

function(target_compile_definitions_ifdef feature_toggle target scope item)
  if(${${feature_toggle}})
    target_compile_definitions(${target} ${scope} ${item} ${ARGN})
  endif()
endfunction()

function(target_include_directories_ifdef feature_toggle target scope item)
  if(${${feature_toggle}})
    target_include_directories(${target} ${scope} ${item} ${ARGN})
  endif()
endfunction()

function(target_link_libraries_ifdef feature_toggle target item)
  if(${${feature_toggle}})
    target_link_libraries(${target} ${item} ${ARGN})
  endif()
endfunction()

function(add_compile_option_ifdef feature_toggle option)
  if(${${feature_toggle}})
    add_compile_options(${option})
  endif()
endfunction()

function(target_compile_option_ifdef feature_toggle target scope option)
  if(${feature_toggle})
    target_compile_options(${target} ${scope} ${option})
  endif()
endfunction()

function(target_cc_option_ifdef feature_toggle target scope option)
  if(${feature_toggle})
    target_cc_option(${target} ${scope} ${option})
  endif()
endfunction()

function(psa_crypto_library_sources_ifdef feature_toggle source)
  if(${${feature_toggle}})
    psa_crypto_library_sources(${source} ${ARGN})
  endif()
endfunction()

function(psa_crypto_library_sources_ifndef feature_toggle source)
  if(NOT ${feature_toggle})
    psa_crypto_library_sources(${source} ${ARGN})
  endif()
endfunction()

function(psa_crypto_sources_ifdef feature_toggle)
  if(${${feature_toggle}})
    psa_crypto_sources(${ARGN})
  endif()
endfunction()

function(psa_crypto_sources_ifndef feature_toggle)
   if(NOT ${feature_toggle})
    psa_crypto_sources(${ARGN})
  endif()
endfunction()

function(psa_crypto_cc_option_ifdef feature_toggle)
  if(${${feature_toggle}})
    psa_crypto_cc_option(${ARGN})
  endif()
endfunction()

function(psa_crypto_ld_option_ifdef feature_toggle)
  if(${${feature_toggle}})
    psa_crypto_ld_options(${ARGN})
  endif()
endfunction()

function(psa_crypto_link_libraries_ifdef feature_toggle)
  if(${${feature_toggle}})
    psa_crypto_link_libraries(${ARGN})
  endif()
endfunction()

function(psa_crypto_compile_options_ifdef feature_toggle)
  if(${${feature_toggle}})
    psa_crypto_compile_options(${ARGN})
  endif()
endfunction()

function(psa_crypto_compile_definitions_ifdef feature_toggle)
  if(${${feature_toggle}})
    psa_crypto_compile_definitions(${ARGN})
  endif()
endfunction()

function(psa_crypto_include_directories_ifdef feature_toggle)
  if(${${feature_toggle}})
    psa_crypto_include_directories(${ARGN})
  endif()
endfunction()

function(psa_crypto_library_compile_definitions_ifdef feature_toggle item)
  if(${${feature_toggle}})
    psa_crypto_library_compile_definitions(${item} ${ARGN})
  endif()
endfunction()

function(psa_crypto_library_compile_options_ifdef feature_toggle item)
  if(${${feature_toggle}})
    psa_crypto_library_compile_options(${item} ${ARGN})
  endif()
endfunction()

function(psa_crypto_link_interface_ifdef feature_toggle interface)
  if(${${feature_toggle}})
    target_link_libraries(${interface} INTERFACE psa_crypto_interface)
  endif()
endfunction()

function(psa_crypto_library_link_libraries_ifdef feature_toggle item)
  if(${${feature_toggle}})
     psa_crypto_library_link_libraries(${item})
  endif()
endfunction()

function(psa_crypto_linker_sources_ifdef feature_toggle)
  if(${${feature_toggle}})
    psa_crypto_linker_sources(${ARGN})
  endif()
endfunction()

macro(list_append_ifdef feature_toggle list)
  if(${${feature_toggle}})
    list(APPEND ${list} ${ARGN})
  endif()
endmacro()

# 2.2. *_ifndef
# See 2.1 *_ifdef
function(set_ifndef variable value)
  if(NOT ${variable})
    set(${variable} ${value} ${ARGN} PARENT_SCOPE)
  endif()
endfunction()

function(target_cc_option_ifndef feature_toggle target scope option)
  if(NOT ${feature_toggle})
    target_cc_option(${target} ${scope} ${option})
  endif()
endfunction()

function(psa_crypto_cc_option_ifndef feature_toggle)
  if(NOT ${feature_toggle})
    psa_crypto_cc_option(${ARGN})
  endif()
endfunction()

function(psa_crypto_compile_options_ifndef feature_toggle)
  if(NOT ${feature_toggle})
    psa_crypto_compile_options(${ARGN})
  endif()
endfunction()
