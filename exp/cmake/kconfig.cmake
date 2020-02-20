# SPDX-License-Identifier: Apache-2.0
# Based on https://github.com/zephyrproject-rtos/zephyr/blob/master/cmake/kconfig.cmake

file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/kconfig/include/config)
file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/kconfig/include/generated)
set(AUTOCONF_H ${PROJECT_BINARY_DIR}/kconfig/include/generated/autoconf.h)

set(KCONFIG_ROOT ${PSA_CRYPTO_BASE}/Kconfig)

set(DOTCONFIG ${PROJECT_BINARY_DIR}/.config)
set(PARSED_KCONFIG_SOURCES_TXT ${PROJECT_BINARY_DIR}/kconfig/sources.txt)
set(input_configs ${CMAKE_SOURCE_DIR}/.config)
set(ENV{KCONFIG_CONFIG} ${DOTCONFIG})
set(ENV{PYTHON_EXECUTABLE} ${PYTHON_EXECUTABLE})

execute_process(
  COMMAND
  ${PYTHON_EXECUTABLE}
  ${PSA_CRYPTO_BASE}/scripts/kconfig.py
  ${input_configs_are_handwritten}
  ${KCONFIG_ROOT}
  ${DOTCONFIG}
  ${AUTOCONF_H}
  ${PARSED_KCONFIG_SOURCES_TXT}
  ${input_configs}
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  # The working directory is set to the app dir such that the user
  # can use relative paths in CONF_FILE, e.g. CONF_FILE=nrf5.conf
  RESULT_VARIABLE ret
  )
if(NOT "${ret}" STREQUAL "0")
  message(FATAL_ERROR "command failed with return code: ${ret}")
endif()


# Parse the lines prefixed with CONFIG_ in the .config file from Kconfig
import_kconfig(CONFIG_ ${DOTCONFIG})


