#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Based on https://github.com/zephyrproject-rtos/zephyr/blob/master/scripts/kconfig/kconfig.py

# Writes/updates the zephyr/.config configuration file by merging configuration
# files passed as arguments, e.g. board *_defconfig and application prj.conf
# files.
#
# When fragments haven't changed, zephyr/.config is both the input and the
# output, which just updates it. This is handled in the CMake files.
#
# Also does various checks (most via Kconfiglib warnings).

import argparse
import os
import sys
import textwrap

# Zephyr doesn't use tristate symbols. They're supported here just to make the
# script a bit more generic.
from kconfiglib import Kconfig, split_expr, expr_value, expr_str, BOOL, \
                       TRISTATE, TRI_TO_STR, AND


def main():
    args = parse_args()

    print("Parsing " + args.kconfig_file)
    kconf = Kconfig(args.kconfig_file, warn_to_stderr=False,
                    suppress_traceback=True)

    if args.handwritten_input_configs:
        # Warn for assignments to undefined symbols, but only for handwritten
        # fragments, to avoid warnings-turned-errors when using an old
        # configuration file together with updated Kconfig files
        kconf.warn_assign_undef = True

        # prj.conf may override settings from the board configuration, so
        # disable warnings about symbols being assigned more than once
        kconf.warn_assign_override = False
        kconf.warn_assign_redun = False

    # Load configuration files
    print(kconf.load_config(args.configs_in[0]))
    for config in args.configs_in[1:]:
        # replace=False creates a merged configuration
        print(kconf.load_config(config, replace=False))

    if args.handwritten_input_configs:
        # Check that there are no assignments to promptless symbols, which
        # have no effect.
        #
        # This only makes sense when loading handwritten fragments and not when
        # loading zephyr/.config, because zephyr/.config is configuration
        # output and also assigns promptless symbols.
        check_no_promptless_assign(kconf)

        # Print warnings for symbols that didn't get the assigned value. Only
        # do this for handwritten input too, to avoid likely unhelpful warnings
        # when using an old configuration and updating Kconfig files.
        check_assigned_sym_values(kconf)
        check_assigned_choice_values(kconf)

    # Hack: Force all symbols to be evaluated, to catch warnings generated
    # during evaluation. Wait till the end to write the actual output files, so
    # that we don't generate any output if there are warnings-turned-errors.
    #
    # Kconfiglib caches calculated symbol values internally, so this is still
    # fast.
    kconf.write_config(os.devnull)

    if kconf.warnings:
        # Put a blank line between warnings to make them easier to read
        for warning in kconf.warnings:
            print("\n" + warning, file=sys.stderr)

        # Turn all warnings into errors, so that e.g. assignments to undefined
        # Kconfig symbols become errors.
        #
        # A warning is generated by this script whenever a symbol gets a
        # different value than the one it was assigned. Keep that one as just a
        # warning for now.
        err("Aborting due to Kconfig warnings")

    # Write the merged configuration and the C header
    print(kconf.write_config(args.config_out))
    print(kconf.write_autoconf(args.header_out))

    # Write the list of parsed Kconfig files to a file
    write_kconfig_filenames(kconf, args.kconfig_list_out)


def check_no_promptless_assign(kconf):
    # Checks that no promptless symbols are assigned

    for sym in kconf.unique_defined_syms:
        if sym.user_value is not None and promptless(sym):
            err(f"""\
{sym.name_and_loc} is assigned in a configuration file, but is not directly
user-configurable (has no prompt). It gets its value indirectly from other
symbols. """ + SYM_INFO_HINT.format(sym))


def check_assigned_sym_values(kconf):
    # Verifies that the values assigned to symbols "took" (matches the value
    # the symbols actually got), printing warnings otherwise. Choice symbols
    # are checked separately, in check_assigned_choice_values().

    for sym in kconf.unique_defined_syms:
        if sym.choice:
            continue

        user_value = sym.user_value
        if user_value is None:
            continue

        # Tristate values are represented as 0, 1, 2. Having them as "n", "m",
        # "y" is more convenient here, so convert.
        if sym.type in (BOOL, TRISTATE):
            user_value = TRI_TO_STR[user_value]

        if user_value != sym.str_value:
            msg = f"{sym.name_and_loc} was assigned the value '{user_value}' " \
                  f"but got the value '{sym.str_value}'. "

            # List any unsatisfied 'depends on' dependencies in the warning
            mdeps = missing_deps(sym)
            if mdeps:
                expr_strs = []
                for expr in mdeps:
                    estr = expr_str(expr)
                    if isinstance(expr, tuple):
                        # Add () around dependencies that aren't plain symbols.
                        # Gives '(FOO || BAR) (=n)' instead of
                        # 'FOO || BAR (=n)', which might be clearer.
                        estr = f"({estr})"
                    expr_strs.append(f"{estr} (={TRI_TO_STR[expr_value(expr)]})")

                msg += "Check these unsatisfied dependencies: " + \
                    ", ".join(expr_strs) + ". "

            warn(msg + SYM_INFO_HINT.format(sym))


def missing_deps(sym):
    # check_assigned_sym_values() helper for finding unsatisfied dependencies.
    #
    # Given direct dependencies
    #
    #     depends on <expr> && <expr> && ... && <expr>
    #
    # on 'sym' (which can also come from e.g. a surrounding 'if'), returns a
    # list of all <expr>s with a value less than the value 'sym' was assigned
    # ("less" instead of "not equal" just to be general and handle tristates,
    # even though Zephyr doesn't use them).
    #
    # For string/int/hex symbols, just looks for <expr> = n.
    #
    # Note that <expr>s can be something more complicated than just a symbol,
    # like 'FOO || BAR' or 'FOO = "string"'.

    deps = split_expr(sym.direct_dep, AND)

    if sym.type in (BOOL, TRISTATE):
        return [dep for dep in deps if expr_value(dep) < sym.user_value]
    # string/int/hex
    return [dep for dep in deps if expr_value(dep) == 0]


def check_assigned_choice_values(kconf):
    # Verifies that any choice symbols that were selected (by setting them to
    # y) ended up as the selection, printing warnings otherwise.
    #
    # We check choice symbols separately to avoid warnings when two different
    # choice symbols within the same choice are set to y. This might happen if
    # a choice selection from a board defconfig is overridden in a prj.conf, for
    # example. The last choice symbol set to y becomes the selection (and all
    # other choice symbols get the value n).
    #
    # Without special-casing choices, we'd detect that the first symbol set to
    # y ended up as n, and print a spurious warning.

    for choice in kconf.unique_choices:
        if choice.user_selection and \
           choice.user_selection is not choice.selection:

            warn(f"""\
The choice symbol {choice.user_selection.name_and_loc} was selected (set =y),
but {choice.selection.name_and_loc if choice.selection else "no symbol"} ended
up as the choice selection. """ + SYM_INFO_HINT.format(choice.user_selection))


# Hint on where to find symbol information. Used like
# SYM_INFO_HINT.format(sym).
SYM_INFO_HINT = """\
See http://docs.zephyrproject.org/latest/reference/kconfig/CONFIG_{0.name}.html
and/or look up {0.name} in the menuconfig/guiconfig interface. The Application
Development Primer, Setting Configuration Values, and Kconfig - Tips and Best
Practices sections of the manual might be helpful too.\
"""


def promptless(sym):
    # Returns True if 'sym' has no prompt. Since the symbol might be defined in
    # multiple locations, we need to check all locations.

    return not any(node.prompt for node in sym.nodes)


def write_kconfig_filenames(kconf, kconfig_list_path):
    # Writes a sorted list with the absolute paths of all parsed Kconfig files
    # to 'kconfig_list_path'. The paths are realpath()'d, and duplicates are
    # removed. This file is used by CMake to look for changed Kconfig files. It
    # needs to be deterministic.

    with open(kconfig_list_path, 'w') as out:
        for path in sorted({os.path.realpath(os.path.join(kconf.srctree, path))
                            for path in kconf.kconfig_filenames}):
            print(path, file=out)


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("--handwritten-input-configs",
                        action="store_true",
                        help="Assume the input configuration fragments are "
                             "handwritten fragments and do additional checks "
                             "on them, like no promptless symbols being "
                             "assigned")
    parser.add_argument("kconfig_file",
                        help="Top-level Kconfig file")
    parser.add_argument("config_out",
                        help="Output configuration file")
    parser.add_argument("header_out",
                        help="Output header file")
    parser.add_argument("kconfig_list_out",
                        help="Output file for list of parsed Kconfig files")
    parser.add_argument("configs_in",
                        nargs="+",
                        help="Input configuration fragments. Will be merged "
                             "together.")

    return parser.parse_args()


def warn(msg):
    # Use a large fill() width to try to avoid linebreaks in the symbol
    # reference link, and add some extra newlines to set the message off from
    # surrounding text (this usually gets printed as part of spammy CMake
    # output)
    print("\n" + textwrap.fill("warning: " + msg, 100) + "\n", file=sys.stderr)


def err(msg):
    sys.exit("\n" + textwrap.fill("error: " + msg, 100) + "\n")


if __name__ == "__main__":
    main()
