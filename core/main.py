#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
import asyncio
import importlib
import importlib.util

from . import fancy_logs
from . import parse_conf
from . import defaults
from . import plugin_base


version = 2.0


def terminate_application():
    log.info("Pythapi terminated.")
    sys.exit(0)


def termination_handler(signal, frame):
    print()
    terminate_application()


def r_mark_broken_dependencies(plugin_name, plugin_dict, inverse_dependency_table, depth=0):
    if depth > len(plugin_dict):
        log.critical("Loop in dependency tree!")
        terminate_application()

    try:
        plugin = plugin_dict[plugin_name]
    except KeyError:
        return

    for inv_dependency_name in inverse_dependency_table[plugin_name]:
        r_mark_broken_dependencies(
            inv_dependency_name,
            plugin_dict,
            inverse_dependency_table,
            depth+1
        )

    plugin.error_code = 1


def serialize_plugin_hierarchy(plugin_dict, inverse_dependency_table, single_plugin_name=None):
    # Step 1: Traverse dependency tree
    def r_traverse_dependencies(i_plugin, i_depth=0):
        if i_depth > len(plugin_dict):
            log.critical("Loop in dependency tree!")
            terminate_application()

        if i_plugin.is_placed:
            return []

        i_serialized_list = []
        for i_dependency in i_plugin.depends:
            if not i_dependency['required']:
                continue

            try:
                i_serialized_list.extend(
                    r_traverse_dependencies(
                        plugin_dict[i_dependency['name']],
                        i_depth+1
                    )
                )
            except KeyError:
                r_mark_broken_dependencies(
                    i_plugin.name,
                    plugin_dict,
                    inverse_dependency_table
                )

        i_serialized_list.append(i_plugin.name)
        i_plugin.is_placed = True
        return i_serialized_list

    for plugin_name in plugin_dict:
        plugin_dict[plugin_name].is_placed = 0

    serialized_list = []
    if single_plugin_name:
        serialized_list.extend(
            r_traverse_dependencies(plugin_dict[single_plugin_name])
        )
    else:
        for k, plugin in plugin_dict.items():
            serialized_list.extend(
                r_traverse_dependencies(plugin)
            )

    # Step 2: Remove plugins with broken dependencies
    for plugin_name, plugin in dict(plugin_dict).items():
        if plugin.error_code == 1:
            log.error("Disabling {} due to an error.".format(plugin_name))
            serialized_list.remove(plugin_name)
            del plugin_dict[plugin_name]

    return serialized_list


# TODO: Create tests
def run(args, test_mode=False):
    global log

    # Reset plugin_base variables
    plugin_base.init()

    # Read configuration files
    config_parser = parse_conf.PythapiConfigParser()
    config_parser.read_defaults(defaults.config_defaults)  # Core defaults only
    config_parser.recursive_read(args.config or defaults.config_base_path)
    config_parser.read_list(args.config_parameter)

    config_cgen = config_parser["core.general"]

    # Initialize fancy_logs
    log = fancy_logs.FancyLogger(
        not (not config_cgen["colored_logs"] or args.no_fancy),
        args.verbosity or config_cgen["loglevel"],
        config_cgen["file_logging_enabled"],
        config_cgen["logfile"],
        )
    plugin_base.log = log
    log.debug("Args: {}".format(vars(args)))
    log.debug("Config: {}".format(config_parser.as_dict()))

    log.info("Start importing plugins...")
    log.indent(1)
    # Add additional plugin paths
    plugin_search_paths = ['plugins'] + config_cgen['additional_plugin_paths']
    for path in plugin_search_paths:
        sys.path.append(path)

    # Import enabled plugins
    tmp_plugin_name_list = config_cgen['enabled_plugins']
    for plugin_filename in list(tmp_plugin_name_list):
        if not importlib.util.find_spec(plugin_filename):
            continue

        log.debug("Importing {}".format(plugin_filename))
        try:
            module = importlib.import_module(plugin_filename)
            plugin_base.module_dict[plugin_filename] = module

            config_parser.read_defaults(module.plugin.config_defaults)
            module.plugin.reinit()

        except ImportError as e:
            log.critical("Error while importing {}".format(plugin_filename), exc_info=e)
            terminate_application()
    log.indent(-1)
    log.blank()

    # Verifiy Configuration
    log.info("Loading Plugins...")
    log.indent(1)
    try:
        config_parser.verify()
    except parse_conf.ConfigNotSatisfiedException as e:
        log.error(e)
        terminate_application()

    # Build plugin_dict and inverse_dependency_table
    plugin_dict = {}
    inverse_dependency_table = {}
    for k, module in plugin_base.module_dict.items():
        plugin_name = module.plugin.name
        plugin_dict[plugin_name] = module.plugin
        inverse_dependency_table[plugin_name] = set()

    for plugin_name, plugin in plugin_dict.items():
        for dependency in plugin.depends:
            try:
                inverse_dependency_table[dependency['name']].add(plugin_name)
            except KeyError:
                continue

    plugin_base.plugin_dict = plugin_dict
    plugin_base.inverse_dependency_table = inverse_dependency_table

    event_mapper = {
        'run': "core.load",
        'install': "core.install",
        'uninstall': "core.uninstall",
    }
    main_event = event_mapper[args.mode]

    while True:
        def mark_error(i_plugin_name):
            log.error("Error at: {}".format(i_plugin_name))
            r_mark_broken_dependencies(
                i_plugin_name,
                plugin_dict,
                inverse_dependency_table
            )

        error_occurred = False
        serialized_plugin_list = serialize_plugin_hierarchy(
            plugin_dict,
            inverse_dependency_table,
            args.plugin
        )

        plugin_base.serialized_plugin_list = serialized_plugin_list

        if main_event == "core.uninstall" or args.reinstall:
            uninstall_list = [args.plugin] if args.plugin else reversed(serialized_plugin_list)

            for plugin_name in uninstall_list:

                if "core.uninstall" not in plugin_dict[plugin_name].events:
                    continue

                log.info("Triggering {} event for {}...".format("core.uninstall", plugin_name))
                log.indent(1)
                plugin_dict[plugin_name].events["core.uninstall"]()
                log.indent(-1)
                log.blank()

            if main_event == "core.uninstall":
                break

        # Triggering main_event event
        for plugin_name in serialized_plugin_list:
            if plugin_dict[plugin_name].is_loaded:
                continue

            if "core.check" in plugin_dict[plugin_name].events:
                log.debug("Checking {}...".format(plugin_name))
                log.indent(1)
                check_successful = plugin_dict[plugin_name].events['core.check']() is not False
                log.indent(-1)
                log.blank()

            else:
                check_successful = True

            if not check_successful and main_event == 'core.load':
                mark_error(plugin_name)
                error_occurred = True
                continue
            elif check_successful and main_event == 'core.install':
                continue

            if main_event not in plugin_dict[plugin_name].events:
                continue

            log.info("Triggering {} event for {}...".format(main_event, plugin_name))
            log.indent(1)
            load_successful = plugin_dict[plugin_name].events[main_event]() is not False
            log.indent(-1)
            log.blank()
            if load_successful:
                plugin_dict[plugin_name].is_loaded = True
            else:
                mark_error(plugin_name)
                error_occurred = True
                continue

        if main_event == 'core.load':
            for plugin_name in serialized_plugin_list:

                if "core.load_optional" not in plugin_dict[plugin_name].events:
                    continue

                log.info("Triggering {} event for {}...".format("core.load_optional", plugin_name))
                log.indent(1)
                plugin_dict[plugin_name].events["core.load_optional"]()
                log.indent(-1)
                log.blank()

        if not error_occurred:
            break

    log.indent(-1)

    if main_event == "core.install":
        log.success("pythapi successfully installed.")
        terminate_application()
    elif main_event == "core.uninstall":
        log.success("pythapi successfully uninstalled.")
        terminate_application()
    else:
        log.success("pythapi successfully started.")

    log.info("Entering main loop...")
    asyncio.get_event_loop().run_forever()
