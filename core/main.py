#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import importlib
import importlib.util
import asyncio

from . import fancy_logs
from . import parse_conf
from . import defaults
from . import plugin_base


version = 2.0
loop = None
loaded_event = None
log = None
terminated = True


def terminate_application(error_msg=None, exc_info=None):
    global terminated
    if terminated:
        return

    if loaded_event is not None:
        loaded_event.set()

    for plugin_name, plugin in plugin_base.plugin_dict.items() or []:
        if not plugin.is_loaded:
            continue

        if 'core.terminate' in plugin.events:
            for event, data in plugin.events['core.terminate']:
                event()

    if loop is not None:
        loop.call_soon_threadsafe(loop.stop)

    if log is not None:
        if error_msg is not None:
            log.critical(error_msg, exc_info=exc_info)

        log.indent(-999)
        log.info("Pythapi terminated.")

    terminated = True
    sys.exit(0)


def termination_handler(signal, frame):
    print()
    terminate_application()


def r_mark_broken_dependencies(plugin_name, plugin_dict, inverse_dependency_table, depth=0):
    if depth > len(plugin_dict):
        terminate_application("Loop in dependency tree!")

    try:
        plugin = plugin_dict[plugin_name]
    except KeyError:
        return

    for id_name, id_required in inverse_dependency_table[plugin_name]:
        if id_required is False:
            continue

        r_mark_broken_dependencies(
            id_name,
            plugin_dict,
            inverse_dependency_table,
            depth+1
        )

    plugin.error_code = 1


def serialize_plugin_hierarchy(plugin_dict, inverse_dependency_table, single_plugin_name=None):
    # Step 1: Traverse dependency tree
    def r_traverse_dependencies(i_plugin, i_depth=0):
        if i_depth > len(plugin_dict):
            terminate_application("Loop in dependency tree!")

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
                log.error("{} is missing {}.".format(plugin_name, i_dependency['name']))
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
            log.info("Disabling {} due to an error.".format(plugin_name))
            serialized_list.remove(plugin_name)
            del plugin_dict[plugin_name]

    return serialized_list


def run(args, event=None, config_dict=None):
    global terminated
    global log
    global loop
    global loaded_event
    loaded_event = event

    if not terminated:
        print("Pythapi is already running!")

        if loaded_event is not None:
            loaded_event.set()

        return

    terminated = False
    # Reset plugin_base variables
    plugin_base.init()

    # Read configuration files
    config_parser = parse_conf.PythapiConfigParser()
    config_parser.read_defaults(defaults.config_defaults)  # Core defaults only
    plugin_base.config = config_parser

    if config_dict:
        config_parser.recursive_read_dict(config_dict)
    else:
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

        except Exception as e:
            terminate_application("Error while importing {}".format(plugin_filename), exc_info=e)
    log.indent(-1)

    # Verifiy Configuration
    log.info("Loading Plugins...")
    log.indent(1)

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
                inverse_dependency_table[dependency['name']].add((plugin_name, dependency['required']))
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
                for event, data in plugin_dict[plugin_name].events["core.uninstall"]:
                    event()
                log.indent(-1)

            if main_event == "core.uninstall":
                break

        # Triggering main_event event
        skip = False
        for plugin_name in serialized_plugin_list:
            if plugin_dict[plugin_name].is_loaded:
                continue

            check_successful = True
            if "core.check" in plugin_dict[plugin_name].events:
                log.debug("Checking {}...".format(plugin_name))
                log.indent(1)
                for event, data in plugin_dict[plugin_name].events['core.check']:
                    check_successful = check_successful and event() is not False
                log.indent(-1)

            if not check_successful and main_event == 'core.load':
                mark_error(plugin_name)
                error_occurred = True
                skip = True
                break
            elif check_successful and main_event == 'core.install':
                continue

            if main_event not in plugin_dict[plugin_name].events:
                continue

            log.info("Triggering {} event for {}...".format(main_event, plugin_name))
            log.indent(1)
            load_successful = True
            for event, data in plugin_dict[plugin_name].events[main_event]:
                load_successful = load_successful and event() is not False
            log.indent(-1)

            if load_successful:
                plugin_dict[plugin_name].is_loaded = True
            else:
                mark_error(plugin_name)
                error_occurred = True
                skip = True
                break
        if skip:
            continue

        if main_event == 'core.load':
            for plugin_name in serialized_plugin_list:

                if "core.load_optional" not in plugin_dict[plugin_name].events:
                    continue

                log.info("Triggering {} event for {}...".format("core.load_optional", plugin_name))
                log.indent(1)
                for event, data in plugin_dict[plugin_name].events["core.load_optional"]:
                    event()
                log.indent(-1)

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
    loop = asyncio.get_event_loop()
    
    if loaded_event is not None:
        loaded_event.set()

    loop.run_forever()
