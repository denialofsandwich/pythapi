#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest

import core.main
import core.tests.tools
import core.plugin_base

import re


def _base_conf_gen():
    return {
        "core.general": {
            "loglevel": 6,
            "additional_plugin_paths": "core/tests/plugins",
            "enabled_plugins": "debug, debug2, debug3",
        },
        "debug2": {
            "enabled_plugins": "lolo, lili, lulu",
        },
    }


@pytest.fixture(scope='function')
def base_conf():
    yield _base_conf_gen()


@pytest.fixture(scope='function')
def cs_bare():
    yield core.tests.tools.CoreSystem()


def test_plain_start(capsys, cs_bare, base_conf):
    cs_bare.conf = base_conf

    with cs_bare:
        pass

    logs = capsys.readouterr().out
    print(logs)

    assert len(re.findall(re.escape("Running core.declare from debug1..."), logs)) == 1
    assert len(re.findall(re.escape("Running core.declare from debug3..."), logs)) == 0

    assert len(re.findall(re.escape("Running core.load from debug1..."), logs)) == 1
    assert len(re.findall(re.escape("Running core.load from debug3..."), logs)) == 1

    assert len(re.findall(re.escape("TERMINATATA"), logs)) == 1

    assert len(re.findall(r'ERROR|CRITICAL', logs)) == 0


# debug2 should throw an error, because it needs debug3 to load
def test_broken_dependency(capsys, cs_bare, base_conf):
    base_conf['core.general']['enabled_plugins'] = "debug, debug2, tete"
    cs_bare.conf = base_conf

    with cs_bare:
        pass

    # Notice the missing Plugin "tete"

    logs = capsys.readouterr().out
    print(logs)

    assert len(re.findall(re.escape("Can't find plugin: tete"), logs)) == 2
    assert len(re.findall(r'ERROR', logs)) == 1
    assert len(re.findall(r'debug2 is missing debug3', logs)) == 1
    assert len(re.findall(r'Pythapi successfuly started.', logs)) == 1


def test_r_mark_broken_dependencies(capsys, cs_bare, base_conf):

    # Test loop detector
    core.main.r_mark_broken_dependencies(None, {}, None, depth=1)

    # Test behavior if plugin doesn't exist
    core.main.r_mark_broken_dependencies("a", {}, None)

    class TestPlugin:
        error_code = 1

    core.main.r_mark_broken_dependencies("a", {
        "a": TestPlugin()
    }, None)

    # Flush sysout
    print(capsys.readouterr())

    base_conf['core.general']['enabled_plugins'] = "debug2, debug3"
    cs_bare.conf = base_conf
    with cs_bare:
        pass

    logs = capsys.readouterr().out
    print(logs)

    assert len(re.findall(re.escape("debug3 is missing debug1."), logs)) == 1
    assert len(re.findall(re.escape("debug2 is missing debug3."), logs)) == 1

    assert len(re.findall(r'ERROR', logs)) == 2


def test_serialize_plugin_hierarchy_loop_detection(capsys, cs_bare, base_conf):
    base_conf['core.general']['enabled_plugins'] = "broken_loop"
    cs_bare.conf = base_conf

    with cs_bare:
        pass

    logs = capsys.readouterr().out
    assert len(re.findall(r'CRITICAL', logs)) == 1


def test_run_single_plugin(capsys, cs_bare, base_conf):
    cs_bare.args.plugin = "debug1"
    cs_bare.conf = base_conf

    with cs_bare:
        pass

    logs = capsys.readouterr().out
    print(logs)


def test_run_twice(capsys, cs_bare, base_conf):
    cs_bare.conf = base_conf

    with cs_bare:
        capsys.readouterr()

        with cs_bare:
            pass

        logs = capsys.readouterr().out
        print(logs)
        assert len(re.findall(re.escape("Pythapi is already running!"), logs)) == 1


def test_read_config_file(capsys, cs_bare, base_conf):
    cs_bare.args.config = "tests/configs/read_from_run.ini"
    cs_bare.conf = base_conf

    with cs_bare:
        pass

    logs = capsys.readouterr().out
    print(logs)
    assert len(re.findall(r'ERROR|CRITICAL', logs)) == 0


def test_import_broken_plugin(capsys, cs_bare, base_conf):
    base_conf['core.general']['enabled_plugins'] = "broken"
    cs_bare.conf = base_conf

    with cs_bare:
        pass

    logs = capsys.readouterr().out
    print(logs)
    assert len(re.findall(r'ERROR', logs)) == 1


def test_import_broken_declare_event(capsys, cs_bare, base_conf):
    base_conf['core.general']['enabled_plugins +'] = "broken_declare"
    cs_bare.conf = base_conf

    with cs_bare:
        pass

    logs = capsys.readouterr().out
    print(logs)
    assert len(re.findall(re.escape("error occured while executing core.declare from broken_declare".format(1)), logs)) == 1
    assert len(re.findall(re.escape("Restarting pythapi without broken plugins...".format(1)), logs)) == 1
    assert len(re.findall(r'ERROR', logs)) == 1


def test_import_broken_load_event(capsys, cs_bare, base_conf):
    base_conf['core.general']['enabled_plugins +'] = "broken_load"
    cs_bare.conf = base_conf

    with cs_bare:
        pass

    logs = capsys.readouterr().out
    print(logs)
    assert len(re.findall(re.escape("error occured while executing core.load from broken_load".format(1)), logs)) == 1
    assert len(re.findall(re.escape("Restarting pythapi without broken plugins...".format(1)), logs)) == 1
    assert len(re.findall(r'ERROR', logs)) == 1


def test_uninstall(capsys, cs_bare, base_conf):
    cs_bare.args.mode = "uninstall"
    cs_bare.conf = base_conf

    with cs_bare:
        pass

    logs = capsys.readouterr().out
    print(logs)

    assert len(re.findall(re.escape("Running core.uninstall from debug1"), logs)) == 1
    assert len(re.findall(re.escape("Running core.uninstall from debug2"), logs)) == 1
    assert len(re.findall(re.escape("Running core.uninstall from debug3"), logs)) == 1
    assert len(re.findall(r'ERROR', logs)) == 0


def test_install(capsys, cs_bare, base_conf):
    cs_bare.args.mode = "install"
    cs_bare.conf = base_conf

    with cs_bare:
        pass

    logs = capsys.readouterr().out
    print(logs)

    assert len(re.findall(re.escape("Triggering core.install event for debug{}...".format(1)), logs)) == 0
    assert len(re.findall(re.escape("Triggering core.install event for debug{}...".format(3)), logs)) == 0
    assert len(re.findall(r'ERROR', logs)) == 0


def test_unknown_runmode(capsys, cs_bare, base_conf):
    cs_bare.args.mode = "not_there"
    cs_bare.conf = base_conf

    with cs_bare:
        pass

    logs = capsys.readouterr().out
    print(logs)

    assert len(re.findall(re.escape("Unknown runmode! Supported modes: run, install, uninstall, reinstall"), logs)) == 1
    assert len(re.findall(r'ERROR', logs)) == 0


def test_import_broken_load_event_forced_essential(capsys, cs_bare, base_conf):
    base_conf['core.general']['enabled_plugins +'] = "broken_load"
    base_conf['broken_load'] = {'essential': 'true'}
    cs_bare.conf = base_conf

    with cs_bare:
        pass

    logs = capsys.readouterr().out
    print(logs)
    assert len(re.findall(re.escape("error occured while executing core.load from broken_load".format(1)), logs)) == 1
    assert len(re.findall(re.escape("broken_load is marked as essential".format(1)), logs)) == 1
    assert len(re.findall(r'CRITICAL', logs)) == 1


def test_external_func(cs_bare, base_conf):
    cs_bare.conf = base_conf

    with cs_bare:
        assert core.plugin_base.plugin_dict['debug1'].external_func() == 4
