#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest
import core.fancy_logs
import os
import re


def test_print_text(capsys):
    message = "Test text"
    log = core.fancy_logs.FancyLogger(True, 6, False, False, "")

    logging_table = {
        "DEBUG": log.debug,
        "INFO": log.info,
        "ACCESS": log.access,
        "SUCCESS": log.success,
        "WARNING": log.warning,
        "ERROR": log.error,
        "CRITICAL": log.critical,
    }

    for level, func in logging_table.items():
        func(message)
        assert capsys.readouterr().out == "{} {}\033[0m\n".format(
            core.fancy_logs.color_codes[level].format(level, ''),
            message
        )

    log.set_fancy(False)
    for level, func in logging_table.items():
        func(message)
        assert capsys.readouterr().out == "{} {}\n".format(
            level,
            message
        )


def test_indentation(capsys):
    message = "Test text"
    log = core.fancy_logs.FancyLogger(True, 6, False, False, "")

    indentation = 0
    for i in [0, 2, -1, -2]:
        indentation += i

        if indentation < 0:
            indentation = 0

        log.indent(i)
        log.debug(message)
        assert capsys.readouterr().out == "{} {}\033[0m\n".format(
            core.fancy_logs.color_codes["DEBUG"].format("DEBUG", ' .'*indentation),
            message
        )

    log.set_fancy(False)
    log.indent(3)
    log.debug(message)
    assert capsys.readouterr().out == "{} {}\n".format(
        "DEBUG",
        message
    )


def test_file_logging():
    filename = "test_log.log"
    log = core.fancy_logs.FancyLogger(True, 6, False, True, filename)

    log.debug("File!")

    assert os.path.isfile(filename) is True

    os.remove(filename)


def test_interposer():
    check = False

    def i_interposer(record, self):
        nonlocal check
        check = True

    log = core.fancy_logs.FancyLogger(True, 6, False, False, "")
    log.add_interposer(i_interposer)

    log.debug("Test interposer")
    assert check is True


def test_interposer_interrupt():
    def i_interposer(record, self):
        raise KeyboardInterrupt()

    log = core.fancy_logs.FancyLogger(True, 6, False, False, "")
    log.add_interposer(i_interposer)

    with pytest.raises(KeyboardInterrupt):
        log.debug("Test interposer")


def test_loglevel_cap():
    log = core.fancy_logs.FancyLogger(True, 6, False, False, "")
    log.set_loglevel(8)
    assert log.loglevel == 6


def test_timestamp(capsys):
    message = "Test text"
    log = core.fancy_logs.FancyLogger(False, 6, True, False, "")

    log.debug("Test Message")

    logs = capsys.readouterr().out
    print(logs)

    assert len(re.findall('[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]{3}', logs)) == 1
