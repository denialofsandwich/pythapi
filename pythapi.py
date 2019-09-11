#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import signal
import argparse

import core.main

if __name__ == "__main__":
    signal.signal(signal.SIGINT, core.main.termination_handler)
    signal.signal(signal.SIGTERM, core.main.termination_handler)

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode",
        default="run",
        nargs="?",
        choices=["run", "install", "uninstall"],
        help="Specifies the run-mode",
    )
    parser.add_argument(
        "plugin", nargs="?", help="Specify a plugin to install/uninstall"
    )
    parser.add_argument("--verbosity", "-v", type=int, help="Sets the verbosity")
    parser.add_argument(
        "--reinstall",
        "-r",
        action="store_true",
        help="Uninstalls a plugin before installing it",
    )
    parser.add_argument(
        "--no-fancy",
        "-n",
        action="store_true",
        help="Disables the colorful logs and shows a more machine-readable logging format",
    )
    parser.add_argument("--config", "-c", default=[], action="append", help="Add config-file")
    parser.add_argument(
        "--config-parameter",
        "-p",
        default=[],
        action="append",
        help="Add config-parameter eg. (web.http_port=8123)",
    )

    args = parser.parse_args()

    core.main.run(args)
