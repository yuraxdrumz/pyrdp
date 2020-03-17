#!/usr/bin/env python3

#
# This file is part of the PyRDP project.
# Copyright (C) 2018, 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import asyncio
from twisted.internet import asyncioreactor
asyncioreactor.install(asyncio.get_event_loop())

import argparse
import logging
import logging.handlers
import sys
import os

from PySide2.QtWidgets import QApplication

from pyrdp.logging import LOGGER_NAMES, NotifyHandler, configure as configureLoggers
from pyrdp.player import MainWindow
from pyrdp.player.config import DEFAULTS
from pyrdp.core import settings

LOG = logging.getLogger(LOGGER_NAMES.PYRDP)


def enableNotifications():
    """Enable notifications if supported."""
    # https://docs.python.org/3/library/os.html
    if os.name != "nt":
        notifyHandler = NotifyHandler()
        notifyHandler.setFormatter(logging.Formatter("[{asctime}] - {message}", style = "{"))

        uiLogger = logging.getLogger(LOGGER_NAMES.PLAYER_UI)
        uiLogger.addHandler(notifyHandler)
    else:
        LOG.warning("Notifications are not supported on this platform.")


def main():
    """
    Parse the provided command line arguments and launch the GUI.
    :return: The app exit code (0 for normal exit, non-zero for errors)
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("replay", help="Replay files to open on launch (optional)", nargs="*")
    parser.add_argument("-b", "--bind", help="Bind address (default: 127.0.0.1)", default="127.0.0.1")
    parser.add_argument("-p", "--port", help="Bind port (default: 3000)", default=3000)
    parser.add_argument("-o", "--output", help="Output folder", default=None)
    parser.add_argument("-L", "--log-level", help="Log level", default=None, choices=["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"], nargs="?")
    parser.add_argument("-F", "--log-filter", help="Only show logs from this logger name (accepts '*' wildcards)", default=None)
    args = parser.parse_args()

    cfg = settings.load(f'{settings.CONFIG_DIR}/player.ini', DEFAULTS)

    # Modify configuration with switches.
    if args.log_level:
        cfg.set('vars', 'level', args.log_level)
    if args.log_filter:
        cfg.set('logs', 'filter', args.log_filter)
    if args.output:
        cfg.set('vars', 'output_dir', args.output)

    configureLoggers(cfg)
    if cfg.getboolean('logs', 'notifications', fallback=False):
        enableNotifications()

    app = QApplication(sys.argv)
    mainWindow = MainWindow(args.bind, int(args.port), args.replay)
    mainWindow.show()

    return app.exec_()


if __name__ == '__main__':
    sys.exit(main())
