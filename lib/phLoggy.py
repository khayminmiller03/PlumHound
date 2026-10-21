#!/usr/bin/env python
# PlumHound (phLoggy.py) - Logging Function
# https://github.com/PlumHound/PlumHound
# License GNU GPL3

# Loggy Function for lazy debugging

import logging
import os


def Loggy(hurdle, level, notice):
    logger = logging.getLogger("PlumHound")
    if not notice:
        return
    if level >= 500:
        logger.debug(notice)
    else:
        logger.info(notice)

def setup_logging(verbosity, logfile="log/PlumHound.log"):
    logger = logging.getLogger("PlumHound")
    os.makedirs(os.path.dirname(logfile), exist_ok=True)

    # set level from verbosity
    if verbosity >= 500:
        logger.setLevel(logging.DEBUG)
    elif verbosity >= 100:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)

    # guard against duplicate handlers if called twice
    if not logger.handlers:
        fmt = logging.Formatter("%(asctime)s\t%(levelname)s\t%(message)s")

        console = logging.StreamHandler()
        console.setFormatter(fmt)
        logger.addHandler(console)

        filehandler = logging.FileHandler(logfile, encoding="utf-8")
        filehandler.setFormatter(fmt)
        logger.addHandler(filehandler)

    return logger
