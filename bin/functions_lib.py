#!/usr/bin/python
from datetime import datetime,  timedelta
import sys, ihooks

def format_date_pack():
    lastHourDateTime = datetime.today() - timedelta(hours = 1)
    return lastHourDateTime.strftime('%Y%m%dT%H%M')


def import_from(name):
    loader = ihooks.BasicModuleLoader()
    m = loader.find_module(name, sys.path)
    if not m:
        raise ImportError, name
    m = loader.load_module(name, m)
    return m
