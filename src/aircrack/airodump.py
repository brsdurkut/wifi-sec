# -*- coding: utf-8 -*-
import logging
import traceback
from subprocess import Popen, PIPE, STDOUT
import shlex
from time import sleep
import os
import signal
from multiprocessing import Process
from pydispatch import dispatcher

import src.helpers as helpers
import src.items as items


SIGNAL_BSSID = 0
SIGNAL_CAPTURED = 1

class Airodump(object):
    """
    Executes airodump-ng commands for mapping nearby AP's
    Tries to capture handshake
    """
    def __init__(self, items, dumps):
        self.items = items
        self._dumps = dumps
        logging.debug("Airodump has been set.")

    def capture(self,
                timeout,
                interface_):
        """
        Monitors to check if handshake is captured
        starts airodump-ng process
        parses exported data from airodump-ng and
        verifies capture file
        """
        try:
            targetlist = self.items.get_available_targets()
            
            signal.signal(signal.SIGALRM, self.signal_handler)

            for target in targetlist:
                dumpfile = helpers.get_fullpath(self._dumps, target['ssid'])

                sleep(0.1)
                self.scan(
                    path=dumpfile,
                    format='cap',
                    bssid=target['bssid'],
                    channel=target['channel'],
                    interface=interface_)

                dispatcher.send(
                    sign=SIGNAL_BSSID,
                    sender="Airodump",
                    target_=target,
                    interface_=interface_)

                signal.alarm(timeout)

                try:
                    while True:
                        sleep(0.1)

                        fullpath = helpers.find_fullpath(
                            startswith=dumpfile, endswith='cap')
                        logging.debug(fullpath)
                        if len(fullpath) is 0:
                            continue

                        fullpath = fullpath[0]

                        exist = helpers.is_exist(file=fullpath)
                        if exist is False or exist == 0:
                            logging.debug(
                                "'{}' has not been created yet "
                                "or the file is empty".format(fullpath))
                            continue

                        verified = helpers.verify(fullpath)

                        if verified is True:
                            self.items.add_capture(
                                bssid_=target['bssid'],
                                path=fullpath)
                            break
                        sleep(1)

                except Exception as err:
                    if err.message == 'Timeout':
                        logging.debug('Time is up for scanning nearby AP\'s')
                    elif err.message == 'APLimit':
                        logging.debug(
                            "Count of AP's has been reached maximum value.")
                    else:
                        raise
                finally:
                    signal.alarm(0)

        except:
            raise
        finally:
            dispatcher.send(
                        sign=SIGNAL_CAPTURED,
                        sender="Airodump")

        return self.items.get_items('ssid', 'captured')

    def discover_client(self, 
                        timeout, 
                        limit,
                        signal_,
                        exception,
                        interface_,
                        resume=False):
        """
        Monitors to find clients for a spesific AP
        starts airodump-ng process
        parses exported data from airodump-ng and
        sends data to items class to create a target client list
        """
        try:
            targetlist = self.items.get_items('bssid', 'ssid', 'channel')

            signal.signal(signal.SIGALRM, self.signal_handler)

            for target in targetlist:
                dumpfile = helpers.get_fullpath(self._dumps, target['ssid'])
                
                sleep(0.1)
                self.scan(
                    path=dumpfile, 
                    format='csv', 
                    bssid=target['bssid'],
                    channel=target['channel'],
                    interface=interface_)

                signal.alarm(timeout)
                try:
                    while True:
                        sleep(0.1)

                        fullpath = helpers.find_fullpath(
                            startswith=dumpfile, endswith='csv')

                        if len(fullpath) is 0:
                            continue

                        fullpath = fullpath[0]

                        exist = helpers.is_exist(file=fullpath)
                        if exist is False or exist == 0:
                            logging.debug(
                                "'{}' has not been created yet "
                                "or the file is empty".format(fullpath))
                            continue

                        parsed = helpers.parse_csv(
                            path= fullpath,
                            type_= 'CLIENT')

                        self.items.add_client(
                            items=parsed,
                            signal=signal_,
                            limit=limit,
                            exception=exception)

                except KeyboardInterrupt:
                    logging.debug(
                        "Keyboard Interrupt. Skipping this target..")
                except Exception as err:
                    if err.message == 'Timeout':
                        logging.debug('Time is up for scanning nearby AP\'s')
                    elif err.message == 'APLimit':
                        logging.debug(
                            "Count of AP's has been reached maximum value.")
                    else:
                        raise
                finally:
                    signal.alarm(0)
        except:
            raise
        return self.items.get_items('ssid', 'clients')

    def discover_ap(self, 
                    timeout, 
                    limit,
                    signal_,
                    encryption_,
                    exception,
                    interface_,
                    resume=False):
        """
        Monitors to find nearby access points
        starts airodump-ng process
        parses exported data from airodump-ng and
        sends data to items class to create a target list
        """
        try:
            dumpfile = helpers.get_fullpath(self._dumps)
            logging.debug(
                'Dump file path has been picked: {}'.format(dumpfile))

            signal.signal(signal.SIGALRM, self.signal_handler)

            self.scan(
                path=dumpfile,
                format='csv',
                interface=interface_)

            signal.alarm(timeout)

            try:
                while True:
                    sleep(0.1)

                    fullpath = helpers.find_fullpath(
                        startswith=dumpfile, endswith='csv')

                    if len(fullpath) is 0:
                        continue

                    fullpath = fullpath[0]

                    exist = helpers.is_exist(file=fullpath)
                    if exist is False or exist == 0:
                        logging.debug(
                            "'{}' has not been created yet "
                            "or the file is empty".format(fullpath))
                        continue

                    parsed = helpers.parse_csv(
                        path= fullpath,
                        type_= 'AP')

                    self.items.add_ap(
                        items=parsed,
                        encryption=encryption_,
                        signal=signal_,
                        limit=limit,
                        exception=exception)

            except KeyboardInterrupt:
                logging.debug(
                    "Keyboard Interrupt. Skipping this process..")
            except Exception as err:
                if err.message == 'Timeout':
                    logging.debug('Time is up for scanning nearby AP\'s')
                elif err.message == 'APLimit':
                    logging.debug(
                        "Count of AP's has been reached maximum value.")
                else:
                    raise
            finally:
                signal.alarm(0)

        except:
            raise

        return self.items.get_items('bssid', 'ssid')

    def scan(self, **kwargs):
        """
        !!!
        """
        def start_process(**kwargs):
            cmd = 'airodump-ng --write-interval 1'
        
            cmd += ' '.join(
                (' --write', kwargs['path'])) if 'path' in kwargs else ''

            cmd += ' '.join(
                (' --output-format', kwargs['format'])) if 'format' in kwargs else ''

            cmd += ' '.join(
                (' --bssid', kwargs['bssid'])) if 'bssid' in kwargs else ''

            cmd += ' '.join(
                (' --channel', kwargs['channel'])) if 'channel' in kwargs else ''

            cmd += ''.join(
                (' ', kwargs['interface'])) if 'interface' in kwargs else ''

            logging.debug(
                "Command is being executed: '{}'".format(cmd))
            command = shlex.split(cmd)
            try:
                Popen(command, 
                    stdout=PIPE,
                    stderr=STDOUT,)
                sleep(0.1)
            except:
                raise
            else:
                return True

        try:
            self.scan_stop()

            p = Process(target=start_process, kwargs=kwargs)
            p.start()
        except:
            raise

        return True

    def scan_stop(self, timeout=5):
        """
        stops any active 'aireplay-ng' attacks
        """
        try:
            signal.signal(signal.SIGALRM, self.signal_handler)

            signal.alarm(timeout)

            try:
                while True:
                    active = self.is_active()
                    if active is False:
                        break

                    self.terminate(pids=active)

                    sleep(0.5)
            except Exception as err:
                if err.message == 'Timeout':
                    logging.debug(
                        "Previous 'airodump-ng' execution "
                        "has not been terminated!")
                raise
            except:
                raise
            finally:
                signal.alarm(0)
        except:
            raise

        return True

    def is_active(self):
        """
        returns process id list of running airodump-ng processes
        """
        cmd = 'pidof airodump-ng'

        logging.debug(
            "Command is being executed: '{}'".format(cmd))
        command = shlex.split(cmd)
        try:
            proc = Popen(command, 
                stdout=PIPE, 
                stderr=STDOUT,)
            proc.wait()

            if proc.returncode is 0:
                pids = proc.communicate()[0].split(' ')
                return [ int(pid) for pid in pids ]
        except:
            raise

        return False

    def terminate(self, pids):
        """
        Sends SIGTERM to given processes
        """
        try:
            logging.debug(
                "SIGTERM has being sent for processes: {}".format(pids))
            for pid in pids:
                os.kill(pid, signal.SIGTERM)
        except:
            raise

        return False


    def signal_handler(self, signum, frame):
        """
        handles signal if any Timeout signal comes.
        """
        if signum == signal.SIGALRM:
            logging.debug('Timeout signal has been sent.')
            raise Exception('Timeout')
