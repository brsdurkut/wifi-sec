# -*- coding: utf-8 -*-
import logging
import traceback

import helpers


class Items(object):
    """
    creates and arranges target list with given data
    """
    def __init__(self):
        self._itemlist = []

    def get_available_targets(self):
        """
        returns AP's that have clients
        {
         'bssid': bssid,
         'ssid': ssid,
         'channel': channel
         'target': list of client addresses
        }
        """
        try:
            has_clients = [item for item in self._itemlist if 'clients' in item]

            if len(has_clients) is 0:
                return []

            targetlist = []
            append = targetlist.append

            for item in has_clients:
                i = {
                        'bssid': item['bssid'],
                        'ssid': item['ssid'],
                        'channel': item['channel'],
                        'target': []
                    }
                
                i['target'] = [ client['addr'] for client in item['clients'] ]
                append(i)
        except:
            raise
        return targetlist

    def get_item(self, key, valuelist, returnkeys):
        """
        arguments:
            key        - find by 'key' in itemlist
            valuelist    - find using keylist by 'key' in itemlist
            returnkeys - return 'returnkeys' from found list
        """
        itemlist = []
        try:
            for item in self._itemlist:
                if item[key] in valuelist:
                    append(item)
            itemlist = [item for item in self._itemlist if item[key] in valuelist]
            if len(itemlist) is 0:
                return []

            foundlist = []
            append = foundlist.append
            for item in itemlist:
                i = {}
                for key in returnkeys:
                    i[key] = item[key]
                append(i)
        except:
            raise
        else:
            return foundlist

    def get_items(self, *keys):
        try:
            itemlist = []
            append = itemlist.append
            if len(keys) is 0:
                itemlist = self._itemlist
            else:
                for item in self._itemlist:
                    if 'captured' in keys and 'captured' not in item:
                            continue

                    i = {}
                    for key in keys:
                        if key == 'clients' and 'clients' not in item:
                            i['clients'] = 'No client'
                            continue

                        i[key] = item[key]

                    append(i)
        except:
            raise
        else:
            return itemlist

    def limit_ap(self, limit):
        if limit is not 0 and len(self._itemlist) >= limit:
            raise Exception('APLimit')
        return False

    def find_ap(self, **kwargs):
        try:
            if 0 < len(kwargs) > 1:
                raise KeyError('Too much arguments!')

            key, value = kwargs.items()[0]
            for i, item in enumerate(self._itemlist):
                if (key in item and 
                    value == item[key]):
                    return i
        except:
            logging.error(traceback.format_exc())
            raise
        return None 

    def update_ap(self, index, item):
        try:
            for k, v in self._itemlist.items():
                if v != item[k]:
                    self._itemlist[k] = item[k]
        except:
            logging.error(traceback.format_exc())
            raise
        return True 

    def add_ap(self, items, **kwargs):
        try:
            if len(items) is 0:
                return True

            enc = kwargs['encryption']
            signal = kwargs['signal']
            limit = kwargs['limit']
            exception = kwargs['exception']

            self._itemlist = []
            append = self._itemlist.append
            for item in items:

                if item['bssid'] in exception:
                    continue

                if item['encryption'].startswith('WPA'):
                    item['encryption'] = 'WPA'
                elif item['encryption'].startswith('WEP'):
                    item['encryption'] = 'WEP'
                elif item['encryption'].startswith('OPN'):
                    item['encryption'] = 'OPEN'

                if item['encryption'] not in enc:
                    continue
                
                if item['signal'] < signal:
                    continue

                found = self.find_ap(bssid=item['bssid'])
                if found is None:
                    new_item = helpers.correct_ssid(item, self._itemlist)
                    append(new_item)

                self.limit_ap(limit)
        except:
            raise
        return True

    def add_client(self, items, **kwargs):
        try:
            if len(items) is 0:
                return True

            signal = kwargs['signal']
            limit = kwargs['limit']
            exception = kwargs['exception']

            clientlist = []
            append = clientlist.append

            for item in items:

                if item['client'] in exception:
                    continue

                if item['signal'] < signal:
                    continue

                found = self.find_ap(bssid=item['bssid'])
                if found is None:
                    continue
                
                if 'clients' not in self._itemlist[found]:
                    self._itemlist[found]['clients'] = []

                append({'addr': item['client'], 'signal': item['signal']})
                self._itemlist[found]['clients'] = clientlist
        except:
            raise
        return True

    def add_capture(self, bssid_, path):
        """
        adds path of capture file to list
        """
        try:
            found = self.find_ap(bssid=bssid_)
            self._itemlist[found]['captured'] = path
            
        except:
            raise
        return True