# -*- coding: utf-8 -*-
import logging
import csv
from subprocess import Popen, PIPE, STDOUT
import shlex
import traceback
from datetime import datetime
import os
import shutil
from multiprocessing import Process

import DropboxUploader.dbxupload as uploader


def move_capturefiles(items, folder_capture, dbx=None):
    """
    moves handshake captured files to another directory(e.g 'captured/')
    if upload choice is active, it uploads capture files to remote dir.
    """
    try:
        if not os.path.isdir(folder_capture):
            raise Exception(
                "'{}' does not exist!".format(folder_capture))

        paths = [ path['captured'] for path in items]
        copy = shutil.copy2
        for path in paths:
            filename = path.rsplit('/', 1)[-1]
            copy(
                path, 
                "".join(
                    (folder_capture, filename)))

        def upload_start(**kwargs):
            try:
                client = uploader.init(kwargs['access_token'])
                success = uploader.upload(
                    client, 
                    kwargs['paths_'], 
                    kwargs['dir_remote'])

                logging.debug(
                    "Dropbox API return: {}".format(success))
            except:
                raise
            
            return True

        if dbx:
            filenames = [ path.rsplit('/', 1)[-1] for path in paths ]
            logging.debug(
                "'{}' files has being uploaded with these data: {}".format(
                    filenames, [dbx.dir_remote, dbx.access_token]))

            p = Process(target=upload_start, 
                        kwargs={'access_token':dbx.access_token,
                                'paths_':paths,
                                'dir_remote':dbx.dir_remote
                                })
            p.start()

    except:
        raise
    else:
        return True

def correct_ssid(data, itemlist):
    """ 
    return clean string
    avoid filename conflicts and special characters
    """
    try:
        stripped = ''.join(c for c in data['ssid'] if c.isalnum())
        
        count = 0
        for item in itemlist:
            if (item['ssid'].startswith(stripped) and
                item['bssid'] != data['bssid']):
                count += 1

        ssid = stripped+"({0})".format(count+1) if count > 0 else stripped
        
        data['ssid'] = ssid
    except:
        raise

    return data

def find_fullpath(**kwargs):
    """
    finds and returns full file path of given partially filename
    """
    try:
        paths = []
        append = paths.append
        if 'startswith' in kwargs:
            path = kwargs['startswith']
            if (path.rsplit('/', 1)[-1] != '' and
                is_exist(folder=path.rsplit('/', 1)[0] is False)):
                raise KeyError("Folder is not exist in path!")
            filename = path.rsplit('/', 1)[1]
            folder = path.rsplit('/', 1)[0]
            allfiles = os.listdir(folder)
            for file in allfiles:
                if (file.startswith(filename) and 
                    os.path.isfile('/'.join((folder, file)))):
                    append('/'.join((folder, file)))

        if 'endswith' in kwargs:
            end = kwargs['endswith']
            return [path for path in paths if path.endswith(end)]
    except:
        raise
    return paths

def is_exist(**kwargs):
    """
    checks given path if it is file or directory
    """
    try:
        if 'file' in kwargs:
            if os.path.isfile(str(kwargs['file'])):
                return os.stat(kwargs['file']).st_size
        elif 'folder' in  kwargs:
            if os.path.isdir(str(kwargs['folder'])):
                return True
        else:
            raise KeyError('Invalid argument!')
    except:
        raise
    return False

def get_dumpfilename(ssid):
    return '{}-{}'.format(ssid, get_date())

def get_fullpath(folderpath, ssid=None):
    """
    returns a created filename with present time extension
    """
    path = folderpath if folderpath[-1] == '/' else ''.join((folderpath, '/'))
    if os.path.isdir(path) is False:
        raise KeyError(
            "Given folder path is not exist! '{}'".format(path))
    path += get_date() if ssid is None else get_dumpfilename(ssid)

    return path

def get_date():
    """
    return string
    Gets present time, makes filename without extension
    """
    now = datetime.now()
    return now.strftime("%y%m%d%H%M")

def verify(path):
    """
    verifies capture file if it has necessary handshake packets
    """
    cmd = 'cowpatty -c -r {}'.format(path)

    command = shlex.split(cmd)
    try:
        proc = Popen(command, 
            stdout=PIPE, 
            stderr=STDOUT,)
        proc.wait()
        if proc.returncode > 0:
            stdout = proc.communicate()[0]
            if stdout.find('incomplete four-way handshake') < 0:
                raise Exception(stdout)
            return False
    except:
        raise
    else:
        return True

def get_latestfilename(path):
    """
    finds and returns full file path of given partially filename
    Finds latest created or with given name file in directory 
    e.g. path='/dir/' or path='/dir/apname..'
    """
    def check_datetime(files):
        strptime = datetime.strptime
        format_ = "%y%m%d%H%M"
        for file in filelist:
            try:
                tmp = strptime(file, format_)
            except Exception as err:
                if(err.message.find('not match format') >= 0):
                    continue
                raise
            else:
                return file
        return None

    try:
        parse = path.rsplit('/', 1)
        if parse[-1] == '':
            if not os.path.isdir(path):
                raise Exception('Invalid directory path!')
            filelist = sorted(
                [ s.rsplit('-', 1)[0] for s in os.listdir(path) ], 
                reverse=True)

            latestfile = check_datetime(filelist)
            if latestfile is not None:
                return "{}/{}".format(
                            parse[0], 
                            latestfile)

        else:
            listdir = sorted(os.listdir(parse[0]), reverse=True)
            filelist = []
            append = filelist.append
            for file in listdir:
                if (os.path.isfile('{0}/{1}'.format(parse[0], file)) and 
                    file.startswith(parse[-1])):
                    append(file.rsplit('-')[1])

            latestfile = check_datetime(filelist)
        if latestfile is not None:
            return "{}/{}".format(
                            parse[0], 
                            latestfile)
        
        raise Exception("There is no valid csv file to resume!")
    except:
        raise

def parse_csv(path, type_):
    """
    returns parsed AP or client list from airodump-ng exported data
    """
    result = []
    try:
        if type_ == 'AP':
            startwith = 'BSSID'
        elif type_ == 'CLIENT':
            startwith = 'Station MAC'
        else:
            raise Exception(
                'Unknown type call for parsing: {}'.format(type_))
        with open(path) as f:
            f_csv = csv.reader(f)
            while True:
                row = next(f_csv)
                if row == []:
                    continue
                elif row[0].startswith(startwith):
                    break
            append = result.append
            for row in f_csv:
                if len(row) is 0:
                    return result
                if type_ == 'AP':
                    append({
                            'bssid': row[0].strip(),
                            'channel': row[3].strip(),
                            'encryption': row[5].strip(),
                            'signal': (100+int(row[8].strip())),
                            'ssid': row[13].strip() 
                            })
                elif type_ == 'CLIENT':
                    append({
                            'bssid': row[5].strip(),
                            'client': row[0].strip(),
                            'signal': (100+int(row[3].strip()))
                            })
    except:
        raise
    finally:
        return result

def get_settings(path):
    """
    returns created settings classes from given config file
    """
    try:
        import yaml
        class Setting(object):
            def __init__(self, raw):
                for key, value in raw.items():
                    if self.has_next(value) is True:
                        new_class = type(key, (), {})
                        for k, v in value.items():
                            if not isinstance(v, dict):
                                continue
                            clss = type(k, (), v)
                            setattr(new_class, k, clss)
                    else:
                        new_class = type(key, (), value)
                    setattr(self, key, new_class)

            def has_next(self, values):
                try:
                    for key, value in values.items():
                        if isinstance(value, dict) and len(value) > 1:
                            return True
                    return False
                except:
                    raise

        stream = file(path, 'r')
        raw = yaml.load(stream)

        return Setting(raw)
    except:
        raise