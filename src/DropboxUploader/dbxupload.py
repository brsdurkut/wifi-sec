#!/usr/bin/python
import logging
import dropbox
import argparse
import os, sys
import traceback

PATHS = []
ACCESS_TOKEN = "@cc355t0k3n"
REMOTE_DIR = "/uploaded/"
FOLDER = None

def init(token=ACCESS_TOKEN):
	""" 
	return dropbox.client.DropboxClient object
	Initializes connection between client and Dropbox
	"""

	try:
		logging.debug(
			'Connecting to Dropbox with access token: {0}'.format(
				token))
		client = dropbox.client.DropboxClient(token)
		check_result = client.account_info()
		logging.debug(check_result)
	except Exception:
		raise
	else:
		logging.debug('Connection has been established.')
		return client

def upload(client, paths, remotedir=REMOTE_DIR):
	"""
	Uploads given files with full path
	"""
	success = []
	append = success.append
	for path in paths:
		if not os.path.isfile(path):
			continue
		try:
			filename = path.rsplit('/', 1)[-1]
			f = open(path, 'r')
			logging.debug(
				'{0} is being uploaded to {1}'.format(path, remotedir))
			result = client.put_file(
				'{0}{1}'.format(remotedir, filename),
				f,
				True)
			append(result)
		except Exception as err:
			raise
	return success

def paths_from_folder(folder):
	"""
	return filepaths in folder
	"""
	folder += '' if folder[-1] == '/' else '/'
	if not os.path.isdir(folder):
		raise Exception('Given path is not a directory!')
	try:
		filepaths = [''.join((folder, filename)) for filename in os.listdir(folder)]
		return filepaths
	except:
		raise
