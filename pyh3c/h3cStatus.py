# -*- coding:utf8 -*-
#!/usr/bin/env python

import ConfigParser

__author__ = "houqp"
__license__ = "GPL"
__version__ = "0.1"
__maintainer__ = "houqp"
__email__ = "qingping.hou@gmail.com"

dev = 'eth0'
user_name = ""
user_pass = ""
dhcp_script = ""
auth_success = 0

def load_config():
  """
  load configuration file
  """
  parser = ConfigParser.SafeConfigParser()
  if not parser.read( ('pyh3c.conf', '../pyh3c.conf')):
    print " [!] Open configuration file failed!"
    exit(0)
  globals()['dev'] = parser.get('sys_conf', 'dev')
  try:
    globals()['dhcp_command'] = parser.get('sys_conf', 'dhcp_script')
  except ConfigParser.NoOptionError:
    globals()['dhcp_command'] = parser.get('sys_conf', 'dhcp_command')
  globals()['user_name'] = parser.get('account', 'user_name')
  globals()['user_pass'] = parser.get('account', 'user_pass')

def create_config():
  """
  create a configuration file and write to disk
  """
  pass

def create_config():
  """
  write current configuration to pyh3c.conf
  """
  pass

