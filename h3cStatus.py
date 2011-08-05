# -*- coding:utf8 -*-
#!/usr/bin/env python

import ConfigParser

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
  parser.read('pyh3c.conf')
  globals()['dev'] = parser.get('sys_conf', 'dev')
  globals()['dhcp_script'] = parser.get('sys_conf', 'dhcp_script')
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

