# -*- coding:utf8 -*-
#!/usr/bin/env python

import ConfigParser
import dnet

__author__ = "houqp"
__license__ = "GPL"
__version__ = "0.2"
__maintainer__ = "houqp"
__email__ = "qingping.hou@gmail.com"
dev = ""
user_name = ""
user_pass = ""
dhcp_command = ""
auth_success = 0

def load_config():
  """
  load configuration file
  """
  parser = ConfigParser.SafeConfigParser()
  if not parser.read( ('pyh3c.conf')):
    print ""
    print " [!] No configuration file found!"
    print " [!] Please answer following question to setup "
    print "     the configuration file: "
    print ""
    create_config()
    return

  if not parser.has_section('sys_conf'):
    create_config()

  try:
    globals()['dev'] = parser.get('sys_conf', 'dev')
  except ConfigParser.NoOptionError:
    globals()['dev'] = ""
    create_config()

  try:
    globals()['dhcp_command'] = parser.get('sys_conf', 'dhcp_script')
  except ConfigParser.NoOptionError:
    try:
      globals()['dhcp_command'] = parser.get('sys_conf', 'dhcp_command')
    except ConfigParser.NoOptionError:
      globals()['dhcp_command'] = ""
      create_config()

  try:
    globals()['user_name'] = parser.get('account', 'user_name')
  except ConfigParser.NoOptionError:
    globals()['user_name'] = ""
    create_config()

  try:
    globals()['user_pass'] = parser.get('account', 'user_pass')
  except ConfigParser.NoOptionError:
    globals()['user_pass'] = ""
    create_config()

  return

def create_config():
  """
  create a configuration file and write to disk
  """
  if not dev:
    intf = dnet.intf()
    def print_dev(dict, arg):
      if not dict['name'] == 'lo':
        print " * %s" % dict['name']
      return
    print "Devices that you can choose are:"
    intf.loop(print_dev)
    print ""
    print " - Most of the time, eth0 is the correct choice."
    print " - If you are using wireless network, than you may need"
    print "   to choose wlan0 or something like that."
    print ""
    globals()['dev'] = raw_input('Please input the device you want to use: ')

  if not user_name:
    globals()['user_name'] = raw_input('Please input the user name of your account: ')

  if not user_pass:
    globals()['user_pass'] = raw_input('Please input the password of your account: ')

  if not dhcp_command:
    globals()['dhcp_command'] = raw_input('Please input the command you use to acquire ip with DHCP: ')
  
  save_config()
  return 

def save_config(parser=None, fp=None):
  """
  write current configuration to pyh3c.conf
  """
  if not parser:
    parser = ConfigParser.SafeConfigParser()

  if not fp:
    try:
      fp = open('pyh3c.conf', 'r+')
    except IOError:
      fp = open('pyh3c.conf', 'w')

  if not parser.has_section('sys_conf'):
    parser.add_section('sys_conf')
  if not parser.has_section('account'):
    parser.add_section('account')

  parser.set('sys_conf', 'dev', dev)
  parser.set('sys_conf', 'dhcp_command', dhcp_command)
  parser.set('account', 'user_name', user_name)
  parser.set('account', 'user_pass', user_pass)
  
  parser.write(fp)
  fp = fp.close()
  return 

