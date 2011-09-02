# -*- coding:utf8 -*-
#!/usr/bin/env python

import ConfigParser
import dnet

__author__ = "houqp"
__license__ = "GPL"
__version__ = "0.2"
__maintainer__ = "houqp"
__email__ = "qingping.hou@gmail.com"


class H3C_STATUS():
  def __init__(self):
    self.dev = ""
    self.hwadd = ""
    self.user_name = ""
    self.user_pass = ""
    self.dhcp_command = ""
    self.ping_target = ""
    self.ping_interval = 1
    self.plugins = []
    self.plugins_to_load = ['keepalive']

    self.auth_success = 0
    self.parser = ConfigParser.SafeConfigParser()

  def load_config(self):
    """
    load configuration file
    """
    if not self.parser.read( ('pyh3c.conf')):
      print ""
      print " [!] No configuration file found!"
      print " [!] Please answer following question to setup "
      print "     the configuration file: "
      print ""
      self.create_config()
      return

    if not self.parser.has_section('sys_conf'):
      self.create_config()
    if not self.parser.has_section('account'):
      self.create_config()

    try:
      self.dev = self.parser.get('sys_conf', 'dev')
    except ConfigParser.NoOptionError:
      self.dev = ""
      self.create_config()

    try:
      self.dhcp_command = self.parser.get('sys_conf', 'dhcp_script')
    except ConfigParser.NoOptionError:
      try:
        self.dhcp_command = self.parser.get('sys_conf', 'dhcp_command')
      except ConfigParser.NoOptionError:
        self.dhcp_command = ""
        self.create_config()

    try:
      self.user_name = self.parser.get('account', 'user_name')
    except ConfigParser.NoOptionError:
      self.user_name = ""
      self.create_config()

    try:
      self.user_pass = self.parser.get('account', 'user_pass')
    except ConfigParser.NoOptionError:
      self.user_pass = ""
      self.create_config()

    try:
      self.ping_target = self.parser.get('sys_conf', 'ping_target')
    except ConfigParser.NoOptionError:
      self.ping_target = ""
      self.create_config()

    try:
      self.new_plugins = self.parser.get('sys_conf', 'plugins')
      self.plugins_to_load.extend( \
          self.new_plugins.replace(' ','').split(',') \
      )
      print self.plugins_to_load
    except ConfigParser.NoOptionError:
      pass
    self.plugins = __import__('plugins', globals(), locals(), self.plugins_to_load)

    return 

  def create_config(self):
    """
    create a configuration file and write to disk
    """
    if not self.dev:
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
      self.dev = raw_input('Please input the device you want to use: ')
      print "------"

    if not self.user_name:
      self.user_name = raw_input('Please input the user name of your account: ')
      print "------"

    if not self.user_pass:
      self.user_pass = raw_input('Please input the password of your account: ')
      print "------"

    if not self.dhcp_command:
      self.dhcp_command = raw_input('Please input the command you use to acquire ip with DHCP: ')
      print "------"
    
    if not self.ping_target:
      print "To disable online status checking, just type \"none\"."
      self.ping_target = raw_input('Please input the target ip you want to ping for online checking: ')
      print "------"

    self.save_config()
    return 

  def save_config(self):
    """
    write current configuration to pyh3c.conf
    """
    if not self.parser:
      self.parser = ConfigParser.SafeConfigParser()

    try:
      fp = open('pyh3c.conf', 'r+')
    except IOError:
      fp = open('pyh3c.conf', 'w')

    if not self.parser.has_section('sys_conf'):
      self.parser.add_section('sys_conf')
    if not self.parser.has_section('account'):
      self.parser.add_section('account')

    self.parser.set('sys_conf', 'dev', self.dev)
    self.parser.set('sys_conf', 'dhcp_command', self.dhcp_command)
    self.parser.set('sys_conf', 'ping_target', self.ping_target)
    self.parser.set('account', 'user_name', self.user_name)
    self.parser.set('account', 'user_pass', self.user_pass)
    
    self.parser.write(fp)
    fp = fp.close()
    return 



