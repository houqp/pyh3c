#!/usr/bin/env python
# -*- coding:utf-8 -*-

import ConfigParser
import os

import i18n

__author__ = "houqp"
__license__ = "GPL"
__version__ = "0.3.1"
__maintainer__ = "houqp"
__email__ = "qingping.hou@gmail.com"

_ = i18n.language.lgettext

class H3CSrvStatus():
    def __init__(self):
        self.dev = ""
        self.cli_hwadd = ""
        self.srv_hwadd = ""
        self.user_name = ""
        self.user_pass = ""
        self.debug_on = False
        self.kill_on = False
        self.parser = ConfigParser.SafeConfigParser()

    def load_config(self):
        """
        load configuration file
        """
        if not self.parser.read( ('/etc/pyh3c_srv.conf')):
            print ''
            print _('No configuration file found!')
            print _('Please answer following question to setup ')
            print _('     the configuration file: ')
            print ''
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
            self.new_plugins = self.parser.get('sys_conf', 'plugins')
            if self.new_plugins:
                self.plugins_to_load.extend( 
                        self.new_plugins.replace(' ','').split(',') 
                )
        except ConfigParser.NoOptionError:
            pass

    def create_config(self):
        """
        create or complete a configuration file and write to disk
        """
        if not self.dev:
            try:
                libdnet = __import__('dnet')
            except ImportError:
                libdnet = __import__('dumbnet')
            intf = libdnet.intf()
            def print_dev(dict, arg):
                if not dict['name'] == 'lo':
                    print ' * %s' % dict['name']
                return
            print _('Devices that you can choose are:')
            intf.loop(print_dev)
            print ''
            print _(' - Generally, eth0 is the right choice for GNU/Linux users.')
            print _(' - If you are using wireless network, than you may need')
            print _('   to choose wlan0 or something like that.')
            print ''
            self.dev = raw_input('Please input the device you want to use: ')
            print '------'

        if not self.user_name:
            self.user_name = raw_input('Please input the user name of your account: ')
            print '------'

        if not self.user_pass:
            self.user_pass = raw_input('Please input the password of your account: ')
            print '------'

        if not self.dhcp_command:
            self.dhcp_command = raw_input('Please input the command you use to acquire ip with DHCP: ')
            print '------'

        self.save_config()

    def save_config(self):
        """
        write current configuration to pyh3c_srv.conf
        """
        if not self.parser:
            self.parser = ConfigParser.SafeConfigParser()

        if not self.parser.has_section('sys_conf'):
            self.parser.add_section('sys_conf')
        if not self.parser.has_section('account'):
            self.parser.add_section('account')

        self.parser.set('sys_conf', 'dev', self.dev)
        self.parser.set('account', 'user_name', self.user_name)
        self.parser.set('account', 'user_pass', self.user_pass)
        
        #ConfigParser module will delete all comments, here is a dirty hack
        #@TODO@: fix the ConfigParser module, or use cfgparse module
        try:
            os.unlink('/etc/pyh3c_srv.conf')
        except OSError:
            pass
        fp = open('/etc/pyh3c_srv.conf', 'w')
        self.parser.write(fp)
        fp = fp.close()
        return 



