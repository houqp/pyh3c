#!/usr/bin/env python
# -*- coding:utf-8 -*-

import pcap
import binascii
import commands
import subprocess
import os 
import atexit
import argparse
from time import sleep

import i18n
from h3cRadius import *
from h3cPack import *
from h3cSrvStatus import *
import dpktMini
import plugins

__author__ = "houqp"
__license__ = "GPL"
__version__ = "0.0.1"
__maintainer__ = "houqp"
__email__ = "qingping.hou@gmail.com"


_ = i18n.language.lgettext

def ser_act(msg):
    return " [*] %s" % msg

def cli_act(msg):
    return " [#] %s" % msg

def msg(msg):
    return " [!] %s" % msg

radius_type = {
        0x01:'start',
        0x02:'logoff'
        }

eap_code = { 
        0x00:'nothing',
        0x01:'request', 
        0x02:'response',
        0x03:'success',
        0x04:'failure',
        0x0a:'h3c_unknown'
        }

eap_type = { 
        0x00:'nothing',
        0x01:'identity', 
        0x07:'allocated', 
        0x19:'unknown' 
        }

error_code = {
        '\x00\x00\x00\x00\x00\x00':'Authentication failed',
        'E63034':'Wrong password',
        'E63035':'Wrong password',
        'E63036':'There is no such a user',
        'E63022':'Maxium online user number reached!',
        'E63100':'Wrong client version, please upgrade it.'
        }


class PyH3C:
    def __init__(self):
        self.h3cSrvStatus = H3CStatus()
        self.plugins_loaded = []
        self.lock_file = "/tmp/pyh3c.lock"

    def do_nothing():
        """
        Method that do nothing.
        """
        pass

    def start_request_handler(self, ether, callback=do_nothing, data=None):
        """ 
        send identity request
        """
        self.h3cSrvStatus.cli_hwadd = ether.src
        identity_eap = pack_eap(0x01, 0x02, 0x01, '\x00')
        identity_radius = pack_radius(0x01, 0x00, identity_eap)
        identity_packet = pack_ether(self.h3cSrvStatus.srv_hwadd, self.h3cSrvStatus.cli_hwadd, identity_radius)
        self.sender.send(str(identity_packet))
        self.callback_caller(callback, data)
        exit(0)

    def logoff_request_handler(self, ether, callback=do_nothing, data=None):
        """ 
        """
        #self.h3cSrvStatus.cli_hwadd = ether.src
        #identity_eap = pack_eap(0x01, 0x02, 0x01, '\x00')
        #identity_radius = pack_radius(0x01, 0x00, identity_eap)
        #identity_packet = pack_ether(self.h3cSrvStatus.srv_hwadd, self.h3cSrvStatus.cli_hwadd, identity_radius)
        #self.sender.send(str(identity_packet))
        self.callback_caller(callback, data)

    def identity_handler(self, ether, callback=do_nothing, data=None):
        """ 
        send allocated request
        """
        radius = RADIUS_H3C(ether.data)
        eap = RADIUS_H3C.EAP(radius.data)
        allocated_eap = pack_eap(0x01, eap.id + 1, 0x07, '\x00')
        allocated_radius = pack_radius(0x01, 0x00, allocated_eap)
        allocated_packet = pack_ether(self.h3cSrvStatus.srv_hwadd, ether.src, allocated_radius)
        self.sender.send(str(allocated_packet))
        self.callback_caller(callback, data)

    def allocated_handler(self, ether, callback=do_nothing, data=None):
        """ 
        response authentication result
        """
        auth_re = False
        radius = RADIUS_H3C(ether.data)
        eap = RADIUS_H3C.EAP(radius.data)
        #auth_data = '%s%s%s' % ( chr(len(self.h3cSrvStatus.user_pass)), self.h3cSrvStatus.user_pass, self.h3cSrvStatus.user_name )
        #allocated_eap = pack_eap(0x02, eap.id, 0x07, auth_data)
        #allocated_radius = pack_radius(0x01, 0x00, allocated_eap)
        #allocated_packet = pack_ether(self.h3cSrvStatus.cli_hwadd, self.h3cSrvStatus.srv_hwadd, allocated_radius)
        #self.sender.send(str(allocated_packet))
        self.callback_caller(callback, (ether,auth_re))

    def success_handler(self, ether, callback=do_nothing, data=None):
        """
        handler for success
        """
        self.h3cSrvStatus.auth_success = True

        self.callback_caller(callback, data)

        #call after_auth_succ functions registered by plugins
        for plugin in self.plugins_loaded:
            getattr(plugin, 'after_auth_succ')(self)

    def h3c_unknown_handler(self, ether, callback=do_nothing, data=None):
        """
        handler for h3c specific
        """
        self.callback_caller(callback, data)

    def failure_handler(self, ether, callback=do_nothing, data=None):
        """
        handler for failed authentication
        """
        self.h3cSrvStatus.auth_success = False

        self.callback_caller(callback, data)

        #call after_auth_succ functions registered by plugins
        for plugin in self.plugins_loaded:
            getattr(plugin, 'after_auth_fail')(self)

    def wtf_handler(self, ether, callback=do_nothing, data=None):
        self.callback_caller(callback, data)

    def get_devices(self):
        """
        Get the list of all devices, return a list
        """
        devs = []
        try:
            libdnet = __import__('dnet')
        except ImportError:
            libdnet = __import__('dumbnet')
        intf = libdnet.intf()
        def add_dev(dict, arg):
            arg.append(dict['name'])
            return
        intf.loop(add_dev, devs)
        return devs

    def debug_packets(self, ether):
            #print 'Ethernet II type:%s' % hex(ether.type)
            radius = RADIUS_H3C(ether.data)
            eap = RADIUS_H3C.EAP(radius.data)
            print ''
            print _('# Start of dumping debug content #')
            print 'From %s to %s' % tuple( map(binascii.b2a_hex, (ether.src, ether.dst) ))
            print '%s' % dpktMini.hexdump(str(ether), 20)
            print '==== RADIUS ===='
            print 'radius_len: %d' % radius.len
            #print '======== EAP_HDR ========'
            #print '%s' % dpktMini.hexdump(str(eap), 20)
            #print 'server_response: %s' % eap_code[eap.code]
            print 'eap_code: %d' % eap.code
            print 'eap_id: %d' % eap.id
            print 'eap_len: %d' % eap.len
            print 'eap_type: %d' % eap.type
                #@must handle failure here
            #print _('eap_type: %s') % eap_type[eap.type] 
            print '======== EAP DATA ========'
            print '%s' % dpktMini.hexdump(eap.data, 20)
            print _('# End of dumping debug content #')
            print ''

    def set_up_lock(self):
        """
        Setup lock file in /tmp/pyh3c.lock in which pid is written 
        """
        try:
            lock = open(self.lock_file)
        except IOError:
            lock = open(self.lock_file, 'w')
            lock.write(str(os.getpid()))
            lock.close()
            return 1
        return 0

    def clean_up(self):
        """
        clean up lock file in /tmp
        """
        os.unlink(self.lock_file)
        return

    def read_args(self):
        """
        parse arguments
        """
        desc = "PyH3CSrv - A H3C authentication server written in Python."
        parser = argparse.ArgumentParser(description=desc)

        parser.add_argument('-u', '--user', type=str, 
                metavar='user_name', dest='user_name', action='store', 
                help="User name for your account.")

        parser.add_argument('-p', '--pass', type=str, 
                metavar='password', dest='user_pass', action='store', 
                help="Password for your account.")

        parser.add_argument('-D', '--dhcp', type=str, 
                metavar='dhcp_command', dest='dhcp_command', action='store', 
                help="DHCP command for acquiring IP after authentication.")

        parser.add_argument('-d', '--dev', type=str, 
                metavar='dev', dest='dev', action='store', 
                help="Ethernet interface used to connect to the internet.")

        parser.add_argument('-g', '--debug', 
                dest='debug_on', action='store_true', 
                help="Turn on debug to see dump content.")

        parser.add_argument('-k', '--kill', 
                dest='kill_on', action='store_true', 
                help="If there is another PyH3C instance running, kill it before start.")

        args = parser.parse_args(namespace=self.h3cSrvStatus)
        return 

    def load_plugins(self):
        """
        Load plugins according to pyh3c.conf
        """
        for p_item in self.h3cSrvStatus.plugins_to_load:
            try:
                self.plugins_loaded.append(getattr(self.h3cSrvStatus.plugins, p_item))
            except AttributeError:
                print msg(_('Failed while loading plugin ')) + '%s' % p_item + _('.')
            else:
                print msg(_('Plugin [ ')) + '%s' % p_item + _('] loaded.')

        return

    def kill_instance(self):
        try:
            fd = open(self.lock_file)
        except IOError:
            return
        pid = fd.read()
        fd.close()
        subprocess.Popen(["kill", "-9", pid])
        os.unlink(self.lock_file)

    def callback_caller(self, callback, data=None):
        if data:
            callback(self, data)
        else:
            callback(self)

    def main(self, callbacks):
        #for initializing
        if not (os.getuid() == 0):
            print msg(_('You must run with root privilege!'))
            exit(-1)

        self.read_args()
        if self.h3cSrvStatus.kill_on:
            self.kill_instance()

        if not self.set_up_lock():
            print msg(_('Only one PyH3CSrv can be ran at the same time!'))
            exit(-1)
        atexit.register(self.clean_up)

        self.h3cSrvStatus.load_config()
        callbacks["hello_world"](self)
        self.load_plugins()
        #end of initializing

        try:
            libdnet = __import__('dnet')
        except ImportError:
            try:
                libdnet = __import__('dumbnet')
            except ImportError:
                print msg(_('Failed loading dnet library, please install it first.'))
        self.sender = libdnet.eth(self.h3cSrvStatus.dev)
        self.h3cSrvStatus.srv_hwadd = self.sender.get()

        hw_s = binascii.b2a_hex(self.h3cSrvStatus.srv_hwadd)
        filter_srv_hwadd = "%s:%s:%s:%s:%s:%s" % (hw_s[0:2], hw_s[2:4], hw_s[4:6], hw_s[6:8], hw_s[8:10], hw_s[10:12])
        filter = 'ether proto 0x888e and (ether host 01:d0:f8:00:00:03 or ether host 01:80:c2:00:00:03 or ether host %s)' % filter_srv_hwadd

        pc = pcap.pcap(self.h3cSrvStatus.dev)
        pc.setfilter(filter)

        #self.send_start(callbacks["send_start_callback"])

        for ptime,pdata in pc:
            ether = dpktMini.ethernet.Ethernet(pdata)

            #ignore Packets sent by myself
            if ether.src !=  self.h3cSrvStatus.srv_hwadd:
                radius = RADIUS_H3C(ether.data)
                eap = RADIUS_H3C.EAP(radius.data)
                
                # output dump content if debug is on
                if self.h3cSrvStatus.debug_on: 
                    self.debug_packets(ether)

                if radius.len == 0:
                    handler = "%s_request_handler" % radius_type[radius.id]
                elif eap_code[eap.code] == 'response':
                    try:
                        handler = "%s_handler" % eap_type[eap.type]
                    except KeyError:
                        handler = "wtf_handler"
                        self.wtf_handler(ether, callbacks["wtf_handler_callback"], eap)
                        continue
                else:
                    try:
                        handler = "%s_handler" % eap_code[eap.code]
                    except KeyError:
                        handler = "wtf_handler"
                        self.wtf_handler(ether, callbacks["wtf_handler_callback"], eap)
                        continue

                #known packet will be handle here
                hander_callback = "%s_callback" % handler
                getattr(self,handler)(ether, callbacks[hander_callback])

        print msg(_('PyH3C exits!'))
        return


def main():

    pyh3c = PyH3C()

    def hello_world(pyh3c):
        print ''
        print ' === PyH3C %s ===' % __version__
        print ser_act(_('Activities from server.'))
        print cli_act(_('Activities from client.'))
        print msg(_('Messages you may want to read.'))
        print ''
        print msg(_('Using user name: ')) + '%s' % pyh3c.h3cSrvStatus.user_name
        print msg(_('Using interface: ')) + '%s' % pyh3c.h3cSrvStatus.dev
        print msg(_('Using DHCP script: ')) + '%s' % pyh3c.h3cSrvStatus.dhcp_command
        print ''
        return 

    def start_request_handler_callback(pyh3c):
        print ser_act(_('Sent out identity request.'))

    def logoff_request_handler_callback(pyh3c):
        print ser_act(_('Received logoff request.'))

    def identity_handler_callback(pyh3c):
        print ser_act(_('Received client identity response, sent allocated request.'))

    def h3c_unknown_handler_callback(ether, pyh3c):
        print ser_act(_('Received unknown h3c response from server.'))

    def allocated_handler_callback(pyh3c, (ether, auth_re)):
        if auth_re:
            print ser_act(_('Client ')) + '%s' % ether.src + _('authenticated.')
        else:
            print ser_act(_('Client ')) + '%s' % ether.src + _('authentication failed!')

    def success_handler_callback(ether, pyh3c):
        print ''
        print   '  /---------------------------------------------\ '
        print _(' | [^_^] Successfully passed the authentication! |')
        print   '  \---------------------------------------------/ '
        print ''

        #@TODO: check operating system here
        dhcp_command = "%s %s" % (pyh3c.h3cSrvStatus.dhcp_command, pyh3c.h3cSrvStatus.dev)
        #@TODO@: use subprocess here
        (status, output) = commands.getstatusoutput(dhcp_command)
        print cli_act(_('running command: ')) + '%s' % dhcp_command + _('to get an IP.')
        print ''
        print output
        print ''

        print msg(_('Every thing is done now, happy surfing the Internet.')) 
        print msg(_('I will send heart beat packets to keep you online.')) 

    def failure_handler_callback(ether, pyh3c):
        print ser_act(_('Received authentication failed packet from server.'))
        radius = RADIUS_H3C(ether.data)
        eap = RADIUS_H3C.EAP(radius.data)
        error = eap.data[1:7]
        try:
            print ser_act(_('Error code: ')) + '\"%s\", %s' % (error, error_code[error])
        except KeyError:
            print ser_act(_('Error code: ')) + '\"%s\", %s' % (binascii.b2a_hex(error), 'Unknown error code!')
            print _('     Please fire a bug report at:')
            print '     https://github.com/houqp/pyh3c/issues'
        print cli_act(_('Try to restart the authentication in one second.'))
        sleep(1)
        pyh3c.send_start(send_start_callback)
    
    def wtf_handler_callback(ether, pyh3c, eap):
        print msg(_('Encountered an unknown packet!'))
        print msg('----------------------------------------')
        print ''
        pyh3c.debug_packets(ether)
        print ''
        print _(' * It may be sent from some aliens, please help improve')
        print _('   software by fire a bug report at:')
        print '   https://github.com/houqp/pyh3c/issues'
        print _('   Also remember to paste the above output in your report.')
        print msg('----------------------------------------')


    callbacks = {
            'hello_world': hello_world,
            'start_request_handler_callback': start_request_handler_callback,
            'logoff_request_handler_callback': logoff_request_handler_callback,
            'identity_handler_callback': identity_handler_callback,
            'h3c_unknown_handler_callback': h3c_unknown_handler_callback,
            'allocated_handler_callback': allocated_handler_callback,
            'success_handler_callback': success_handler_callback,
            'failure_handler_callback': failure_handler_callback,
            'wtf_handler_callback': wtf_handler_callback
            }

    pyh3c.main(callbacks)



if __name__ == "__main__":
    main()
