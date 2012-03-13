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


class PyH3CSrv:
    def __init__(self):
        self.h3cSrvStatus = H3CSrvStatus()
        self.lock_file = "/tmp/pyh3c_srv.lock"

    def do_nothing():
        """
        Method that do nothing.
        """
        pass

    def start_request_handler(self, ether, callback=do_nothing, data=None):
        """ 
        Received start request, send identity request to client
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
        client request logoff do nothing, @TODO mark status  13.03 2012 (houqp)
        """
        #self.h3cSrvStatus.cli_hwadd = ether.src
        #identity_eap = pack_eap(0x01, 0x02, 0x01, '\x00')
        #identity_radius = pack_radius(0x01, 0x00, identity_eap)
        #identity_packet = pack_ether(self.h3cSrvStatus.srv_hwadd, self.h3cSrvStatus.cli_hwadd, identity_radius)
        #self.sender.send(str(identity_packet))
        self.callback_caller(callback, data)

    def identity_handler(self, ether, callback=do_nothing, data=None):
        """ 
        Received identity response, send allocated request
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
        Received allocated response, send authentication result
        """
        auth_re = False
        radius = RADIUS_H3C(ether.data)
        eap = RADIUS_H3C.EAP(radius.data)
        #@TODO handle username and password here  13.03 2012 (houqp)

        #auth_data = '%s%s%s' % ( chr(len(self.h3cSrvStatus.user_pass)), self.h3cSrvStatus.user_pass, self.h3cSrvStatus.user_name )
        #allocated_eap = pack_eap(0x02, eap.id, 0x07, auth_data)
        #allocated_radius = pack_radius(0x01, 0x00, allocated_eap)
        #allocated_packet = pack_ether(self.h3cSrvStatus.cli_hwadd, self.h3cSrvStatus.srv_hwadd, allocated_radius)
        #self.sender.send(str(allocated_packet))
        if auth_re:
            self.send_auth_success(ether)
        else:
            self.send_auth_fail(ether)
        self.callback_caller(callback, (ether,auth_re))

    def send_auth_success(self, ether):
        radius = RADIUS_H3C(ether.data)
        eap = RADIUS_H3C.EAP(radius.data)
        succ_eap = pack_eap(0x03, eap.id + 1, 0x00, '\x00')
        succ_radius = pack_radius(0x01, 0x00, succ_eap)
        succ_packet = pack_ether(self.h3cSrvStatus.srv_hwadd, ether.src, succ_radius)
        self.sender.send(str(succ_packet))

    def send_auth_fail(self, ether):
        radius = RADIUS_H3C(ether.data)
        eap = RADIUS_H3C.EAP(radius.data)
        succ_eap = pack_eap(0x04, eap.id + 1, 0x00, '\x00')
        succ_radius = pack_radius(0x01, 0x00, succ_eap)
        succ_packet = pack_ether(self.h3cSrvStatus.srv_hwadd, ether.src, succ_radius)
        self.sender.send(str(succ_packet))

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
        Setup lock file in /tmp/pyh3c_srv.lock in which pid is written 
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

    def read_args(self):
        """
        parse arguments
        """
        desc = "PyH3CSrv - A H3C authentication server written in Python."
        parser = argparse.ArgumentParser(description=desc)

        parser.add_argument('-d', '--dev', type=str, 
                metavar='dev', dest='dev', action='store', 
                help="Ethernet interface used to connect to the internet.")

        parser.add_argument('-g', '--debug', 
                dest='debug_on', action='store_true', 
                help="Turn on debug to see dump content.")

        parser.add_argument('-k', '--kill', 
                dest='kill_on', action='store_true', 
                help="If there is another PyH3CSrv instance running, kill it before start.")

        args = parser.parse_args(namespace=self.h3cSrvStatus)

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

        print msg(_('PyH3CSrv exits!'))


def main():

    pyh3c_srv = PyH3CSrv()

    def hello_world(pyh3c_srv):
        print ''
        print ' === PyH3CSrv %s ===' % __version__
        print ser_act(_('Activities from server.'))
        print cli_act(_('Activities from client.'))
        print msg(_('Messages you may want to read.'))
        print ''
        print ser_act(_('Waiting for clients...'))

    def start_request_handler_callback(pyh3c_srv):
        print cli_act(_('Client sent authentication request.'))
        print ser_act(_('Sent out identity request.'))

    def identity_handler_callback(pyh3c_srv):
        print cli_act(_('Client sent identity response.'))
        print ser_act(_('Sent out allocated request.'))

    def logoff_request_handler_callback(pyh3c_srv):
        print ser_act(_('Received logoff request.'))

    def h3c_unknown_handler_callback(ether, pyh3c_srv):
        print ser_act(_('Received unknown h3c response from server.'))

    def allocated_handler_callback(pyh3c_srv, (ether, auth_re)):
        if auth_re:
            print ser_act(_('Client ')) + '[%s]' % binascii.b2a_hex(ether.src) + _(' authenticated.')
        else:
            print ser_act(_('Client ')) + '[%s]' % binascii.b2a_hex(ether.src) + _(' authentication failed!')

    callbacks = {
            'hello_world': hello_world,
            'start_request_handler_callback': start_request_handler_callback,
            'logoff_request_handler_callback': logoff_request_handler_callback,
            'identity_handler_callback': identity_handler_callback,
            'allocated_handler_callback': allocated_handler_callback,
            }

    pyh3c_srv.main(callbacks)



if __name__ == "__main__":
    main()
