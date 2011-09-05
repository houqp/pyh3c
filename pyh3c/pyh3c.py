# -*- coding:utf8 -*-
#!/usr/bin/env python

import pcap
import dpkt
#import dnet
import binascii
import commands
import subprocess
import os 
import atexit
import argparse
from time import sleep

from h3cRadius import *
from h3cPack import *
from h3cStatus import *
import plugins

__author__ = "houqp"
__license__ = "GPL"
__version__ = "0.5.1"
__maintainer__ = "houqp"
__email__ = "qingping.hou@gmail.com"


response_type = { 
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
    'E63036':'Unknown user name'
    }

class PyH3C:
  def __init__(self):
    self.h3cStatus = H3C_STATUS()
    self.plugins_loaded = []
    self.lock_file = "/tmp/pyh3c.lock"

  def do_nothing():
    """
    Method that do nothing.
    """
    pass

  def send_start(self, callback=do_nothing, data=None):
    """
    start the authentication
    """
    # manually construct the header because it's special
    start_radius = RADIUS_H3C(
          code = 1,
          id = 1,
          len = 0,
          data = '\x00'
        )
    start_packet = pack_ether(self.h3cStatus.hwadd, "\xff\xff\xff\xff\xff\xff", start_radius)

    #call before_auth functions registered by plugins
    for plugin in self.plugins_loaded:
      getattr(plugin, 'before_auth')(self)

    self.sender.send(str(start_packet))
    if data:
      callback(data)
    else:
      callback()
    return 

  def identity_handler(self, ether, callback=do_nothing, data=None):
    """ 
    response user_name to server
    """
    #@you may need to set id according to server's response here
    identity_eap = pack_eap(0x02, 0x02, 0x01, self.h3cStatus.user_name)
    identity_radius = pack_radius(0x01, 0x00, identity_eap)
    identity_packet = pack_ether(self.h3cStatus.hwadd, ether.src, identity_radius)
    self.sender.send(str(identity_packet))
    if data:
      callback(ether, data)
    else:
      callback(ether)
    return 

  def allocated_handler(self, ether, callback=do_nothing, data=None):
    """ 
    response password to server
    """
    auth_data = "%s%s%s" % ( chr(len(self.h3cStatus.user_pass)), self.h3cStatus.user_pass, self.h3cStatus.user_name )
    #@you may need to set id according to server's response here
    allocated_eap = pack_eap(0x02, 0x03, 0x07, auth_data)
    allocated_radius = pack_radius(0x01, 0x00, allocated_eap)
    allocated_packet = pack_ether(self.h3cStatus.hwadd, ether.src, allocated_radius)
    self.sender.send(str(allocated_packet))
    if data:
      callback(ether, data)
    else:
      callback(ether)
    return 

  def success_handler(self, ether, callback=do_nothing, data=None):
    """
    handler for success
    """
    self.h3cStatus.auth_success = 1

    if data:
      callback(ether, data)
    else:
      callback(ether)

    #call after_auth_succ functions registered by plugins
    for plugin in self.plugins_loaded:
      getattr(plugin, 'after_auth_succ')(self)

    return 

  def h3c_unknown_handler(self, ether, callback=do_nothing, data=None):
    """
    handler for h3c specific
    """
    if data:
      callback(ether, data)
    else:
      callback(ether)
    return 

  def failure_handler(self, ether, callback=do_nothing, data=None):
    """
    handler for failed authentication
    """
    self.h3cStatus.auth_success = 0
    if data:
      callback(ether, data)
    else:
      callback(ether)

    #call after_auth_succ functions registered by plugins
    for plugin in self.plugins_loaded:
      getattr(plugin, 'after_auth_fail')(self)

    return 

  def wtf_handler(self, ether, callback=do_nothing, data=None):
    """
    What the fuck handler for packets that I've never seen before.
    """
    print " [!] Encountered an unknown packet!"
    print " [!] ----------------------------------------"
    print ""
    callback(ether, data)
    print ""
    print " * It may be sent from some aliens, please help improve"
    print "   software by fire a bug report at:"
    print "   https://github.com/houqp/pyh3c/issues"
    print "   Also remember to paste the above output in your report."
    print " [!] ----------------------------------------"
    return

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
    desc = "PyH3C - A H3C client written in Python."
    parser = argparse.ArgumentParser(description=desc)

    parser.add_argument('-u', '--user', type=str, \
        metavar='user_name', dest='user_name', action='store', \
        help="User name for your account.")

    parser.add_argument('-p', '--pass', type=str, \
        metavar='password', dest='user_pass', action='store', \
        help="Password for your account.")

    parser.add_argument('-D', '--dhcp', type=str, \
        metavar='dhcp_command', dest='dhcp_command', action='store', \
        help="DHCP command for acquiring IP after authentication.")

    parser.add_argument('-d', '--dev', type=str, \
        metavar='dev', dest='dev', action='store', \
        help="Ethernet interface used to connect to the internet.")

    parser.add_argument('-g', '--debug', \
        dest='debug_on', action='store_true', \
        help="Turn on debug to see dump content.")

    parser.add_argument('-k', '--kill', \
        dest='kill_on', action='store_true', \
        help="If there is another PyH3C instance running, kill it before start.")

    args = parser.parse_args(namespace=self.h3cStatus)
    return 

  def load_plugins(self):
    """
    Load plugins according to pyh3c.conf
    """
    for p_item in self.h3cStatus.plugins_to_load:
      try:
        self.plugins_loaded.append(getattr(self.h3cStatus.plugins, p_item))
      except AttributeError:
        print " [!] Failed while loading plugin %s." % p_item
      else:
        print " [!] Plugin [ %s ] loaded." % p_item

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

  def main(self):

    def hello_world():
      print ""
      print " === PyH3C %s ===" % __version__
      print " [*] Activities from server."
      print " [#] Activities from client."
      print " [!] Messages you may want to read."
      print ""
      print " ----------------------------------------------"
      print " [!] This piece of software may not be working"
      print " [!] as you expected. But if it really works, "
      print " [!] remember to send me a Thank you letter via"
      print " [!] qingping.hou@gmail.com."
      print ""
      print " [!] OK, I am just kidding. Forget about this."
      print ""
      print " [!] Now, let the hunt begin!"
      print " ----------------------------------------------"
      print ""
      print " [!] Using user name: %s" % self.h3cStatus.user_name
      print " [!] Using interface: %s" % self.h3cStatus.dev
      print " [!] Using DHCP script: %s" % self.h3cStatus.dhcp_command
      print ""
      return 

    def do_dhcp():
      #@TODO: check operating system here
      dhcp_command = "%s %s" % (self.h3cStatus.dhcp_command, self.h3cStatus.dev)
      #@TODO@: use subprocess here
      (status, output) = commands.getstatusoutput(dhcp_command)
      print " [#] running command: %s to get an IP." % dhcp_command
      print ""
      print output
      print ""
      return

    def send_start_callback():
      print " [*] Sent out the authentication request."

    def identity_handler_callback(ether):
      if self.h3cStatus.auth_success:
        print " [*] Received server check online request, sent response packet."
      else:
        print " [*] Received identity challenge request."
        print "     [#] Sent identity challenge response."

    def h3c_unknown_handler_callback(ether):
      print " [*] Received unknown h3c response from server."

    def allocated_handler_callback(ether):
      print " [*] Received allocated challenge request."
      print "     [#] Sent allocated challenge response."

    def success_handler_callback(ether):
      print ""
      print "  /---------------------------------------------\ "
      print " | [^_^] Successfully passed the authentication! |"
      print "  \---------------------------------------------/ "
      print ""
      do_dhcp()
      print " [!] Every thing is done now, happy surfing the Internet." 
      print " [!] I will send heart beat packets to keep you online." 

    def failure_handler_callback(ether):
      print " [*] Received authentication failed packet from server."

      radius = RADIUS_H3C(ether.data)
      eap = RADIUS_H3C.EAP(radius.data)
      error = eap.data[1:7]
      try:
        print " [*] Error code: \"%s\", %s" % (error, error_code[error])
      except KeyError:
        print " [*] Error code: \"%s\", %s" % (binascii.b2a_hex(error), "Unknown error code!")
        print "     Please fire a bug report at:"
        print "     https://github.com/houqp/pyh3c/issues"
      print "     [#] Try to restart the authentication in one second."
      sleep(1)
      self.send_start(send_start_callback)

    def debug_packets(ether, eap):
        #print 'Ethernet II type:%s' % hex(ether.type)
        print ""
        print "# Start of dump content #"
        print 'From %s to %s' % tuple( map(binascii.b2a_hex, (ether.src, ether.dst) ))
        print "%s" % dpkt.hexdump(str(ether), 20)
        print "==== RADIUS ===="
        print "radius_len: %d" % radius.len
        #print "======== EAP_HDR ========"
        #print "%s" % dpkt.hexdump(str(eap), 20)
        #print "server_response: %s" % response_type[eap.code]
        print "eap_code: %d" % eap.code
        print "eap_id: %d" % eap.id
        print "eap_len: %d" % eap.len
        print "eap_type: %d" % eap.type
          #@must handle failure here
        #print "eap_type: %s" % eap_type[eap.type] 
        print "======== EAP DATA ========"
        print "%s" % dpkt.hexdump(eap.data, 20)
        print "# End of dump content #"
        print ""

    #--- main() starts here ---

    #for initializing
    if not (os.getuid() == 0):
      print " [!] You must run with root privilege!"
      exit(-1)

    self.read_args()
    if self.h3cStatus.kill_on:
      self.kill_instance()

    if not self.set_up_lock():
      print " [!] Only one PyH3C can be ran at the same time!"
      exit(-1)
    atexit.register(self.clean_up)

    self.h3cStatus.load_config()
    hello_world()
    self.load_plugins()
    #end of initializing

    try:
      libdnet = __import__('dnet')
    except ImportError:
      libdnet = __import__('dumbnet')
    self.sender = libdnet.eth(self.h3cStatus.dev)
    self.h3cStatus.hwadd = self.sender.get()

    hw_s = binascii.b2a_hex(self.h3cStatus.hwadd)
    filter_hwadd = "%s:%s:%s:%s:%s:%s" % (hw_s[0:2], hw_s[2:4], hw_s[4:6], hw_s[6:8], hw_s[8:10], hw_s[10:12])
    filter = 'ether host %s and ether proto 0x888e' % filter_hwadd

    pc = pcap.pcap(self.h3cStatus.dev)
    pc.setfilter(filter)

    self.send_start(send_start_callback)

    for ptime,pdata in pc:
      ether = dpkt.ethernet.Ethernet(pdata)

      #ignore Packets sent by myself
      if ether.dst == self.h3cStatus.hwadd:
        radius = RADIUS_H3C(ether.data)
        eap = RADIUS_H3C.EAP(radius.data)
        
        # output dump content if debug is on
        if self.h3cStatus.debug_on: 
          debug_packets(ether, eap)

        if response_type[eap.code] == 'request':
          try:
            handler = "%s_handler" % eap_type[eap.type]
          except KeyError:
            handler = "wtf_handler"
            self.wtf_handler(ether, debug_packets, eap)
            continue
        else:
          try:
            handler = "%s_handler" % response_type[eap.code]
          except KeyError:
            handler = "wtf_handler"
            self.wtf_handler(ether, debug_packets, eap)
            continue

        #known packet will be handle here
        hander_callback = "%s_callback" % handler
        getattr(self,handler)(ether, locals()[hander_callback])

    print " [!] PyH3C exits!"
    return


if __name__ == "__main__":

  pyh3c = PyH3C()
  pyh3c.main()



