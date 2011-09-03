# -*- coding:utf8 -*-
#!/usr/bin/env python

import pcap
import dpkt
import dnet
import binascii
import commands
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
__version__ = "0.4.1"
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
      callback(data)
    else:
      callback()
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
      callback(data)
    else:
      callback()
    return 

  def success_handler(ether, callback=do_nothing, data=None):
    """
    handler for success
    """
    self.h3cStatus.auth_success = 1

    if data:
      callback(data)
    else:
      callback()

    #call after_auth_succ functions registered by plugins
    for plugin in self.plugins_loaded:
      getattr(plugin, 'after_auth_succ')(self)

    return 

  def h3c_unknown_handler(self, ether, callback=do_nothing, data=None):
    """
    handler for h3c specific
    """
    if data:
      callback(data)
    else:
      callback()
    return 

  def failure_handler(self, ether, callback=do_nothing, data=None):
    """
    handler for failed authentication
    """
    self.h3cStatus.auth_success = 0
    if data:
      callback(data)
    else:
      callback()

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

  def set_up_lock(self):
    """
    Setup lock file in /tmp/pyh3c.lock inwhich pid is written 
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

    class set_dest(argparse.Action):
      def __call__(self, parser, namespace, values, option_string=None):
        self.dest = values

    parser.add_argument('-u', '--user', type=str, \
        metavar='user_name', \
        dest='self.h3cStatus.user_name', action=set_dest, \
        help="User name for your account.")

    parser.add_argument('-p', '--pass', type=str, \
        metavar='password', \
        dest='self.h3cStatus.password', action=set_dest, \
        help="Password for your account.")

    parser.add_argument('-D', '--dhcp', type=str, \
        metavar='dhcp_command', \
        dest='self.h3cStatus.dhcp_command', action=set_dest, \
        help="DHCP command for acquiring IP after authentication.")

    parser.add_argument('-d', '--dev', type=str, \
        metavar='dev', \
        dest='self.h3cStatus.dev', action=set_dest, \
        help="Ethernet interface used to connect to the internet.")

    args = parser.parse_args()
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
      (status, output) = commands.getstatusoutput(dhcp_command)
      print ""
      print output
      print ""
      return

    def send_start_callback():
      print " [*] Sent out the authentication request."

    def identity_handler_callback():
      if self.h3cStatus.auth_success:
        print " [*] Received server check online request, sent keepalive packet."
      else:
        print " [*] Received identity challenge request."
        print "     [#] Sent identity challenge response."

    def h3c_unknown_handler_callback():
      print " [*] Received unknown h3c response from server."

    def allocated_handler_callback():
      print " [*] Received allocated challenge request."
      print "     [#] Sent allocated challenge response."

    def success_handler_callback():
      print ""
      print "  /---------------------------------------------\ "
      print " | [^_^] Successfully passed the authentication! |"
      print "  \---------------------------------------------/ "
      print ""
      print " [#] running command: %s to get an IP." % dhcp_command
      do_dhcp()
      print " [!] Every thing is done now, happy surfing the Internet." 
      print " [!] I will send heart beat packets to keep you online." 

    def failure_handler_callback():
      print " [*] Received authentication failed packet from server."
      print "     [#] Try to restart the authentication in one second."
      sleep(1)
      self.send_start(send_start_callback)

    def debug_packets(ether,eap):
        #print 'Ethernet II type:%s' % hex(ether.type)
        print 'From %s to %s' % tuple( map(binascii.b2a_hex, (ether.src, ether.dst) ))
        print "%s" % dpkt.hexdump(str(ether), 20)
        print "==== RADIUS ===="
        print "radius_len: %d" % radius.len
        #print "======== EAP_HDR ========"
        #print "%s" % dpkt.hexdump(str(eap), 20)
        print "server_response: %s" % response_type[eap.code]
        print "eap_id: %d" % eap.id
        print "eap_len: %d" % eap.len
          #@must handle failure here
        #print "eap_type: %s" % eap_type[eap.type] 
        print "======== EAP DATA ========"
        print "%s" % dpkt.hexdump(eap.data, 20)

    #--- main() starts here ---

    #for initializing
    if not (os.getuid() == 0):
      print " [!] You must run with root privilege!"
      exit(-1)

    if not self.set_up_lock():
      print " [!] Only one PyH3C can be ran at the same time!"
      exit(-1)
    atexit.register(self.clean_up)

    self.h3cStatus.load_config()
    self.read_args()
    hello_world()
    self.load_plugins()
    #endof initializing

    self.sender = dnet.eth(self.h3cStatus.dev)
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
        #debug_packets(ether, eap)

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



