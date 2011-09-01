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

from h3cRadius import *
from h3cPack import *
import h3cStatus

__author__ = "houqp"
__license__ = "GPL"
__version__ = "0.3"
__maintainer__ = "houqp"
__email__ = "qingping.hou@gmail.com"

client_hwadd = ""
lock_file = "/tmp/pyh3c.lock"

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

def do_nothing():
  pass

def send_start(sender, callback=do_nothing, data=None):
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
  start_packet = pack_ether(client_hwadd, "\xff\xff\xff\xff\xff\xff", start_radius)
  sender.send(str(start_packet))
  if data:
    callback(data)
  else:
    callback()
  return 

def identity_handler(ether, sender, callback=do_nothing, data=None):
  """ 
  response user_name to server
  """
  #@you may need to set id according to server's response here
  identity_eap = pack_eap(0x02, 0x02, 0x01, h3cStatus.user_name)
  identity_radius = pack_radius(0x01, 0x00, identity_eap)
  identity_packet = pack_ether(client_hwadd, ether.src, identity_radius)
  sender.send(str(identity_packet))
  if data:
    callback(data)
  else:
    callback()
  return 

def allocated_handler(ether, sender, callback=do_nothing, data=None):
  """ 
  response password to server
  """
  auth_data = "%s%s%s" % ( chr(len(h3cStatus.user_pass)), h3cStatus.user_pass, h3cStatus.user_name )
  #@you may need to set id according to server's response here
  allocated_eap = pack_eap(0x02, 0x03, 0x07, auth_data)
  allocated_radius = pack_radius(0x01, 0x00, allocated_eap)
  allocated_packet = pack_ether(client_hwadd, ether.src, allocated_radius)
  sender.send(str(allocated_packet))
  if data:
    callback(data)
  else:
    callback()
  return 

def success_handler(ether, sender, callback=do_nothing, data=None):
  """
  handler for success
  """
  h3cStatus.auth_success = 1
  if data:
    callback(data)
  else:
    callback()
  return 

def h3c_unknown_handler(ether, sender, callback=do_nothing, data=None):
  """
  handler for h3c specific
  """
  if data:
    callback(data)
  else:
    callback()
  return 

def failure_handler(ether, sender, callback=do_nothing, data=None):
  """
  handler for failed authentication
  """
  h3cStatus.auth_success = 0
  if data:
    callback(data)
  else:
    callback()
  return 

def nothing_handler(ether, sender, callback=do_nothing, data=None):
  """
  handler for others, just let go
  """
  if data:
    callback(data)
  else:
    callback()
  return 

def check_online():
  """
  check to see whether the client is still online.
  """
  if data:
    callback(data)
  else:
    callback()
  return 

  

def set_up_lock():
  try:
    lock = open(lock_file)
  except IOError:
    lock = open(lock_file, 'w')
    lock.write(str(os.getpid()))
    lock.close()
    return 1
  return 0

def clean_up():
  os.unlink(lock_file)
  return

def read_args():
  desc = "PyH3C - A H3C client written in Python."
  parser = argparse.ArgumentParser(description=desc)

  class user_action(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
      h3cStatus.user_name = values
  parser.add_argument('-u', '--user', type=str, \
      metavar='user_name', dest='user_name', action=user_action, \
      help="User name for your account.")

  class pass_action(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
      h3cStatus.user_pass = values
  parser.add_argument('-p', '--pass', type=str, \
      metavar='password', dest='password', action=pass_action, \
      help="Password for your account.")

  class dhcp_action(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
      h3cStatus.dhcp_command = values
  parser.add_argument('-D', '--dhcp', type=str, \
      metavar='dhcp_command', dest='dhcp_command', action=dhcp_action, \
      help="DHCP command for acquiring IP after authentication.")

  class dev_action(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
      h3cStatus.dev = values
  parser.add_argument('-d', '--dev', type=str, \
      metavar='dev', dest='dev', action=dev_action, \
      help="Ethernet interface used to connect to the internet.")

  args = parser.parse_args()


if __name__ == "__main__":

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
    print " [!] Using user name: %s" % h3cStatus.user_name
    print " [!] Using interface: %s" % h3cStatus.dev
    print " [!] Using DHCP script: %s" % h3cStatus.dhcp_command
    print ""
    return 

  def send_start_callback():
    print " [*] Sent out the authentication request."

  def identity_handler_callback():
    if h3cStatus.auth_success:
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
    dhcp_command = "%s %s" % (h3cStatus.dhcp_command, h3cStatus.dev)
    print ""
    print "  /---------------------------------------------\ "
    print " | [^_^] Successfully passed the authentication! |"
    print "  \---------------------------------------------/ "
    print ""
    print " [#] running command: %s to get an IP." % dhcp_command
    print ""
    (status, output) = commands.getstatusoutput(dhcp_command)
    print output
    print ""
    print " [!] Every thing is done now, happy surfing the Internet." 
    print " [!] I will send heart beat packets to keep you online." 

  def failure_handler_callback():
    print " [*] Received authentication failed packet from server."
    print "     [#] Try to restart the authentication."
    send_start()

  def debug_packets():
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

  if not set_up_lock():
    print " [!] Only one PyH3C can be ran at the same time!"
    exit(-1)
  atexit.register(clean_up)

  h3cStatus.load_config()

  read_args()

  hello_world()
  #endof initializing

  sender = dnet.eth(h3cStatus.dev)
  client_hwadd = sender.get()

  hw_s = binascii.b2a_hex(client_hwadd)
  filter_hwadd = "%s:%s:%s:%s:%s:%s" % (hw_s[0:2], hw_s[2:4], hw_s[4:6], hw_s[6:8], hw_s[8:10], hw_s[10:12])
  filter = 'ether host %s and ether proto 0x888e' % filter_hwadd

  pc = pcap.pcap(h3cStatus.dev)
  pc.setfilter(filter)

  send_start(sender, send_start_callback)

  for ptime,pdata in pc:
    ether = dpkt.ethernet.Ethernet(pdata)
    #debug_packets()

    #ignore Packets sent by myself
    if ether.dst == client_hwadd:
      radius = RADIUS_H3C(ether.data)
      eap = RADIUS_H3C.EAP(radius.data)

      if response_type[eap.code] == 'request':
        handler = "%s_handler" % eap_type[eap.type]
      else:
        handler = "%s_handler" % response_type[eap.code]
      hander_callback = "%s_callback" % handler
      globals()[handler](ether, sender, globals()[hander_callback])

  print "\n"




