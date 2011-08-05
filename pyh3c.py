# -*- coding:utf8 -*-
#!/usr/bin/env python

import pcap
import dpkt
import binascii
import dnet
import commands

from h3cRadius import *
from h3cPack import *
import h3cStatus

client_hwadd = ""
server_hwadd = ""

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


def send_start():
  """
  start the authentication
  """
  print " [*] Send out the authentication request."
  start_radius = RADIUS_H3C(
        code = 1,
        id = 1,
        len = 0,
        data = '\x00'
      )
  start_packet = dpkt.ethernet.Ethernet(
        #dst = "\x08\x00\x27\x00\xd7\x15",
        #dst = "\x01\x80\xc2\x00\x00\x03",
        dst = "\xff\xff\xff\xff\xff\xff",
        src = client_hwadd,
        type = 0x888e,
        data = str(start_radius)
      )
  #print "%s" % binascii.b2a_hex(str(start_packet))
  sender.send(str(start_packet))

def identity_handler(ether):
  """ 
  response username to server
  """
  if h3cStatus.auth_success:
    print " [*] Received server check online request, sending keepalive packet."
  else:
    print " [*] Received identity challenge request."
    print "     ==> [#] Now sending identity challenge response."
  identity_eap = RADIUS_H3C.EAP(
        code = 0x02,
        #@you may need to set id according to server's response here
        id = 0x02,
        len = 5 + len(h3cStatus.user_name),
        type = 0x01,
        data = h3cStatus.user_name
      )
  identity_radius = RADIUS_H3C(
        code = 1,
        id = 0,
        len = identity_eap.len,
        data = str(identity_eap)
      )
  identity_packet = dpkt.ethernet.Ethernet(
        dst = ether.src,
        src = client_hwadd,
        type = 0x888e,
        data = str(identity_radius)
      )
  sender.send(str(identity_packet))

def allocated_handler(ether):
  """ 
  response password to server
  """
  auth_data = "%s%s%s" % ( chr(len(h3cStatus.user_pass)), h3cStatus.user_pass, h3cStatus.user_name )
  print " [*] Received allocated challenge request."
  print "     ==> [#] Now sending allocated challenge response."
  allocated_eap = RADIUS_H3C.EAP(
    code = 0x02,
    #@you may need to set id according to server's response here
    id = 0x03,
    len = 5 + len(h3cStatus.user_pass),
    type = 0x07,
    data = auth_data
  )
  allocated_radius = RADIUS_H3C(
    code = 1,
    id = 0,
    len = allocated_eap.len,
    data = str(allocated_eap)
  )
  allocated_packet = dpkt.ethernet.Ethernet(
    dst = ether.src,
    src = client_hwadd,
    type = 0x888e,
    data = str(allocated_radius)
  )
  sender.send(str(allocated_packet))

def success_handler(ether):
  """
  handler for success
  """
  print "\n"
  print " /---------------------------------------------\ "
  print "| [^_^] Successfully passed the authentication! |"
  print " \---------------------------------------------/ "
  print "\n"
  h3cStatus.auth_success = 1
  #dhcp_command = "%s %s" % (h3cStatus.dhcp_script,h3cStatus.dev)
  #(status, output) = commands.getstatusoutput(dhcp_command)
  #print output

def h3c_unknown_handler(ether):
  """
  handler for h3c specific
  """
  print " [*] Received unknown h3c response from server."
  pass

def failure_handler(ether):
  """
  handler for failed authentication
  """
  h3cStatus.auth_success = 0
  exit(0)

def nothing_handler(ether):
  """
  handler for others, just let go
  """
  pass

if __name__ == "__main__":

  h3cStatus.load_config()

  sender = dnet.eth(h3cStatus.dev)
  client_hwadd = sender.get()

  hw_s = binascii.b2a_hex(client_hwadd)
  filter_hwadd = "%s:%s:%s:%s:%s:%s" % (hw_s[0:2], hw_s[2:4], hw_s[4:6], hw_s[6:8], hw_s[8:10], hw_s[10:12])
  filter = 'ether host %s and ether proto 0x888e' % filter_hwadd

  pc = pcap.pcap(h3cStatus.dev)
  pc.setfilter(filter)

  send_start()

  for ptime,pdata in pc:
    ether = dpkt.ethernet.Ethernet(pdata)
#    #print 'Ethernet II type:%s' % hex(ether.type)
    #print 'From %s to %s' % tuple( map(binascii.b2a_hex, (ether.src, ether.dst) ))
    #print "%s" % dpkt.hexdump(str(ether), 20)
    #print "==== RADIUS ===="
    #print "radius_len: %d" % radius.len
    ##print "======== EAP_HDR ========"
    ##print "%s" % dpkt.hexdump(str(eap), 20)
    #print "server_response: %s" % response_type[eap.code]
    #print "eap_id: %d" % eap.id
    #print "eap_len: %d" % eap.len
      ##@must handle failure here
    ##print "eap_type: %s" % eap_type[eap.type] 
    #print "======== EAP DATA ========"
    #print "%s" % dpkt.hexdump(eap.data, 20)

    #ignore Packets sent by myself
    if ether.dst == client_hwadd:
      radius = RADIUS_H3C(ether.data)
      eap = RADIUS_H3C.EAP(radius.data)

      if response_type[eap.code] == 'request':
        handler = "%s_handler" % eap_type[eap.type]
      else:
        handler = "%s_handler" % response_type[eap.code]
      globals()[handler](ether)

  print "\n"



