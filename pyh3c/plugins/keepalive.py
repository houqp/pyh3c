# -*- coding:utf8 -*-
#!/usr/bin/env python

import commands
import threading
from time import sleep

def watcher(pyh3c, command):
  dissconn_count = 0
  def restart_auth():
    print " [!] Disconnected! Now restart authentication ..."
  while True:
    sleep(ping_interval)
    (status, output) = commands.getstatusoutput(command)
    if status != 0:
      dissconn_count += 1
      if dissconn_count >= h3cStatus.ping_tolerence:
        pyh3c.start_packet(restart_auth)
        dissconn_count = 0
        #wait some time for reauth
        sleep(ping_interval)
    else:
      dissconn_count = 0
  return


def check_online(pyh3c):
  """
  check to see whether the client is still online.
  """
  check_command = 'ping -c 1 -n %s' % h3cStatus.ping_target
  #spwan watcher here
  return 
 
def before_auth(pyh3c):
  pass

def after_auth_succ(pyh3c):
  if pyh3c.h3cStatus.ping_target == 'none':
    return
  check_online(pyh3c)
  return 

def after_auth_fail(pyh3c):
  pass
  
