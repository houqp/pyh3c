#!/usr/bin/env python
# -*- coding:utf8 -*-

import commands
import threading
from time import sleep

__author__ = "houqp"
__license__ = "GPL"
__version__ = "0.6"
__maintainer__ = "houqp"
__email__ = "qingping.hou@gmail.com"


keepalive_lock = 0

def watcher(pyh3c):
  global keepalive_lock 
  keepalive_lock = 1
  dissconn_count = 0
  check_command = 'ping -c 1 -W 1 -n %s' % pyh3c.h3cStatus.ping_target

  def restart_auth(pyh3c):
    print " [!] Disconnected! Now restart authentication ..."

  while True:
    sleep(pyh3c.h3cStatus.ping_interval)
    (status, output) = commands.getstatusoutput(check_command)
    #print "dissconn_count:%d" % dissconn_count
    if status != 0:
      dissconn_count += 1
      if dissconn_count >= pyh3c.h3cStatus.ping_tolerence:
        pyh3c.send_start(restart_auth)
        dissconn_count = 0
        #wait some time for reauth
        sleep(pyh3c.h3cStatus.ping_after_reauth)
    else:
      dissconn_count = 0
  return

def check_online(pyh3c):
  """
  check to see whether the client is still online.
  """
  #spawn watcher here
  t = threading.Thread(group=None, target=watcher, name='watcher', args=(pyh3c,), kwargs={})
  t.daemon = True
  t.start()
  print " [!] Keepalive watcher spawned."
  return 


def before_auth(pyh3c):
  pass

def after_auth_succ(pyh3c):
  if keepalive_lock or pyh3c.h3cStatus.ping_target == 'none':
    return
  check_online(pyh3c)
  return 

def after_auth_fail(pyh3c):
  pass
  
