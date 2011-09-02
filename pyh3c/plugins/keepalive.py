# -*- coding:utf8 -*-
#!/usr/bin/env python

import commands
import threading
from time import sleep

__author__ = "houqp"
__license__ = "GPL"
__version__ = "0.5"
__maintainer__ = "houqp"
__email__ = "qingping.hou@gmail.com"


def watcher(pyh3c):
  dissconn_count = 0
  check_command = 'ping -c 1 -n %s' % pyh3c.h3cStatus.ping_target

  def restart_auth():
    print " [!] Disconnected! Now restart authentication ..."

  while True:
    sleep(pyh3c.h3cStatus.ping_interval)
    (status, output) = commands.getstatusoutput(check_command)
    if status != 0:
      dissconn_count += 1
      if dissconn_count >= pyh3c.h3cStatus.ping_tolerence:
        pyh3c.send_start(restart_auth)
        break
        #dissconn_count = 0
        #wait some time for reauth
        #sleep(pyh3c.h3cStatus.ping_interval)
    else:
      dissconn_count = 0
  return

def check_online(pyh3c):
  """
  check to see whether the client is still online.
  """
  #spwan watcher here
  t = threading.Thread(group=None, target=watcher, name='watcher', args=(pyh3c,), kwargs={})
  t.daemon = True
  t.start()
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
  
