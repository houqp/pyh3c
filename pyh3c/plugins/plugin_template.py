#!/usr/bin/env python
# -*- coding:utf8 -*-

# ===============================================================
#
# This is a plugin template, currently, we have 3 hooks in pyh3c:
# 
#  * before_auth() will be called just before sending start authentication packet.
#
#  * after_auth_succ() will be called after received authentication succed packet.
#
#  * after_auth_fail() will be called after received authentication failed packet.
# 
#  You can create your own section in pyh3c.conf for your plugin
#  and parse it with ConfigParser module.
#
# ===============================================================
#
# Here are some attributes that you may want to use in your functions:
#  pyh3c.h3cStatus: 
#    A h3cStatus instance 
#
#  pyh3c.plugins_loaded: 
#    A list containning objects for loaded plugins.
#
#  pyh3c.lock_file:
#    A string, path for lock file
#
#  pyh3c.h3cStatus.dev:
#    String, name for selected network interface 
#
#  pyh3c.h3cStatus.hwadd:
#    String, hardware address for pyh3c.h3cStatus.dev.
#
#  pyh3c.h3cStatus.user_name:
#    String, user name of the account
#
#  pyh3c.h3cStatus.user_pass:
#    String, user pass of the account
#
#  pyh3c.h3cStatus.dhcp_command:
#    String, command used to acquire dynamic ip
#
#  pyh3c.h3cStatus.plugins_to_load:
#    List of string, each string is the name for plugins 
#    that user want to load. Its content is initialized 
#    according to pyh3c.conf, more specifically, according 
#    to plugins option in sys_conf section.
#
#  pyh3c.h3cStatus.ping_target:
#    String, can be ip address or domain. Should be 
#    self-explanatory.
#
#  pyh3c.h3cStatus.ping_interval:
#    Int, time interval between each ping action, in seconds
#
#  pyh3c.h3cStatus.ping_tolerence:
#    Int, maxium ping failed time. When exceed this value,
#    authentication start packet will be resent.
#
#  pyh3c.h3cStatus.auth_success:
#    Int, 1 for successful authentication, 0 for not 
#    yet authenticated.
#
#  pyh3c.h3cStatus.parser:
#    A SafeConfigParser instance, used to manipulate 
#    configuration.

def before_auth(pyh3c):
  print "before_auth function runs here"
  return

def after_auth_succ(pyh3c):
  print "after_auth_succ function runs here"
  return

def after_auth_fail(pyh3c):
  print "after_auth_fail function runs here"
  return
