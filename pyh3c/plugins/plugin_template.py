# -*- coding:utf8 -*-
#!/usr/bin/env python

def before_auth(pyh3c):
  print "before_auth function runs here"
  return

def after_auth_succ(pyh3c):
  print "after_auth_succ function runs here"
  return

def after_auth_fail(pyh3c):
  print "after_auth_fail function runs here"
  return
