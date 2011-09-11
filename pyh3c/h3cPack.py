# -*- coding:utf-8 -*-
#!/usr/bin/env python

import dpkt

from h3cRadius import *

__author__ = "houqp"
__license__ = "GPL"
__version__ = "1.1"
__maintainer__ = "houqp"
__email__ = "qingping.hou@gmail.com"

def pack_ether(_src, _dst, _radius):
  """
  construct and return a radius header.
  _src is the source address of the frame, in binary
  _dst is the destination address of the frame, in binary
  _radius is a RADIUS_H3C object, not a string
  """
  _ether = dpkt.ethernet.Ethernet(
        src = _src,
        dst = _dst,
        type = 0x888e,
        data = str(_radius)
      )
  return _ether

def pack_radius(_code, _id, _eap=None):
  """
  construct and return a radius header.
  _code, _id should be selfexplanatory
  _len is the length of eap Packet
  _eap is a RADIUS_H3C.EAP object, not a string
  """
  if not _eap:
    _radius = RADIUS_H3C(
          code = _code,
          id = _id,
          len = 0,
          data = ""
        )
  else:
    _radius = RADIUS_H3C(
          code = _code,
          id = _id,
          len = _eap.len,
          data = str(_eap)
        )
  return _radius

def pack_eap(_code, _id, _type, _auth_data):
  """
  construct and return a radius header.
  _code, _id, _type, _auth_data should be selfexplanatory
  """
  _len = 5 + len(_auth_data)
  _eap = RADIUS_H3C.EAP(
        code = _code,
        id = _id,
        len = _len,
        type = _type,
        data = _auth_data
      )
  return _eap
