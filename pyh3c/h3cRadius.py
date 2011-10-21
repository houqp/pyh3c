#!/usr/bin/env python
# -*- coding:utf-8 -*-

__author__ = "houqp"
__license__ = "GPL"
__version__ = "0.1"
__maintainer__ = "houqp"
__email__ = "qingping.hou@gmail.com"

import dpktMini

class RADIUS_H3C(dpktMini.Packet):
        __hdr__ = (
                ('code', 'B', 0),
                ('id', 'B', 0),
                ('len', 'H', 4),
                )
        class EAP(dpktMini.Packet):
                __hdr__ = (
                        ('code', 'B', 0),
                        ('id', 'B', 0),
                        ('len', 'H', 4),
                        ('type', 'B', 0)
                )

