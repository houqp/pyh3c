# -*- coding:utf-8 -*-
#!/usr/bin/env python

__author__ = "houqp"
__license__ = "GPL"
__version__ = "0.1"
__maintainer__ = "houqp"
__email__ = "qingping.hou@gmail.com"

import dpkt

class RADIUS_H3C(dpkt.Packet):
    __hdr__ = (
        ('code', 'B', 0),
        ('id', 'B', 0),
        ('len', 'H', 4),
        )
    class EAP(dpkt.Packet):
        __hdr__ = (
            ('code', 'B', 0),
            ('id', 'B', 0),
            ('len', 'H', 4),
            ('type', 'B', 0)
        )

