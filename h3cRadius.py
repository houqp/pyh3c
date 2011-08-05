# -*- coding:utf8 -*-
#!/usr/bin/env python

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

