#!/usr/bin/env python
#
# Copyright 2011 Michael Cutler <m@cotdp.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import re
import pcapy
 
DEV          = 'eth0'
MAX_LEN      = 1500
PROMISCUOUS  = 1
READ_TIMEOUT = 100
PCAP_FILTER  = 'port 80'
MAX_PKTS     = -1
MY_IP        = '192.168.0.1'

def main():
    hostpattern = re.compile('Host\:\s+([\w\-\.]+)', re.IGNORECASE)
    uripattern = re.compile('[GEPOST]+ (.*?) HTTP/[\d\.]', re.IGNORECASE)
    def ph(hdr, data):
        host = None
        uri  = None
        match = hostpattern.search(data)
        if match != None:
            host = match.group(1)
        match = uripattern.search(data)
        if match != None:
            uri = match.group(1)
        if host != None and uri != None:
            if host != MY_IP:
                ip = '{0}.{1}.{2}.{3}'.format(ord(data[26]), ord(data[27]), ord(data[28]), ord(data[29]))
                ts = hdr.getts()
                print 'client=%s, when=%s, sz=%dB' % (ip, ts, len(data))
                print 'Url: http://%s%s' % (host, uri)
    # Start the capture
    p = pcapy.open_live(DEV, MAX_LEN, PROMISCUOUS, READ_TIMEOUT)
    p.setfilter(PCAP_FILTER)
    print "Listening on %s: net=%s, mask=%s" % (DEV, p.getnet(), p.getmask())
    p.loop(MAX_PKTS, ph)
 
if __name__ == "__main__":
    main()
