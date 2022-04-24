#!/usr/bin/python3
# -*- coding: UTF-8 -*- 

import os
import random
from scapy.all import *
from scapy.contrib import bgp

from .base_monitor import BaseMonitor


CMP_RSLT = {
    0: "EMPTY",
    1: "TYPE",
    2: "RCODE",
    3: "TSIG"
}

class RuntimeMonitor(BaseMonitor):
    """
    Logfile class: Monitor the logfile of a target

    .. deprecated:: 0.2.0
       This class is a shortcut with limited capabilities. It should be
       substituted by custom classes that implement BaseMonitor.
    """

    def __init__(self, saveResp=None, saveTestcase=None, cmpResp=None, logfile=None, protocol=None):
        """
        @type  saveResp: str
        @param saveResp: Folder to save current response
        @type  saveTestcase: str
        @param saveTestcase: Folder to save current response
        @type  cmpResp:  str
        @param cmpResp:  Folder to save response that will compared to
        @type  logfile:  str
        @param logfile:  File to record differences with response
        @type  protocol:  str
        @param protocol:  Protocol the processing packtes belong to
        """
        BaseMonitor.__init__(self)

        self.saveResp = saveResp
        self.saveTestcase = saveTestcase
        self.cmpResp = cmpResp
        self.logfile = logfile
        self.protocol = protocol
        self.__dbg_flag = False


    def save_resp(self, cur_resp, resp_name):
        """ save current response """

        idx = resp_name.rfind(".")
        fileName = self.saveResp + str(resp_name) + ".raw"
        if not os.path.exists(os.path.split(fileName)[0]):
            os.makedirs(os.path.split(fileName)[0])
        with open(fileName, 'ab+') as fd:
            fd.write(cur_resp)

    def save_testcase(self, testcase, testcase_id):
        """ save current response """

        fileName = self.saveTestcase + str(testcase_id) + ".raw"
        if not os.path.exists(os.path.split(fileName)[0]):
            os.makedirs(os.path.split(fileName)[0])
        with open(fileName, 'ab+') as fd:
            fd.write(testcase)


    def cmp_resps(self, cur_resp, cmp_resp):
        """ Compare parsed packets"""

        #------------- DNS packets -------------#
        if self.protocol == "DNS":
            origin_pkt = DNS(cmp_resp)
            cur_pkt = DNS(cur_resp)
            # compair RCODE 
            if origin_pkt.rcode != cur_pkt.rcode:
                return CMP_RSLT[2]
            # compair MAC if has a tsig section
            if origin_pkt.tsig and cur_pkt.tsig:
                if not (origin_pkt.tsig.mac and cur_pkt.tsig.mac):
                    return CMP_RSLT[3]

        #------------- BGP packets -------------#
        elif self.protocol == "BGP":
            origin_pkt = scapy.contrib.bgp.BGP(cmp_resp)
            cur_pkt = scapy.contrib.bgp.BGP(cur_resp)
            # compair packet TYPE
            if origin_pkt.type != cur_pkt.type:
                return CMP_RSLT[1]
            # compair ERROR_CODE and SUBCODE
            elif origin_pkt.type == scapy.contrib.bgp.BGP.NOTIFICATION_TYPE:
                origin_notify_pkt = scapy.contrib.bgp.BGPNotification(cmp_resp[19:])
                cur_notify_pkt = scapy.contrib.bgp.BGPNotification(cur_resp[19:])
                if origin_notify_pkt.error_code != cur_notify_pkt.error_code or origin_notify_pkt.error_subcode != cur_notify_pkt.error_subcode:
                    return CMP_RSLT[2]

        #------------- OSPF packets ------------#
        # TODO
        elif self.protocol == "OSPF":
            origin_pkt = scapy.contrib.ospf.OSPF_Hdr(cmp_resp[:24])
            cur_pkt = scapy.contrib.ospf.OSPF_Hdr(cur_resp[:24])


        #------------- DHCP packets ------------#
        # TODO
        return None


    def log_cmp_result(self, resp_name, reslt_type):

        with open(self.logfile, 'a+', encoding='utf-8') as fd:
            fd.write("\n----------------------\n")
            fd.write("\nTest case %s : diff %s" % (resp_name, reslt_type))
        return


    def check_resp(self, resp_name, cur_resp):
        """ Compare the current response with response in the specify file """
        idx = resp_name.rfind(".")
        resp_name = resp_name + ".raw"
        cur_mutant = resp_name.split(".")[-3]
        cmp_file = b''
        cmp_resp = b''

        if resp_name in os.listdir(self.cmpResp):
            cmp_file = os.path.join('%s/%s'% (self.cmpResp, resp_name))
        # else:
        #     for i in range(10):
        #         tmp_idx = int(resp_name.split(".")[-2])
        #         tmp_idx += 1
        #         tmp_resp_name = resp_name[:idx] +  "." + str(tmp_idx) + ".raw"
        #         if tmp_resp_name in os.listdir(self.cmpResp):
        #             cmp_file = os.path.join('%s/%s'% (self.cmpResp, tmp_resp_name))
        #             break

        if cmp_file:
            with open(cmp_file, 'rb') as fd:
                fd.seek(0)
                cmp_resp = fd.read()
        # else:
        #     self.log_cmp_result(resp_name, CMP_RSLT[0])

        if cur_resp == b'' or cmp_resp == b'':
            if cur_resp == b'' and cmp_resp == b'':
                pass
            else:
                self.log_cmp_result(resp_name, CMP_RSLT[0])
        else:
            cmp_result = self.cmp_resps(cur_resp, cmp_resp)
            if cmp_result:
                self.log_cmp_result(resp_name, cmp_result)

        return