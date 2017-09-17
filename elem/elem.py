#!/usr/bin/python

from exploit_database import ExploitDatabase
from security_api import SecurityAPI

import sys
import subprocess
import re
import log


class Elem(object):
    def __init__(self, args):
        self.args = args
        self.logger = log.setup_custom_logger('elem')
        self.console_logger = log.setup_console_logger('console')
        self.exploitdb = ExploitDatabase(self.args.exploitdb,
                                         self.args.exploits,
                                         self.args.exploitdbrepo)

    def run(self):

        if hasattr(self.args, 'refresh'):
            self.refresh(self.args.securityapi)
        elif hasattr(self.args, 'list'):
            self.list_exploits(self.args.edbid,
                               self.args.cveid)
        elif hasattr(self.args, 'score'):
            self.score_exploit(self.args.edbid,
                               self.args.version,
                               self.args.kind,
                               self.args.value)
        elif hasattr(self.args, 'assess'):
            self.assess()

    def refresh(self,
                security_api_url):

        self.exploitdb.refresh_repository()
        self.exploitdb.refresh_exploits_with_cves()

        securityapi = SecurityAPI(security_api_url)
        securityapi.refresh()

        for cve in securityapi.cve_list:
            for edbid in self.exploitdb.exploits.keys():
                if cve in self.exploitdb.exploits[edbid]['cves'].keys():
                    self.exploitdb.exploits[edbid]['cves'][cve]['rhapi'] = True
                    self.exploitdb.write(edbid)

    def list_exploits(self, edbid_to_find=None, cveid_to_find=None):
        results = []

        if edbid_to_find:
            if self.exploitdb.affects_el(edbid_to_find):
                results += self.exploitdb.get_exploit_strings(edbid_to_find)
            else:
                self.console_logger.warn("Exploit ID %s does not appear "
                                         "to affect enterprise Linux." %
                                         edbid_to_find)
                sys.exit(0)

        if cveid_to_find:
            exploit_ids = self.exploitdb.exploits_by_cve(cveid_to_find)
            for edbid in exploit_ids:
                results += self.exploitdb.get_exploit_strings(edbid)
            if len(exploit_ids) == 0:
                self.console_logger.warn("There do not appear to be any "
                                         "exploits that affect CVE %s."
                                         % cveid_to_find)


        if not edbid_to_find and not cveid_to_find:
            for edbid in self.exploitdb.exploits.keys():
                if self.exploitdb.affects_el(edbid):
                    results += self.exploitdb.get_exploit_strings(edbid)


        for line in results:
            self.console_logger.info(line)

    def score_exploit(self,
                      edbid,
                      version,
                      score_kind,
                      score):
        self.exploitdb.score(edbid, version, score_kind, score)
        self.exploitdb.write(edbid)

    def assess(self):
        assessed_cves = []
        lines = []
        error_lines = []
        try:
            command = ["yum", "updateinfo", "list", "cves"]
            p = subprocess.Popen(command,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            out, err = p.communicate()
            lines = out.split('\n')
            error_lines = err.split('\n')
        except OSError:
            self.logger.error("\'assess\' may only be "
                              "run on an Enterprise Linux host.")
            sys.exit(1)
        pattern = re.compile('\s(.*CVE-\d{4}-\d{4,})')
        for line in lines:
            result = re.findall(pattern, line)
            if result and result[0] not in assessed_cves:
                assessed_cves.append(result[0])

        for cveid in assessed_cves:
            edbids = self.exploitdb.exploits_by_cve(cveid)
            for edbid in edbids:
                strings = self.exploitdb.get_exploit_strings(edbid)
                for string in strings:
                    self.console_logger.info(string)
