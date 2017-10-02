import subprocess
import sys
import re
import logging


class AssessmentManager(object):
    def __init__(self):
        self.assessed_cves = []
        self.logger = logging.getLogger('elem')
        
    def assess(self):
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
            if result and result[0] not in self.assessed_cves:
                self.assessed_cves.append(result[0])

        self.assessed_cves = list(set(self.assessed_cves))
