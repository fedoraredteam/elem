import ConfigParser
import argparse
from resource import ResourceManager
from resource import ExploitManager
from resource import CurationManager
from resource import SecurityApi
from resource import AssessmentManager
from resource import MANAGER_GIT
from resource import MANAGER_URL
import logging
import sys
from os.path import expanduser
import os
import shutil

DEFAULT_CONFIG_FILE='./config/elem.conf'

class Elem(object):
    def __init__(self, cli_args=None, config=None):
        self.cli_args = cli_args
        self.config = config
        self.security_apis = dict()
        self.curation_manager = None
        self.exploit_managers = dict()
        self.tlsverify = not cli_args.notlsverify
        self.console_logger = logging.getLogger('console')
        
        for section in config.sections():
            if section.startswith('security-api'):
                name = section.split(':')[1]
                security_api = SecurityApi(name, 
                                    self.config.get(section, 'url'), 
                                    self.config.get(section, 'location'), 
                                    self.tlsverify)
                self.security_apis[name] = security_api

            elif section.startswith('curation-data') and not self.curation_manager:
                name = section.split(':')[1]
                if self.config.has_option(section, 'git'):
                    curation_manager = CurationManager(name,  
                                                 self.config.get(section, 'git'), 
                                                 self.config.get(section, 'location'),
                                                 file_listing=self.config.get(section, 'file_listing'), 
                                                 config_option='git',
                                                 tlsverify=self.tlsverify)
                elif self.config.has_option(section, 'url'):
                     curation_manager = CurationManager(name,  
                                                 self.config.get(section, 'url'), 
                                                 self.config.get(section, 'location'), 
                                                 file_listing=self.config.get(section, 'file_listing'),
                                                 config_option='url',
                                                 tlsverify=self.tlsverify)

                self.curation_manager = curation_manager

            elif section.startswith('exploits-source'):
                name = section.split(':')[1]
                
                if self.config.has_option(section, 'git'):
                    exploit_manager = ExploitManager(name,  
                                                 self.config.get(section, 'git'), 
                                                 self.config.get(section, 'location'),
                                                 file_listing=self.config.get(section, 'file_listing'), 
                                                 config_option='git',
                                                 tlsverify=self.tlsverify)
                elif self.config.has_option(section, 'url'):
                     exploit_manager = ExploitManager(name,  
                                                 self.config.get(section, 'url'), 
                                                 self.config.get(section, 'location'), 
                                                 file_listing=self.config.get(section, 'file_listing'),
                                                 config_option='url',
                                                 tlsverify=self.tlsverify)

                self.exploit_managers[name] = exploit_manager

    def refresh(self):
        if self.curation_manager.kind() == MANAGER_GIT:
            self.curation_manager.get_data()
            self.curation_manager.load_data()

        for manager in self.exploit_managers.keys():
            if self.exploit_managers[manager].kind() == MANAGER_GIT:
                self.exploit_managers[manager].get_data()
                self.exploit_managers[manager].load_data()
                if self.curation_manager.kind() == MANAGER_GIT:
                    for eid in self.exploit_managers[manager].data.keys():
                        if eid not in self.curation_manager.data.keys():
                            self.curation_manager.data[eid] = \
                                self.exploit_managers[manager].data[eid]

                        for cveid in self.exploit_managers[manager].data[eid]['cves']:
                            if cveid not in self.curation_manager.data[eid]['cves']:
                                self.curation_manager.data[eid]['cves'].append(cveid)
                        self.curation_manager.save_data(eid)
                self.console_logger.info("Total Listing: " + str(self.exploit_managers[manager].total_listing()))
                self.console_logger.info("Potentially Relevant Listing: " + str(self.exploit_managers[manager].total_relevant()))
                self.console_logger.info("Potentially Relevant with CVEs: " + str(self.exploit_managers[manager].total_with_cves()))

    def show(self, eids=[], cves=[]):
        self.curation_manager.get_data()
        self.curation_manager.load_data()
        lines = []
        if len(eids) > 0:
            filtered_data = self.curation_manager.exploits_by_ids(eids)
            lines += self.curation_manager.list_data(filtered_data)
        if len(cves) > 0:
            filtered_data = self.curation_manager.exploits_by_cves(cves)
            lines += self.curation_manager.list_data(filtered_data)
        if len(eids) == 0 and len(cves) == 0:
            lines = self.curation_manager.list_data()

        for line in lines:
            self.console_logger.info(line)

    def score(self,
              edbid,
              cpe,
              score_kind,
              score):
        try:
            if self.curation_manager.kind() == MANAGER_GIT:
                self.curation_manager.get_data()
                self.curation_manager.load_data()
            else:
                self.console_logger.error("\nIn order to score exploits, the curation manager must be configured as a Git repo.  Please reconfigure the curation manager and run: elem refresh\n")
                sys.exit(1)
        except OSError:
            self.console_logger.error("\nNo exploit information loaded.  "
                                      "Please try: elem refresh\n")
            sys.exit(1)
        if 'Not Detected' in cpe:
            self.console_logger.error("\nThe CPE was neither detected nor provided.  Please provide a CPE with the --cpe option.\n")
            sys.exit(1)

        self.curation_manager.score(edbid, cpe, score_kind, score)
        self.curation_manager.save_data(edbid)

    def stage(self, eid, cpe, command, selinux, packages, services):
        try:
            if self.curation_manager.kind() == MANAGER_GIT:
                self.curation_manager.get_data()
                self.curation_manager.load_data()
            else:
                self.console_logger.error("\nIn order to set staging information for exploits, the curation manager must be configured as a Git repo.  Please reconfigure the curation manager and run: elem refresh\n")
                sys.exit(1)
        except OSError:
            self.console_logger.error("\nNo exploit information loaded.  "
                                      "Please try: elem refresh\n")
            sys.exit(1)
        if 'Not Detected' in cpe:
            self.console_logger.error("\nThe CPE was neither detected nor provided.  Please provide a CPE with the --cpe option.\n")
            sys.exit(1)
        

        if len(command) > 0:
            self.curation_manager.set_staging(eid, cpe, command)
        if selinux is not None:
            self.curation_manager.set_selinux(eid, cpe, selinux)
        if len(packages) > 0:
            self.curation_manager.set_packages(eid, cpe, packages)
        if len(services) > 0:
            self.curation_manager.set_services(eid, cpe, services)
        self.curation_manager.save_data(eid)
        
    
    def assess(self):
        self.curation_manager.get_data()
        self.curation_manager.load_data()

        assessment_manager = AssessmentManager()
        assessment_manager.assess()

        exploits = []
        lines = []
        filtered_data = self.curation_manager.exploits_by_cves(assessment_manager.assessed_cves)
        lines += self.curation_manager.list_data(filtered_data)

        for line in lines:
            self.console_logger.info(line)


    def copy(self, source, eids, destination, stage=False, cpe=''):

        if 'Not Detected' in cpe:
            self.console_logger.error("\nThe CPE was neither detected nor provided.  Please provide a CPE with the --cpe option.\n")
            sys.exit(1)
        self.curation_manager.load_data()

        for eid in eids:
            fullpath = os.path.join(self.exploit_managers[source].manager_path,
                                    self.exploit_managers[source].file_listing.listing[eid]['file'])
            self.console_logger.info("Copying from %s to %s." % (fullpath, destination))
            shutil.copy(fullpath, destination)
            if stage and cpe is not '':
                success, msg = self.curation_manager.stage(eid,
                                                           destination,
                                                           cpe)
                if success:
                    self.console_logger.info("Successfuly staged exploit %s" %
                                             (eid))
                else:
                    self.console_logger.info("Unsuccessfuly staged exploit " +
                                             "%s with error message %s." %
                                             (eid, str(msg)))
            elif stage and cpe is '':
                self.console_logger.warn("CPE is undefined so unable to "
                                         "stage %s" % eid)
            


class ConfigurationHandler(object):
    def __init__(self, config_file=''):
        if config_file is not '':
            self.config_file = DEFAULT_CONFIG_FILE

    def read_config(self):
        config = ConfigParser.ConfigParser()
        config.readfp(open(self.config_file))
        return config


class CliHandler(object):
    def __init__(self):

        self.parser = argparse.ArgumentParser(description='Cross Reference CVE\'s ' +
                                              'against a Exploit-DB entries for ' +
                                              'Enterprise Linux.')

        self.parser.add_argument('--notlsverify',
                                 action='store_true',
                                 help='Do not use TLS when querying Security API\'s')

        self.parser.add_argument('--config',
                                 required=False,
                                 default=DEFAULT_CONFIG_FILE,
                                 help='Configuration file to use')

        subparsers = self.parser.add_subparsers()
        refresh_parser = subparsers.add_parser('refresh')
        refresh_parser.set_defaults(which='refresh')

        list_parser = subparsers.add_parser('list')
        list_parser.set_defaults(which='list')
        list_parser.add_argument('--eids',
                                 help="The exploit ID's on which to filter.",
                                 required=False,
                                 nargs='*',
                                 default=[],
                                 type=str)
        list_parser.add_argument('--cveids',
                                 help="The CVE ID(s) on which to filter.",
                                 required=False,
                                 nargs='*',
                                 default=[],
                                 type=str)

        score_parser = subparsers.add_parser('score')
        score_parser.set_defaults(which='score')
        score_parser.add_argument('--eid',
                                help='Which exploit to score',
                                required=True,
                                type=str)
        score_parser.add_argument('--cpe',
                                required=False,
                                default=self.read_cpe(),
                                type=str)
        score_parser.add_argument('--kind',
                                required=False,
                                default='stride',
                                choices=['stride'],
                                help='Threat Score Kind',
                                type=str)
        score_parser.add_argument('--value',
                                required=True,
                                help='Threat Score',
                                type=str)

        staging_parser = subparsers.add_parser('stage')
        staging_parser.set_defaults(which='stage')
        staging_parser.add_argument('--eid',
                                    help='Which exploit on which to set staging information.',
                                    required=True,
                                    type=str)
        staging_parser.add_argument('--cpe',
                                    required=False,
                                    default=self.read_cpe(),
                                    type=str)
        staging_parser.add_argument('--packages',
                                    help="The packages needed to support this exploit",
                                    required=False,
                                    nargs='*',
                                    default=[],
                                    type=str)
        staging_parser.add_argument('--services',
                                    help="The services needed to support this exploit",
                                    required=False,
                                    nargs='*',
                                    default=[],
                                    type=str)
        staging_parser.add_argument('--selinux',
                                    required=False,
                                    choices=['enforcing', 'permissive'],
                                    help='SELinux state for this exploit to work.',
                                    type=str)
        staging_parser.add_argument('--command',
                                    help="The command used to stage the exploit",
                                    required=False,
                                    nargs=argparse.REMAINDER,
                                    type=str)

        copy_parser = subparsers.add_parser('copy')
        copy_parser.set_defaults(which='copy')
        copy_parser.add_argument('--destination',
                                required=False,
                                default=expanduser("~"),
                                type=str)
        copy_parser.add_argument('--eids',
                                help='Which exploit(s) to copy',
                                required=True,
                                nargs='*',
                                type=str)
        copy_parser.add_argument('--stage',
                                required=False,
                                action='store_true',
                                help="Stage the exploit if exploit info is avaialble.")
        copy_parser.add_argument('--cpe',
                                required=False,
                                default=self.read_cpe(),
                                type=str)
        copy_parser.add_argument('--source',
                                required=False,
                                default='exploit-database',
                                type=str)

        assess_parser = subparsers.add_parser('assess')
        assess_parser.set_defaults(which='assess')

    def read_config(self):
        args = self.parser.parse_args()
        return args

    def read_cpe(self):
        file_name = '/etc/system-release-cpe'
        try:
            with open(file_name, 'r') as cpe_file:
                return cpe_file.read().replace('\n','')
        except IOError:
            return 'Not Detected'