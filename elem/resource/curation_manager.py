import os
import json
import subprocess
import sys
from resource import UrlResourceManager
from resource import GitResourceManager
from resource import MANAGER_GIT
from resource import FileListing
import logging

class CurationManager(object):
    def __init__(self, name, url, data_location, file_listing, config_option='url', tlsverify=True):
        self.config_option = config_option
        self.data_location = data_location
        self.name = name
        self.file_listing = FileListing(data_location, file_listing)
        if config_option is 'url':
            self.manager = UrlResourceManager(name, url, data_location, file_listing, tlsverify)
        elif config_option is 'git':
            self.manager = GitResourceManager(name, url, data_location, file_listing, tlsverify)
        self.data = dict()
        self.logger = logging.getLogger('elem')

    def get_data(self):
       self.manager.get_data()

    def load_data(self):
        for eid in self.file_listing.listing:
            file_path = os.path.join(self.data_location, 
                                     self.file_listing.listing[eid]['file'])
            with open(os.path.join(file_path), "r") as curation_file:
                if eid not in self.data.keys():
                    self.data[eid] = json.load(curation_file)

    def save_data(self, eid):
        source = self.data[eid]['source']
        file_name = os.path.join(self.data_location, source, eid + '.json')
        with open(file_name, "w") as curation_file:
            json.dump(self.data[eid], curation_file, indent=4, sort_keys=True)
            if eid not in self.file_listing.listing.keys():
                self.file_listing.listing[eid] = dict()
            self.file_listing.listing[eid]['file'] = os.path.join(source, eid + '.json')
            self.file_listing.listing[eid]['platform'] = ''
            self.file_listing.write()

    def list_data(self, filtered_data=None):
        if filtered_data is None:
            filtered_data = self.data
        strings = []
        for eid in filtered_data.keys():
            strings += self.exploit_strings(eid)
        return strings

    def exploit_strings(self, eid):
        strings = []
        if 'cpes' not in self.data[eid].keys():
                string = eid
                strings.append(string)
        else:
            for cpe in self.data[eid]['cpes'].keys():
                for kind in self.data[eid]['cpes'][cpe]['scores'].keys():
                    string = eid
                    string += ","
                    string += cpe
                    string += ","
                    string += kind
                    string += ','
                    string += self.data[eid]['cpes'][cpe]['scores'][kind]
                    strings.append(string)
        return strings


    def exploits_by_ids(self, eids):
        new_dict = dict((eid, exploit) for eid, exploit in self.data.iteritems() 
                        if eid in eids)
        return new_dict

    def exploits_by_cves(self, cveids):
        new_dict = dict((eid, exploit) for eid, exploit in self.data.iteritems()
                        if self.exploit_affected_by_cves(eid, cveids))
        return new_dict

    def exploit_affected_by_cves(self, eid, cveids):
        if not isinstance(cveids, list):
            cveids = [cveids]
        for cveid in cveids:
            if cveid in self.data[eid]['cves']:
                return True
        return False

    def add_cpe(self, eid, cpe):
        if eid in self.data.keys():
            if 'cpes' not in self.data[eid].keys():
                self.data[eid]['cpes'] = dict()

            if cpe not in self.data[eid]['cpes'].keys():
                self.data[eid]['cpes'][cpe] = dict()

    def set_packages(self, eid, cpe, packages):
        self.add_cpe(eid, cpe)
        self.data[eid]['cpes'][cpe]['packages'] = packages

    def set_services(self, eid, cpe, services):
        self.add_cpe(eid, cpe)
        self.data[eid]['cpes'][cpe]['services'] = services

    def set_staging(self, eid, cpe, staging):
        self.add_cpe(eid, cpe)
        self.data[eid]['cpes'][cpe]['staging'] = staging

    def set_selinux(self, eid, cpe, selinux):
        self.add_cpe(eid, cpe)
        self.data[eid]['cpes'][cpe]['selinux'] = selinux
    
    def score(self, eid, cpe, kind, value):
        self.add_cpe(eid, cpe)
        if 'scores' not in self.data[eid]['cpes'][cpe].keys():
            self.data[eid]['cpes'][cpe]['scores'] = dict()
        
        self.data[eid]['cpes'][cpe]['scores'][kind] = value

    def kind(self):
        return self.manager.kind

    def stage(self, eid, destination, cpe):
        if 'staging' not in self.data[eid]['cpes'][cpe]:
            return False, "No staging information available."

        try:
            command = ' '.join(self.data[eid]['cpes'][cpe]['staging'])
            p = subprocess.Popen(command,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 cwd=destination,
                                 shell=True)
            out, err = p.communicate()
            lines = out.split('\n')
            error_lines = err.split('\n')
        except OSError:
            self.logger.error("Command %s cannot be run on this host." %
                              self.data[eid]['cpes'][cpe]['staging'])
            sys.exit(1)
        if p.returncode != 0:
            return False, ','.join(error_lines)
        return True, lines
