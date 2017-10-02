import json
import dateutil.parser
from resource import UrlResourceManager

class SecurityApi(object):
    def __init__(self, name, url, data_location, tlsverify=True):
        self.manager = UrlResourceManager(name, url, data_location, tlsverify)

    def get_data(self, path='', params=[]):
        return self.manager.get_data(path, params)

    def get_cves_after(self, date):
        cves = []
        dict_cves = self.manager.get_data('cves.json', ['after='+str(date).split(' ')[0], 'per_page=20000'])
        for dict_cve in dict_cves:
            cves.append(dict_cve['CVE'])
        return sorted(cves)

    def get_cve(self, cveid):
        cve = self.manager.get_data('cve/'+cveid +'.json')
        return cve

    def kind(self):
        return self.manager.kind

    def latest_resource_date(self):
        result = self.manager.get_data('cve.json', ['per_page=1'])
        return dateutil.parser.parse(result[0]['public_date']).replace(tzinfo=None)