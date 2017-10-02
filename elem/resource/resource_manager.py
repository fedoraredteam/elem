import os
import sys
import logging
import json
import requests
from git import Repo
from git.repo import fun

from resource import MANAGER_URL
from resource import MANAGER_GIT
from resource import UNIX_EPOCH


class ResourceManager(object):
    def __init__(self, name, remote_location, data_location, kind, file_listing='', tlsverify=True):
        self.name = name
        self.remote_location = remote_location
        self.kind = kind
        self.data_location = data_location
        self.file_listing = file_listing
        self.logger = logging.getLogger('elem')
        self.tlsverify = tlsverify

    @classmethod
    def git_resource_manager(cls, name, repo, data_location, file_listing="", tlsverify=True, kind=MANAGER_GIT):
        return GitResourceManager(name, repo, data_location, file_listing, tlsverify, kind)

    @classmethod
    def url_resource_manager(cls, name, url, data_location, file_listing="", tlsverify=True, kind=MANAGER_URL):
        return UrlResourceManager(name, url, data_location, file_listing, tlsverify, kind)

class UrlResourceManager(ResourceManager):
    def __init__(self, name, url, data_location, file_listing="", tlsverify=True, kind=MANAGER_URL):
        super(UrlResourceManager, self).__init__(name, url, data_location, kind, file_listing)
        self.tlsverify = tlsverify

    def get_data(self, path='', params=[]):
        url = self.remote_location
        if path is not '':
            url += '/'
            url += path
        if len(params) > 0:
            url += '?'
            for param in params:
                url += param
                url += '&'
        r = requests.get(url, verify=self.tlsverify)

        if r.status_code != 200:
            self.logger.error('ERROR: Invalid request; returned {} for the '
                              'following query:\n{}'.format(r.status_code,
                                                            url))
            sys.exit(1)

        if not r.json():
            self.logger.warn('No data returned with the following '
                             'query: %s' % url)
            sys.exit(0)

        return r.json()


class GitResourceManager(ResourceManager):
    def __init__(self, name, repo, data_location, file_listing='', tlsverify=True, kind=MANAGER_GIT):
        super(GitResourceManager, self).__init__(name, repo, data_location, file_listing=file_listing, kind=kind)
        
    def get_data(self):
        repo = None
        origin = None
        if fun.is_git_dir(self.data_location):
            repo = Repo(self.data_location)
        else:
            repo = Repo.init(self.data_location)

        try:
            origin = repo.remote('origin')
        except ValueError:
            origin = repo.create_remote('origin', self.remote_location)
        origin.fetch()

        if 'master' not in repo.heads:
            repo.create_head('master', origin.refs.master)
        repo.heads.master.set_tracking_branch(origin.refs.master)
        repo.heads.master.checkout()
        origin.pull()

