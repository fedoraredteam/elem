import os
import csv

class FileListing(object):
    def __init__(self, data_location, file_listing):
        self.data_location = data_location
        self.file_listing = file_listing
        self.file_listing_path = os.path.join(self.data_location, self.file_listing)
        self.listing = dict()
        self.read()

    def read(self):
        if self.file_listing.endswith('.csv'):
            self.read_csv()
        elif self.file_listing.endswith('.json'):
            self.read_json()

    def write(self):
        if self.file_listing.endswith('.csv'):
            self.write_csv()
        elif self.file_listing.endswith('.json'):
            self.write_json()

    def read_json(self):
        pass

    def read_csv(self):
        with open(self.file_listing_path, "rb") as csv_obj:
            reader = csv.DictReader(csv_obj, delimiter=',')
            for line in reader:
                self.listing[line['id']] = dict(file=line['file'],
                                                platform=line['platform'])

    def write_json(self):
        pass
    
    def write_csv(self):
        data = [['id', 'file', 'platform']]
        for line_id in self.listing.keys():
            line = []
            line.append(line_id)
            line.append(self.listing[line_id]['file'])
            data.append(line)
        with open(self.file_listing_path, "wb") as csv_obj:
            writer = csv.writer(csv_obj, delimiter=',')
            for line in data:
                writer.writerow(line)

    def filter_listing(self, platform_filter=[]):
        new_dict = dict((lineid, listing) for lineid, listing in self.listing.iteritems()
                        if listing['platform'] not in platform_filter)
        return new_dict
