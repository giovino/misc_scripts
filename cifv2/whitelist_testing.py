#! /usr/bin/env python3

import re
import sys
import json
import subprocess
from pprint import pprint


observables = [
    { 'observable': 'bobby.com', 'otype': 'fqdn' },
    { 'observable': 'little.bobby.com', 'otype': 'fqdn' },
    { 'observable': 'http://www.bobby.com', 'otype': 'url' },
    { 'observable': '1.1.1.253', 'otype': 'ipv4' },
    { 'observable': 'bobby@bobby.com', 'otype': 'email' },
    { 'observable': '2001:4860:4860::8844', 'otype': 'ipv6' },
]

meta_data = {
            'tlp': 'amber',
            'confidence': '95',
            'provider': 'csirtgadgets.org',
            'group': 'everyone',
}


def get_api_key():

    r = subprocess.check_output(["/opt/cif/bin/cif-tokens"]).decode("utf-8")

    regex = r"(root@localhost\s+everyone\s+yes\s+yes\s+(\S+))"

    try:
        match = re.search(regex, r)
        return match.group(2)
    except AttributeError:
        print("ERROR: API key not found, exiting")
        sys.exit(1)


def create_dataset():

    l = []
    for record in observables:
        d = record
        
        for key, value in meta_data.items():
            d[key] = value
        l.append(d)

    return l


def submit_data(dataset, tag):

    for record in dataset:
        record['tags'] = tag
        json_encoded = json.dumps(record)

        rcode = subprocess.check_call('echo \'%s\' | cif --no-verify-ssl --remote https://localhost -s --token %s' % (json_encoded, api_key), shell=True)
        if rcode == 0:
            print("observable: {0}, tag: {1} submitted successfully".format(record['observable'], record['tags']))
        else:
            print("ERROR submitting: observable: {0}, tag: {1}".format(record['observable'], record['tags']))


def check_feed():
    
    for record in observables:
        print("Generated feed for otype: {0}".format(record['otype']))
        result = subprocess.check_output(["cif",
                                          "--feed",
                                          "--otype",
                                          "%s" %record['otype'],
                                          "-c",
                                          "85",
                                          "-f",
                                          "json", ])
        
        result = json.loads(result.decode("utf-8"))
    
        for record1 in result:
            if record['observable'] == record1['observable']:
                print("ERROR: {0} found in feed: {1}".format(record['observable'], record1['observable']))
        else:
            print("{0} not found in {1} feed".format(record['observable'], record['otype']))


if __name__ == "__main__":

    # get an api key with the 'write" attribute
    api_key = get_api_key()

    # create an list of dicts that contain indicator data used for whitelist
    # testing
    dataset = create_dataset()

    # submit malware indicators
    submit_data(dataset, 'malware')

    # submit whitelist indicators
    submit_data(dataset, 'whitelist')

    # test for whitelisted indicators in feed
    check_feed()
