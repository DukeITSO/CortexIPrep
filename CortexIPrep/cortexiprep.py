#!/usr/bin/env python
# encoding: utf-8

"""
Cortex Analyzer used to look up IP addresses against the Packetmail IP Reputation Service (Punch++). Not a public
resource, so you'll have to ask around for access.
"""
import requests
from cortexutils.analyzer import Analyzer


class CortexIPrep(Analyzer):
    def __init__(self):
        # Bootstrap our ancestor
        Analyzer.__init__(self)
        # Pull the API key from the application.conf config section
        self.api_key = self.getParam('config.key', None, 'API key is missing')
        # We don't want to extract observables for Hive from this
        self.auto_extract = False

    def summary(self, raw):
        """
        'raw' is the json that's returned in the report
        """
        total_reputation_observations = len(raw[ 'packetmail_iprep' ]) - 5
        taxonomies = [ ]
        level = "info"
        namespace = "IPRep"
        predicate = "TI"
        value = "Rep Hits: {0}".format(total_reputation_observations)
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {"taxonomies": taxonomies}

    def search_punch(self, ip, apikey):
        url = 'https://www.packetmail.net/iprep.php/{0}'.format(ip)
        p = {'apikey': apikey}

        r = requests.get(url, params=p)
        ret = dict(r.json())

        if ret['query_result'] != 'Success':
            raise Exception('Remote service returned unsuccessfully:{0}'.format(repr(ret)))

        # Remove keys we don't need; thanks to nathan@packetmail.net for the whitelist approach
        for key, value in ret.items():
          if not isinstance(value,dict) and not key == "_id" and not key == "created_on":
            ret.pop(key, None)
        return ret

    def run(self):
        """
        Run the analysis here
        """
        Analyzer.run(self)

        if self.data_type == 'ip':
            try:

                ## Just get some json, using the user input as the seach query
                iprep = self.search_punch(self.getData(), self.api_key)

                ## This gets put back to the summary report object
                self.report({
                    'packetmail_iprep': iprep
                })

            except ValueError as e:
                self.unexpectedError(e)
        else:
            self.notSupported()


if __name__ == '__main__':
    CortexIPrep().run()
