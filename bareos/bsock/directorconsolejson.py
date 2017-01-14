"""
Reimplementation of the bconsole program in python.
"""

from   bareos.bsock.directorconsole import DirectorConsole, asyncio_switch
from   pprint import pformat, pprint
import json

class DirectorConsoleJson(DirectorConsole):
    """
    use to send and receive the response from director
    """

    def __init__(self, *args, **kwargs):
        super(DirectorConsoleJson, self).__init__(*args, **kwargs)

    @asyncio_switch
    def _init_connection(self):
        # older version did not support compact mode,
        # therfore first set api mode to json (which should always work in bareos >= 15.2.0)
        # and then set api mode json compact (which should work with bareos >= 15.2.2)
        call = self.call(".api json")
        call_compact = self.call(".api json compact=yes")
        self.logger.debug((yield from call) if self.aio else call)
        self.logger.debug((yield from call_compact) if self.aio else call_compact)


    @asyncio_switch
    def call(self, command):
        call = self.call_fullresult(command)
        json = (yield from call) if self.aio else call
        if json == None:
            return
        if 'result' in json:
            result = json['result']
        else:
            # TODO: or raise an exception?
            result = json
        return result


    @asyncio_switch
    def call_fullresult(self, command):
        call = super(DirectorConsoleJson, self).call(command)
        resultstring = (yield from call) if self.aio else call
        data = None
        if resultstring:
            try:
                data = json.loads(resultstring.decode('utf-8'))
            except ValueError as e:
                # in case result is not valid json,
                # create a JSON-RPC wrapper
                data = {
                    'error': {
                        'code': 2,
                        'message': str(e),
                        'data': resultstring
                    },
                }
        return data


    def _show_result(self, msg):
        pprint(msg)
