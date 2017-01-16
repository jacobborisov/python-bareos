"""
Communicates with the bareos-dir console
"""

from   bareos.bsock.connectiontype  import ConnectionType
from   bareos.bsock.lowlevel import LowLevel, coroutine_if
from asyncio import coroutine

class DirectorConsole(LowLevel):
    '''use to send and receive the response to Bareos File Daemon'''

    def __init__(self,
                 address="localhost",
                 port=9101,
                 dirname=None,
                 name="*UserAgent*",
                 password=None,
                 asyncio=False):
        super(DirectorConsole, self).__init__(asyncio)
        if asyncio:
            def establish():
                yield from self.connect(address, port, dirname, ConnectionType.DIRECTOR)
                yield from self.auth(name=name, password=password, auth_success_regex=b'^1000 OK.*$')
                yield from self._init_connection()
            self.establish = coroutine(establish)
        else:
            self.connect(address, port, dirname, ConnectionType.DIRECTOR)
            self.auth(name=name, password=password, auth_success_regex=b'^1000 OK.*$')
            self._init_connection()


    @coroutine_if('aio')
    def _init_connection(self):
        _ = self.call("autodisplay off")
        if self.aio: yield from _


    def get_to_prompt(self):
        self.send(b".")
        return super(DirectorConsole, self).get_to_prompt()
