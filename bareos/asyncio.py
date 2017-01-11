import asyncio
import struct
import hmac
import random
import time
import re

from .bsock.lowlevel import LowLevel
from .bsock.directorconsole import DirectorConsole
from .util.bareosbase64 import BareosBase64
from .bsock.connectiontype import ConnectionType
from .bsock import Password
from .bsock.protocolmessages import ProtocolMessages
from .bsock.constants import Constants

from   pprint import pformat, pprint
import json

class AsyncConsole(DirectorConsole):
    def __init__(self):
        super(DirectorConsole, self).__init__()
        self.read_stream = None
        self.write_stream = None
        
    @classmethod
    @asyncio.coroutine
    def get_connection(cls, address="localhost",
                 port=9101,
                 dirname=None,
                 name="*UserAgent*",
                 password=None):
        con = cls()
        yield from con.connect(address, port, dirname, ConnectionType.DIRECTOR)
        yield from con.auth(name=name, password=password, auth_success_regex=b'^1000 OK.*$')
        yield from con._init_connection()
        return con
    
    @asyncio.coroutine
    def connect(self, address, port, dirname, type):
        self.address = address
        self.port = port
        if dirname:
            self.dirname = dirname
        else:
            self.dirname = address
        self.connection_type = type
        yield from self.__connect()
        
    @asyncio.coroutine
    def __connect(self):
        
        self.read_stream, self.write_stream = yield from asyncio.open_connection(host=self.address, port=self.port)
        
        # try:
        #     self.socket = socket.create_connection((self.address, self.port))
        # except socket.gaierror as e:
        #     self._handleSocketError(e)
        #     raise ConnectionError(
        #         "failed to connect to host " + str(self.address) + ", port " + str(self.port) + ": " + str(e))
        # else:
        #     self.logger.debug("connected to " + str(self.address) + ":" + str(self.port))
        # return True
        
    @asyncio.coroutine
    def call(self, command):
        '''
        call a bareos-director user agent command
        '''
        if isinstance(command, list):
            command = " ".join(command)
        return (yield from self.__call(command, 0))

    @asyncio.coroutine
    def __call(self, command, count):
        '''
        Send a command and receive the result.
        If connection is lost, try to reconnect.
        '''
        result = b''
        #try:
        yield from self.send(bytearray(command, 'utf-8'))
        result = yield from self.recv_msg()
        # except (SocketEmptyHeader, ConnectionLostError) as e:
        #     self.logger.error("connection problem (%s): %s" % (type(e).__name__, str(e)))
        #     if count == 0:
        #         if self.reconnect():
        #             return self.__call(command, count+1)
        return result
    
    @asyncio.coroutine
    def auth(self, name, password, auth_success_regex):
        '''
        login to the bareos-director
        if the authenticate success return True else False
        dir: the director location
        name: own name.
        '''
        if not isinstance(password, Password):
            raise AuthenticationError("password must by of type bareos.Password() not %s" % (type(password)))
        self.password = password
        self.name = name
        self.auth_success_regex = auth_success_regex
        return self.__auth()
    
    @asyncio.coroutine
    def __auth(self):
        bashed_name = ProtocolMessages.hello(self.name, type=self.connection_type)
        # send the bash to the director
        yield from self.send(bashed_name)

        (ssl, result_compatible, result) = yield from self._cram_md5_respond(password=self.password.md5(), tls_remote_need=0)
        if not result:
            raise AuthenticationError("failed (in response)")
        if not (yield from self._cram_md5_challenge(clientname=self.name, password=self.password.md5(), tls_local_need=0, compatible=True)):
            raise AuthenticationError("failed (in challenge)")
        yield from self.recv_msg(self.auth_success_regex)
        self.auth_credentials_valid = True
        return True
    
    @asyncio.coroutine
    def send(self, msg=None):
        '''use socket to send request to director'''
        
        msg_len = len(msg) # plus the msglen info
        
        self.write_stream.write(struct.pack("!i", msg_len) + msg)
        self.logger.debug("%s" %(msg))
        yield from self.write_stream.drain()
        
        # self.__check_socket_connection()
        # msg_len = len(msg) # plus the msglen info
        # 
        # try:
        #     # convert to network flow
        #     self.socket.sendall(struct.pack("!i", msg_len) + msg)
        #     self.logger.debug("%s" %(msg))
        # except socket.error as e:
        #     self._handleSocketError(e)
    
    @asyncio.coroutine
    def __get_header(self):
        #self.__check_socket_connection()
        header = yield from self.read_stream.readexactly(4)
        if len(header) == 0:
            self.logger.debug("received empty header, assuming connection is closed")
            raise SocketEmptyHeader()
        else:
            return self._LowLevel__get_header_data(header)
    
    @asyncio.coroutine
    def recv(self):
        '''will receive data from director '''
        # self.__check_socket_connection()
        # get the message header
        header = yield from self.__get_header()
        if header <= 0:
            self.logger.debug("header: " + str(header))
        # get the message
        length = header
        msg = yield from self.recv_submsg(length)
        return msg
    
    @asyncio.coroutine
    def recv_submsg(self, length):
        # get the message
        msg = yield from self.read_stream.readexactly(length)
        
        if (type(msg) is str):
            msg = bytearray(msg.decode('utf-8'), 'utf-8')
        if (type(msg) is bytes):
            msg = bytearray(msg)
        #self.logger.debug(str(msg))
        return msg
    
    @asyncio.coroutine
    def recv_msg(self, regex = b'^\d\d\d\d OK.*$', timeout = None):
        '''will receive data from director '''
        #self.__check_socket_connection()
        #try:
        timeouts = 0
        while True:
            # get the message header
            #self.socket.settimeout(0.1)
            #try:
            header = yield from self.__get_header()
            # except socket.timeout:
            #     # only log every 100 timeouts
            #     if timeouts % 100 == 0:
            #         self.logger.debug("timeout (%i) on receiving header" % (timeouts))
            #     timeouts+=1
            # else:
            if header <= 0:
                # header is a signal
                self._LowLevel__set_status(header)
                if self.is_end_of_message(header):
                    result = self.receive_buffer
                    self.receive_buffer = b''
                    return result
            else:
                # header is the length of the next message
                length = header
                self.receive_buffer += yield from self.recv_submsg(length)
                # Bareos indicates end of command result by line starting with 4 digits
                match = re.search(regex, self.receive_buffer, re.MULTILINE)
                if match:
                    self.logger.debug("msg \"{0}\" matches regex \"{1}\"".format(self.receive_buffer.strip(), regex))
                    result = self.receive_buffer[0:match.end()]
                    self.receive_buffer = self.receive_buffer[match.end()+1:]
                    return result
                #elif re.search("^\d\d\d\d .*$", msg, re.MULTILINE):
                    #return msg
        # except socket.error as e:
        #     self._handleSocketError(e)
        return msg

    @asyncio.coroutine
    def _init_connection(self):
        yield from self.call("autodisplay off")
        #return
    
    @asyncio.coroutine
    def _cram_md5_challenge(self, clientname, password, tls_local_need=0, compatible=True):
        '''
        client launch the challenge,
        client confirm the dir is the correct director
        '''

        # get the timestamp
        # here is the console
        # to confirm the director so can do this on bconsole`way
        rand = random.randint(1000000000, 9999999999)
        #chal = "<%u.%u@%s>" %(rand, int(time.time()), self.dirname)
        chal = '<%u.%u@%s>' %(rand, int(time.time()), clientname)
        msg = bytearray('auth cram-md5 %s ssl=%d\n' %(chal, tls_local_need), 'utf-8')
        # send the confirmation
        yield from self.send(msg)
        # get the response
        msg = yield from self.recv()
        if msg[-1] == 0:
            del msg[-1]
        self.logger.debug("received: " + str(msg))

        # hash with password
        hmac_md5 = hmac.new(bytes(bytearray(password, 'utf-8')))
        hmac_md5.update(bytes(bytearray(chal, 'utf-8')))
        bbase64compatible = BareosBase64().string_to_base64(bytearray(hmac_md5.digest()), True)
        bbase64notcompatible = BareosBase64().string_to_base64(bytearray(hmac_md5.digest()), False)
        self.logger.debug("string_to_base64, compatible:     " + str(bbase64compatible))
        self.logger.debug("string_to_base64, not compatible: " + str(bbase64notcompatible))

        is_correct = ((msg == bbase64compatible) or (msg == bbase64notcompatible))
        # check against compatible base64 and Bareos specific base64
        if is_correct:
            yield from self.send(ProtocolMessages.auth_ok())
        else:
            self.logger.error("expected result: %s or %s, but get %s" %(bbase64compatible, bbase64notcompatible, msg))
            yield from self.send(ProtocolMessages.auth_failed())

        # check the response is equal to base64
        return is_correct
    
    @asyncio.coroutine
    def _cram_md5_respond(self, password, tls_remote_need=0, compatible=True):
        '''
        client connect to dir,
        the dir confirm the password and the config is correct
        '''
        # receive from the director
        chal = ""
        ssl = 0
        result = False
        msg = ""
        #try:
        msg = yield from self.recv()
        # except RuntimeError:
        #     self.logger.error("RuntimeError exception in recv")
        #     return (0, True, False)
        
        # invalid username
        if ProtocolMessages.is_not_authorized(msg):
            self.logger.error("failed: " + str(msg))
            return (0, True, False)
        
        # check the receive message
        self.logger.debug("(recv): " + str(msg))
        
        msg_list = msg.split(b" ")
        chal = msg_list[2]
        # get th timestamp and the tle info from director response
        ssl = int(msg_list[3][4])
        compatible = True
        # hmac chal and the password
        hmac_md5 = hmac.new(bytes(bytearray(password, 'utf-8')))
        hmac_md5.update(bytes(chal))

        # base64 encoding
        msg = BareosBase64().string_to_base64(bytearray(hmac_md5.digest()))

        # send the base64 encoding to director
        yield from self.send(msg)
        received = yield from self.recv()
        if  ProtocolMessages.is_auth_ok(received):
            result = True
        else:
            self.logger.error("failed: " + str(received))
        return (ssl, compatible, result)
    
class AsyncConsoleJson(AsyncConsole):
    """
    use to send and receive the response from director
    """

    def __init__(self, *args, **kwargs):
        super(AsyncConsoleJson, self).__init__(*args, **kwargs)

    @asyncio.coroutine
    def _init_connection(self):
        # older version did not support compact mode,
        # therfore first set api mode to json (which should always work in bareos >= 15.2.0)
        # and then set api mode json compact (which should work with bareos >= 15.2.2)
        self.logger.debug((yield from self.call(".api json")))
        self.logger.debug((yield from self.call(".api json compact=yes")))
        
    @classmethod
    @asyncio.coroutine
    def get_connection(cls, *args, **kwargs):
        return (yield from super(AsyncConsoleJson, cls).get_connection(*args, **kwargs))

    @asyncio.coroutine
    def call(self, command):
        json = yield from self.call_fullresult(command)
        if json == None:
            return
        if 'result' in json:
            result = json['result']
        else:
            # TODO: or raise an exception?
            result = json
        return result

    @asyncio.coroutine
    def call_fullresult(self, command):
        resultstring = yield from super(AsyncConsoleJson, self).call(command)
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