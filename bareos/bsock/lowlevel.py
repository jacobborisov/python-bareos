"""
Low Level socket methods to communication with the bareos-director.
"""

# Authentication code is taken from
# https://github.com/hanxiangduo/bacula-console-python

from   bareos.exceptions import *
from   bareos.util.bareosbase64 import BareosBase64
from   bareos.util.password import Password
from   bareos.bsock.constants import Constants
from   bareos.bsock.connectiontype import ConnectionType
from   bareos.bsock.protocolmessages import ProtocolMessages
import hmac
import logging
import random
import re
from   select import select
import socket
import struct
import sys
import time
import types
import functools
import asyncio
from asyncio import IncompleteReadError

def coroutine_if(flag):
    '''
    decorator returns function as coroutine if 'flag' attribute of the object set to True,
    otherwise simply returns return value
    '''
    def wr(fn):
        @functools.wraps(fn)
        def wrapper(self, *args, **kwargs):
            if hasattr(self, flag) and getattr(self, flag):
                fnc = asyncio.coroutine(fn)
                return fnc(self, *args, **kwargs)
            try:
                res = fn(self, *args, **kwargs)
                if not isinstance(res, types.GeneratorType):
                    return res
                res.__next__()
            except StopIteration as e:
                return e.value
        return wrapper
    return wr

class LowLevel(object):
    """
    Low Level socket methods to communicate with the bareos-director.
    """

    def __init__(self, asyncio=False):
        self.logger = logging.getLogger()
        self.logger.debug("init")
        self.status = None
        self.address = None
        self.password = None
        self.port = None
        self.dirname = None
        if asyncio:
            self.aio = True
            self.read_stream = None
            self.write_stream = None
            self.established = False
        else:
            self.aio = False
            self.socket = None
        self.auth_credentials_valid = False
        self.connection_type = None
        self.receive_buffer = b''

    @coroutine_if('aio')
    def connect(self, address, port, dirname, type):
        self.address = address
        self.port = port
        self.dirname = dirname or address
        self.connection_type = type
        return self.__connect() if not self.aio else (yield from self.__connect())


    @coroutine_if('aio')
    def __connect(self):
        try:
            if self.aio:
                self.read_stream, self.write_stream = yield from asyncio.open_connection(host=self.address, port=self.port)
            else:
                self.socket = socket.create_connection((self.address, self.port))
        except socket.gaierror as e:
            self._handleSocketError(e)
            raise ConnectionError(
                "failed to connect to host " + str(self.address) + ", port " + str(self.port) + ": " + str(e))
        else:
            self.logger.debug("connected to " + str(self.address) + ":" + str(self.port))
        return True


    @coroutine_if('aio')
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
        return self.__auth() if not self.aio else (yield from self.__auth())


    @coroutine_if('aio')
    def __auth(self):
        bashed_name = ProtocolMessages.hello(self.name, type=self.connection_type)
        # send the bash to the director
        self.send(bashed_name) if not self.aio else (yield from self.send(bashed_name))
        
        generator = self._cram_md5_respond(password=self.password.md5(), tls_remote_need=0)
        (ssl, result_compatible, result) = generator if not self.aio else (yield from generator)
        if not result:
            raise AuthenticationError("failed (in response)")
        generator = self._cram_md5_challenge(clientname=self.name, password=self.password.md5(), tls_local_need=0, compatible=True)
        if self.aio: generator = yield from generator
        if not generator:
            raise AuthenticationError("failed (in challenge)")
        generator = self.recv_msg(self.auth_success_regex)
        if self.aio: yield from generator
        self.auth_credentials_valid = True
        return True


    @coroutine_if('aio')
    def _init_connection(self):
        pass


    @coroutine_if('aio')
    def disconnect(self):
        ''' disconnect '''
        if self.aio:
            try:
                yield from self.send(bytearray("quit", 'utf-8'))
                header = yield from self.read_stream.readexactly(4)
                result = self._LowLevel__get_header_data(header)
                if result == -16:
                    return True
                else:
                    #TODO: maybe raise exception?
                    pass
            finally:
                self.write_stream.close()
        else:
            pass


    def reconnect(self):
        result = False
        if self.auth_credentials_valid:
            try:
                if self.__connect() and self.__auth() and self._init_connection():
                    result = True
            except socket.error:
                self.logger.warning("failed to reconnect")
        return result


    @coroutine_if('aio')
    def call(self, command):
        '''
        call a bareos-director user agent command
        '''
        if self.aio and not self.established:
            self.established = True
            yield from self.establish()
        if isinstance(command, list):
            command = " ".join(command)
        result = self.__call(command, 0)
        return result if not self.aio else (yield from result)


    @coroutine_if('aio')
    def __call(self, command, count):
        '''
        Send a command and receive the result.
        If connection is lost, try to reconnect.
        '''
        result = b''
        try:
            generator = self.send(bytearray(command, 'utf-8'))
            if self.aio: yield from generator
            result = self.recv_msg() if not self.aio else (yield from self.recv_msg())
        except (SocketEmptyHeader, ConnectionLostError) as e:
            self.logger.error("connection problem (%s): %s" % (type(e).__name__, str(e)))
            if count == 0:
                if self.reconnect():
                    return self.__call(command, count+1)
        return result


    def send_command(self, commamd):
        return self.call(command)


    @coroutine_if('aio')
    def send(self, msg=None):
        '''use socket to send request to director'''
        self.__check_socket_connection()
        msg_len = len(msg) # plus the msglen info
        packed_msg = struct.pack("!i", msg_len) + msg

        try:
            # convert to network flow
            if self.aio:
                self.write_stream.write(packed_msg)
                yield from self.write_stream.drain()
            else:
                self.socket.sendall(packed_msg)
            self.logger.debug("%s" %(msg))
        except socket.error as e:
            self._handleSocketError(e)


    @coroutine_if('aio')
    def recv(self):
        '''will receive data from director '''
        self.__check_socket_connection()
        # get the message header
        header = self.__get_header() if not self.aio else (yield from self.__get_header())
        if header <= 0:
            self.logger.debug("header: " + str(header))
        # get the message
        length = header
        msg = self.recv_submsg(length)
        if self.aio: msg = yield from msg
        return msg


    @coroutine_if('aio')
    def recv_msg(self, regex = b'^\d\d\d\d OK.*$', timeout = None):
        '''will receive data from director '''
        self.__check_socket_connection()
        try:
            timeouts = 0
            while True:
                # get the message header
                if not self.aio:
                    self.socket.settimeout(0.1)
                try:
                    header = self.__get_header() if not self.aio else (yield from self.__get_header())
                except socket.timeout:
                    # only log every 100 timeouts
                    if timeouts % 100 == 0:
                        self.logger.debug("timeout (%i) on receiving header" % (timeouts))
                    timeouts+=1
                else:
                    if header <= 0:
                        # header is a signal
                        self.__set_status(header)
                        if self.is_end_of_message(header):
                            result = self.receive_buffer
                            self.receive_buffer = b''
                            return result
                    else:
                        # header is the length of the next message
                        length = header
                        submsg = self.recv_submsg(length)
                        self.receive_buffer += submsg if not self.aio else (yield from submsg)
                        # Bareos indicates end of command result by line starting with 4 digits
                        match = re.search(regex, self.receive_buffer, re.MULTILINE)
                        if match:
                            self.logger.debug("msg \"{0}\" matches regex \"{1}\"".format(self.receive_buffer.strip(), regex))
                            result = self.receive_buffer[0:match.end()]
                            self.receive_buffer = self.receive_buffer[match.end()+1:]
                            return result
                        #elif re.search("^\d\d\d\d .*$", msg, re.MULTILINE):
                            #return msg
        except socket.error as e:
            self._handleSocketError(e)
        return msg


    @coroutine_if('aio')
    def recv_submsg(self, length):
        # get the message
        msg = b''
        if self.aio:
            msg = yield from self.read_stream.readexactly(length)
        while not self.aio and length > 0:
            self.logger.debug("  submsg len: " + str(length))
            # TODO
            self.socket.settimeout(10)
            submsg = self.socket.recv(length)
            length -= len(submsg)
            #self.logger.debug(submsg)
            msg += submsg
        if (type(msg) is str):
            msg = bytearray(msg.decode('utf-8'), 'utf-8')
        if (type(msg) is bytes):
            msg = bytearray(msg)
        #self.logger.debug(str(msg))
        return msg


    def interactive(self):
        """
        Enter the interactive mode.
        Exit via typing "exit" or "quit".
        """
        command = ""
        while command != "exit" and command != "quit" and self.is_connected():
            command = self._get_input()
            resultmsg = self.call(command)
            self._show_result(resultmsg)
        return True


    def _get_input(self):
        # Python2: raw_input, Python3: input
        try:
            myinput = raw_input
        except NameError:
            myinput = input
        data = myinput(">>")
        return data


    def _show_result(self, msg):
        #print(msg.decode('utf-8'))
        sys.stdout.write(msg.decode('utf-8'))
        # add a linefeed, if there isn't one already
        if msg[-2] != ord(b'\n'):
            sys.stdout.write(b'\n')


    @coroutine_if('aio')
    def __get_header(self):
        self.__check_socket_connection()
        try:
            header = self.socket.recv(4) if not self.aio else (yield from self.read_stream.readexactly(4))
        except IncompleteReadError as e:
            print('IncompleteReadError', e)
        if len(header) == 0:
            self.logger.debug("received empty header, assuming connection is closed")
            raise SocketEmptyHeader()
        else:
            return self.__get_header_data(header)


    def __get_header_data(self, header):
        # struct.unpack:
        #   !: network (big/little endian conversion)
        #   i: integer (4 bytes)
        data = struct.unpack("!i", header)[0]
        return data


    def is_end_of_message(self, data):
        return ((not self.is_connected()) or
                data in (Constants.BNET_EOD,
                         Constants.BNET_TERMINATE,
                         Constants.BNET_MAIN_PROMPT,
                         Constants.BNET_SUB_PROMPT))


    def is_connected(self):
        return (self.status != Constants.BNET_TERMINATE)


    @coroutine_if('aio')
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
        # send the confirmation and get the response
        self.send(msg) if not self.aio else (yield from self.send(msg))
        msg = self.recv() if not self.aio else (yield from self.recv())
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
            generator = self.send(ProtocolMessages.auth_ok())
        else:
            self.logger.error("expected result: %s or %s, but get %s" %(bbase64compatible, bbase64notcompatible, msg))
            generator = self.send(ProtocolMessages.auth_failed())
        if self.aio: yield from generator

        # check the response is equal to base64
        return is_correct


    @coroutine_if('aio')
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
        try:
            msg = self.recv() if not self.aio else (yield from self.recv())
        except RuntimeError:
            self.logger.error("RuntimeError exception in recv")
            return (0, True, False)
        
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
        self.send(msg) if not self.aio else (yield from self.send(msg))
        received = self.recv() if not self.aio else (yield from self.recv())
        if  ProtocolMessages.is_auth_ok(received):
            result = True
        else:
            self.logger.error("failed: " + str(received))
        return (ssl, compatible, result)


    def __set_status(self, status):
        self.status = status
        status_text = Constants.get_description(status)
        self.logger.debug(str(status_text) + " (" + str(status) + ")")


    def has_data(self):
        self.__check_socket_connection()
        timeout = 0.1
        readable, writable, exceptional = select([self.socket], [], [], timeout)
        return readable


    def get_to_prompt(self):
        time.sleep(0.1)
        if self.has_data():
            msg = self.recv_msg()
            self.logger.debug("received message: " + str(msg))
        # TODO: check prompt
        return True


    def __check_socket_connection(self):
        result = True
        if self.aio:
            return True
        if self.socket == None:
            result = False
            if self.auth_credentials_valid:
                # connection have worked before, but now it is gone
                raise ConnectionLostError("currently no network connection")
            else:
                raise RuntimeError("should connect to director first before send data")
        return result


    def _handleSocketError(self, exception):
        self.logger.error("socket error:" + str(exception))
        self.socket = None
