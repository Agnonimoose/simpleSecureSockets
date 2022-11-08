"""
!!!!!!!!!!!!!!!!!!!!
ATTENTION
!!!!!!!!!!!!!!!!!!!!
This snippet is missing the RSA initial encryption! You will need to create your own
when connected to send and add the encryptor to the sever privately. I Purposely took
this out, you should read about encryption before attempting to copy encrypted sockets.

"""

import socket
import json, base64
from time import sleep, time
import ormsgpack as omg
from cryptography.fernet import Fernet
import hashlib
from hashlib import blake2b
from hmac import compare_digest
import zlib


class socketObj:
    def __init__(self):
        self.zocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.zocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.HEADER_LENGTH = 10
        self._compress = True

    def send(self, data, mode, session=None):

        encoded = self.encryptData(data, mode=mode, session=session)
        if encoded != 0:
            try:
                self.zocket.sendall(encoded)
            except Exception as e:
                return e
        else:
            return encoded

    def encryptData(self, data, mode="public", session=None):

        dumped = self.packObj(data)
        if mode == "public":
            dumped = self.sendPublic(dumped, session=session)
        elif mode == "private":
            dumped = self.sendPrivate(dumped, session=session)
        else:
            pass
        return dumped

    def packObj(self, obj):
        return omg.packb(obj)

    def recv(self):
        attemps = 0
        header = b''
        while (len(header) < 10) and (attemps < 20):
            try:
                header = self.zocket.recv(10)
            except socket.error as e:
                attemps += 1

        if len(header) != 10:
            return Exception("Failed to find header")
        attemps = 0
        header = int(header.decode().strip())
        datar = b''
        while len(datar) < header:
            try:
                datar += self.zocket.recv(10000)
            except:
                pass
            if attemps == 200:
                return Exception("recv timedout !")
            else:
                attemps += 1
        data = header + datar
        if data == None:
            return None
        else:
            msg = self.decodeMessage(data)
            return msg

    def getHeader(self, data):
        header = f"{len(data):<{self.HEADER_LENGTH}}".encode('utf-8')
        return header

    def unpackObj(self, obj):
        return omg.unpackb(obj)

    def decodeMessage(self, msg):
        header = int(msg[:self.HEADER_LENGTH].decode('utf-8').strip())
        if len(msg[self.HEADER_LENGTH:]) == header:
            type = msg[self.HEADER_LENGTH:self.HEADER_LENGTH + 3].decode('utf-8')
            func = self._funcDict[type]
            result = func(msg[self.HEADER_LENGTH + 3:])
            return result
        else:
            return Exception("HEADER LENGTH ERROR")


class server(socketObj):
    def __init__(self, ip: str, port: int, ):
        super().__init__()
        try:
            self.zocket.bind((ip, port))
        except PermissionError:
            raise PermissionError(f"Port {port} is already in use by another service, try a port above 999")
        except OSError:
            raise OSError(f"'{ip}' must not be your ip address")

        # Missing loop here, create own loop with select for multiple socket serving
        self.zocket.setblocking(False)
        self.zocket.listen(8)

        self.key = """THIS SHOULD BE YOUR PUBLIC KEY ^^ See above"""

        self._funcDict = {"pub": self.decodePublic, "pri": self.decodePrivate}
        self.encryptors = {}

    def acceptConnection(self):
        """
        !!!!!!!!!!!!!!!!!!!!
        ATTENTION
        !!!!!!!!!!!!!!!!!!!!
        1) Impliment your RSA connection here!
        2) Look up private key from
        """
        session = self.makeHash("random salt string" + str(time()))

        key = "LOOK UP KEY FROM WHERE YOU STORE IT"

        self.encryptors[session] = encryptData(session, key)
        self.send(session)

    def makeHash(self, salt):
        s = salt.encode('utf-8')
        return hashlib.sha224(s).hexdigest()

    def sendPublic(self, msg, session=None):
        self.encryptors[session].encodeMessage(msg, mode="public")
        encoded = self.encryptors[session].phrase
        header = self.getHeader(b'pub' + session.encode() + encoded)
        phrase = header + b'pub' + session.encode() + encoded
        return phrase

    def sendPrivate(self, msg, session=None):
        if self.encryptors[session]._key != None:
            self.encryptors[session].encodeMessage(msg, mode="private")
            encoded = self.encryptors[session].phrase
            headerType = b'pri' + session.encode()
            header = self.getHeader(headerType + encoded)
            phrase = header + headerType + encoded
            return phrase
        else:
            return Exception("private gateway not open")


    def decodePublic(self, data):
        message = self.encryptors[data[:56]].decodeMessage(data[56:], mode="public")
        return message

    def decodePrivate(self, data):
        message = self.encryptors[data[:56]].decodeMessage(data[56:], mode="private")
        return message


class client(socketObj):
    def __init__(self, ip: str, port: int, key=None, socket_timeout=.5):
        super().__init__()

        self.zocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.zocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.zocket.settimeout(socket_timeout)

        for i in range(5):
            try:
                self.zocket.connect((ip, port))
                break
            except Exception:
                if i == 4:
                    raise ConnectionRefusedError("Is your server on?")
                sleep(.1)

        self.con = client
        self.key = key

        self._funcDict = {"pub": self.decodePublic, "pri": self.decodePrivate}

    def connect(self):
        """
        !!!!!!!!!!!!!!!!!!!!
        ATTENTION
        !!!!!!!!!!!!!!!!!!!!
        Implement your RSA connection here!
        """
        self.session = "Returned session ID"
        self._encryptor = encryptData(self.session, self.key)

    def sendPublic(self, msg):
        self._encryptor.encodeMessage(msg, mode="public")
        encoded = self._encryptor.phrase
        header = self.getHeader(b'pub' + self.session.encode() + encoded)
        phrase = header + b'pub' + self.session.encode() + encoded
        return phrase

    def sendPrivate(self, msg):
        if self._encryptor._key != None:
            self._encryptor.encodeMessage(msg, mode="private")
            encoded = self._encryptor.phrase
            headerType = b'pri' + self.session.encode()
            header = self.getHeader(headerType + encoded)
            phrase = header + headerType + encoded
            return phrase
        else:
            return Exception("No valid private key found")

    def decodePublic(self, data):
        message = self._encryptor.decodeMessage(data[56:], mode="public")
        return message

    def decodePrivate(self, data):
        message = self._encryptor.decodeMessage(data[56:], mode="private")
        return message


class encryptData:
    __slots__ = ["_gate", "_key", "_sig", "_compress", "decryptedPhrase", "phrase", "session"]

    def __init__(self, session, key):
        self.session = session
        self._sig = self._generateSig(session)
        self._key = key
        if self._key == None:
            self._gate = None
        else:
            self._gate = Fernet(self._key)
        self.phrase = None
        self.decryptedPhrase = None
        self._compress = True

    def _generateSig(self, session):
        s = "vkC3GTDPDrmv2K3kQzDLaS8uJ3SOsuDwYPEGbvINUg" + session + "0c334ab2cce3e59a9f8d25b891b6f8f306da11433bb0b019c6ab30c6"
        s = s.encode('utf-8')
        return hashlib.sha224(s).hexdigest().encode()

    def encodeMessage(self, msg, mode="private"):
        if mode == "private":
            encrypted = self._gate.encrypt(msg)
        else:
            encrypted = msg

        if self._compress == True:
            encrypted = b'__c__' + zlib.compress(encrypted, level=9)

        signed = self.sign(encrypted)
        self.phrase = signed + encrypted

    def sign(self, cookie):
        h = blake2b(digest_size=16, key=self._sig)
        h.update(cookie)
        return h.hexdigest().encode('utf-8')

    def verify(self, cookie, sig):
        good_sig = self.sign(cookie)
        return compare_digest(good_sig, sig)

    def decodeMessage(self, phrase, mode="private"):
        sig = phrase[:32]
        data = phrase[32:]
        if self.verify(data, sig) == True:
            if data[:5] == b'__c__':
                data = zlib.decompress(data[5:])
            try:
                if mode != "private":
                    self.decryptedPhrase = data
                    return data
                else:
                    decryptedMsg = self._gate.decrypt(data)
                    self.decryptedPhrase = decryptedMsg
                    return decryptedMsg
            except Exception as e:
                return e
        else:
            self.decryptedPhrase = None
            return Exception("Signature Verification Error")
