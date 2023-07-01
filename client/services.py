import threading
import time
from collections import defaultdict
from datetime import datetime
from typing import cast

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import serialization
from django.utils import timezone
from django.utils.timezone import make_aware
from google.protobuf import empty_pb2

from django.conf import settings

from common.api import dnschat_pb2, dnschat_pb2_grpc
from common.services import EncryptionService, AbstractKeyService, AbstractRSAKeyService


class ClientService:
    def __init__(self, stub: dnschat_pb2_grpc.ChatStub):
        self._stub = stub
        self._key_service = KeyService()
        self._rsa_key_service = RSAKeyService()
        self._encryption_service = EncryptionService(self._key_service, self._rsa_key_service)
        self.session_key_id = None
        self.dh_private_key = None
        self.messages = defaultdict(list)
        self.group_messages = defaultdict(list)
        self.chat_keys = {}
        self.group_keys = {}
        self.is_logged_in = False
        self.username = ''

        self._pull_messages_thread = threading.Thread(target=self._pull_messages)
        self._pull_messages_thread.start()


    def start_session(self):
        public_key = self._stub.GetPublicKey(empty_pb2.Empty())
        rsa_public_key = RSA.import_key(public_key.public_key)
        key_id = SHA256.new(rsa_public_key.export_key(format='PEM')).digest()[0:16]
        self._rsa_key_service.add_rsa_public_key(key_id, rsa_public_key)

        signed_dh_params = self._stub.GetDHParams(empty_pb2.Empty())
        dh_params = cast(dnschat_pb2.DHParams, self._encryption_service.verify(signed_dh_params))
        self._encryption_service.dh_params = serialization.load_pem_parameters(dh_params.params, backend=None)

        private_key = self._encryption_service.dh_new_private_key()
        dh_pub_key = dnschat_pb2.DHPubKey(y=private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        signed_server_dh_pub_key = self._stub.NewSession(dh_pub_key)
        server_dh_pub_key = cast(dnschat_pb2.DHPubKey, self._encryption_service.verify(signed_server_dh_pub_key))
        _, derived_key = self._encryption_service.dh_exchange(server_dh_pub_key.y, private_key)
        self.session_key_id = SHA256.new(derived_key).digest()[0:16]
        self._key_service.add_key(self.session_key_id, derived_key)
        print('Session key id:')
        print(self.session_key_id.hex())

    def register(self, username: str, password: str):
        key_encryption_key = SHA256.new((username + password + 'key_encryption_key').encode()).digest()
        login_password = SHA256.new((username + password + 'login_password').encode()).digest().hex()

        key_count = settings.MAX_CLIENT_KEYS
        keys = []
        for _ in range(key_count):
            private_key = self._encryption_service.dh_new_private_key()
            public_key = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            encrypted_private_key = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(key_encryption_key),
            )
            keys.append(dnschat_pb2.Key(public_key=public_key, encrypted_private_key=encrypted_private_key))

        rsa_key = RSA.generate(2048)
        rsa_public_key = rsa_key.publickey().export_key(format='PEM')
        encrypted_rsa_private_key = rsa_key.export_key(
            format='PEM',
            pkcs=8,
            protection='scryptAndAES128-CBC',
            passphrase=key_encryption_key.hex(),
        )
        keys.append(dnschat_pb2.Key(
            public_key=rsa_public_key, encrypted_private_key=encrypted_rsa_private_key, is_rsa=True
        ))

        request = dnschat_pb2.RegisterRequest(
            username=username,
            password=login_password,
            keys=keys,
            rsa_pub_key=dnschat_pb2.RSAPubKey(public_key=rsa_public_key),
        )
        encrypted_request = self._encryption_service.encrypt_message(request, self.session_key_id)
        encrypted_response = self._stub.Register(encrypted_request)
        signed_response = cast(dnschat_pb2.SignedMessage, self._encryption_service.decrypt_message(encrypted_response))
        response = cast(dnschat_pb2.RegisterResponse, self._encryption_service.verify(signed_response))
        if response.duplicate:
            return 'Duplicate username'
        return 'Success'

    def login(self, username: str, password: str):
        key_encryption_key = SHA256.new((username + password + 'key_encryption_key').encode()).digest()
        login_password = SHA256.new((username + password + 'login_password').encode()).digest().hex()
        request = dnschat_pb2.LoginRequest(username=username, password=login_password)
        encrypted_request = self._encryption_service.encrypt_message(request, self.session_key_id)
        encrypted_response = self._stub.Login(encrypted_request)
        signed_response = cast(dnschat_pb2.SignedMessage, self._encryption_service.decrypt_message(encrypted_response))
        response = cast(dnschat_pb2.LoginResponse, self._encryption_service.verify(signed_response))
        if response.success:
            self.dh_private_key = serialization.load_pem_private_key(
                response.key.encrypted_private_key,
                password=key_encryption_key
            )
            rsa_private_key = RSA.import_key(
                response.rsa_key.encrypted_private_key,
                passphrase=key_encryption_key.hex()
            )
            self.rsa_key_id = SHA256.new(response.rsa_key.public_key).digest()[0:16]
            self._rsa_key_service.add_rsa_private_key(
                self.rsa_key_id,
                rsa_private_key
            )
            self.is_logged_in = True
            self.username = username
            return True, f'Success {self.rsa_key_id.hex()}'
        return False, 'Invalid username or password'

    def list_users(self):
        request = empty_pb2.Empty()
        signed_request = self._encryption_service.sign(request, self.rsa_key_id)
        encrypted_request = self._encryption_service.encrypt_message(signed_request, self.session_key_id)
        encrypted_response = self._stub.ListUsers(encrypted_request)
        signed_response = cast(dnschat_pb2.SignedMessage, self._encryption_service.decrypt_message(encrypted_response))
        response = cast(dnschat_pb2.ListUsersResponse, self._encryption_service.verify(signed_response))
        return response.users

    def get_messages(self, username: str):
        return self.messages[username]

    def send_message(self, username: str, text: str):
        return self._send_message(username, dnschat_pb2.Simple(text=text))

    def _send_message(self, username: str, message):
        if username not in self.chat_keys:
            key_id, public_key = self._new_chat_session(username)
            self.chat_keys[username] = key_id, public_key

        while True:
            key_id, public_key = self.chat_keys[username]
            signed_message = self._encryption_service.sign(message, self.rsa_key_id)
            encrypted_message = self._encryption_service.encrypt_message(signed_message, key_id)
            request = dnschat_pb2.SendChatMessageRequest(
                message=encrypted_message.SerializeToString(),
                recipient=username,
                is_group=False,
                key_id=key_id,
                peer_dh_key_id=SHA256.new(public_key).digest()[0:16],
            )
            signed_request = self._encryption_service.sign(request, self.rsa_key_id)
            encrypted_request = self._encryption_service.encrypt_message(signed_request, self.session_key_id)
            encrypted_response = self._stub.SendChatMessage(encrypted_request)
            signed_response = cast(dnschat_pb2.SignedMessage, self._encryption_service.decrypt_message(encrypted_response))
            response = cast(dnschat_pb2.SendChatMessageResponse, self._encryption_service.verify(signed_response))
            if response.session_expired:
                key_id, public_key = self._new_chat_session(username)
                self.chat_keys[username] = key_id, public_key
            elif response.success:
                if message.DESCRIPTOR.name == 'Simple':
                    self.messages[username].append({
                        'you': True,
                        'text': message.text,
                        'timestamp': timezone.now(),
                    })
                return 'Success'
            else:
                return 'Failed to send message'

    def send_group_message(self, group_name: str, text: str):
        key_id = self.group_keys[group_name]
        if key_id is None:
            return 'Group key does not exist'
        message = dnschat_pb2.Simple(text=text)
        signed_message = self._encryption_service.sign(message, self.rsa_key_id)
        encrypted_message = self._encryption_service.encrypt_message(signed_message, key_id)
        request = dnschat_pb2.SendChatMessageRequest(
            message=encrypted_message.SerializeToString(),
            recipient=group_name,
            is_group=True,
            key_id=key_id,
        )
        signed_request = self._encryption_service.sign(request, self.rsa_key_id)
        encrypted_request = self._encryption_service.encrypt_message(signed_request, self.session_key_id)
        encrypted_response = self._stub.SendChatMessage(encrypted_request)
        signed_response = cast(dnschat_pb2.SignedMessage, self._encryption_service.decrypt_message(encrypted_response))
        response = cast(dnschat_pb2.SendChatMessageResponse, self._encryption_service.verify(signed_response))
        if response.success:
            return 'Success'
        else:
            return 'Failed to send message'

    def expire_session(self, password: str):
        key_encryption_key = SHA256.new((self.username + password + 'key_encryption_key').encode()).digest()
        request = empty_pb2.Empty()
        signed_request = self._encryption_service.sign(request, self.rsa_key_id)
        encrypted_request = self._encryption_service.encrypt_message(signed_request, self.session_key_id)
        encrypted_response = self._stub.ExpireSession(encrypted_request)
        signed_response = cast(dnschat_pb2.SignedMessage, self._encryption_service.decrypt_message(encrypted_response))
        response = cast(dnschat_pb2.Key, self._encryption_service.verify(signed_response))
        self.dh_private_key = serialization.load_pem_private_key(
            response.encrypted_private_key,
            password=key_encryption_key
        )
        return ''

    def create_group(self, group_name: str):
        request = dnschat_pb2.CreateGroupRequest(group_name=group_name)
        signed_request = self._encryption_service.sign(request, self.rsa_key_id)
        encrypted_request = self._encryption_service.encrypt_message(signed_request, self.session_key_id)
        encrypted_response = self._stub.CreateGroup(encrypted_request)
        signed_response = cast(dnschat_pb2.SignedMessage, self._encryption_service.decrypt_message(encrypted_response))
        response = cast(dnschat_pb2.CreateGroupResponse, self._encryption_service.verify(signed_response))
        if response.success:
            return 'Success'
        elif response.duplicate:
            return 'Duplicate'
        else:
            return 'Failed'

    def add_user_to_group(self, group_name, username):
        request = dnschat_pb2.AddUserToGroupRequest(group_name=group_name, user=username)
        signed_request = self._encryption_service.sign(request, self.rsa_key_id)
        encrypted_request = self._encryption_service.encrypt_message(signed_request, self.session_key_id)
        encrypted_response = self._stub.AddUserToGroup(encrypted_request)
        signed_response = cast(dnschat_pb2.SignedMessage, self._encryption_service.decrypt_message(encrypted_response))
        response = cast(dnschat_pb2.AddUserToGroupResponse, self._encryption_service.verify(signed_response))
        if response.duplicate:
            return 'Duplicate user'
        elif not response.success:
            return 'Failed'
        else:
            group_key = SHA256.new(get_random_bytes(2048)).digest()
            group_key_id = SHA256.new(group_key).digest()[0:16]
            self._key_service.add_key(group_key_id, group_key)
            for member in response.user_dh_pub_keys:
                message = dnschat_pb2.GroupChatKey(key=group_key, group_name=group_name)
                self._send_message(member, message)
            return 'Success'

    def remove_user_from_group(self, group_name, username):
        request = dnschat_pb2.RemoveUserFromGroupRequest(group_name=group_name, user=username)
        signed_request = self._encryption_service.sign(request, self.rsa_key_id)
        encrypted_request = self._encryption_service.encrypt_message(signed_request, self.session_key_id)
        encrypted_response = self._stub.RemoveUserFromGroup(encrypted_request)
        signed_response = cast(dnschat_pb2.SignedMessage, self._encryption_service.decrypt_message(encrypted_response))
        response = cast(dnschat_pb2.RemoveUserFromGroupResponse, self._encryption_service.verify(signed_response))
        if response.not_found:
            return 'Not found'
        elif not response.success:
            return 'Failed'
        else:
            group_key = SHA256.new(get_random_bytes(2048)).digest()
            group_key_id = SHA256.new(group_key).digest()[0:16]
            self._key_service.add_key(group_key_id, group_key)
            for member in response.user_dh_pub_keys:
                message = dnschat_pb2.GroupChatKey(key=group_key, group_name=group_name)
                self._send_message(member, message)
            return 'Success'

    def list_groups(self):
        return self.group_keys.keys()

    def get_group_messages(self, group_name):
        return self.group_messages[group_name]

    def _new_chat_session(self, username: str):
        request = dnschat_pb2.NewChatSessionRequest(recipient=username)
        signed_request = self._encryption_service.sign(request, self.rsa_key_id)
        encrypted_request = self._encryption_service.encrypt_message(signed_request, self.session_key_id)
        encrypted_response = self._stub.NewChatSession(encrypted_request)
        signed_response = cast(dnschat_pb2.SignedMessage, self._encryption_service.decrypt_message(encrypted_response))
        response = cast(dnschat_pb2.NewChatSessionResponse, self._encryption_service.verify(signed_response))
        if response.success:
            _, key = self._encryption_service.dh_exchange(response.dh_pub_key.y, self.dh_private_key)
            key_id = SHA256.new(key).digest()[0:16]
            self._key_service.add_key(key_id, key)

            rsa_key_id = SHA256.new(response.rsa_pub_key.public_key).digest()[0:16]
            rsa_public_key = RSA.import_key(response.rsa_pub_key.public_key)
            self._rsa_key_service.add_rsa_public_key(rsa_key_id, rsa_public_key)
            return key_id, response.dh_pub_key.y

    def _pull_messages(self):
        while True:
            if not self.is_logged_in:
                time.sleep(5)
                continue

            request = empty_pb2.Empty()
            signed_request = self._encryption_service.sign(request, self.rsa_key_id)
            encrypted_request = self._encryption_service.encrypt_message(signed_request, self.session_key_id)
            encrypted_response = self._stub.PullMessages(encrypted_request)
            signed_response = cast(dnschat_pb2.SignedMessage, self._encryption_service.decrypt_message(encrypted_response))
            response = cast(dnschat_pb2.PullMessageResponse, self._encryption_service.verify(signed_response))
            if response.success:
                for m in response.messages:
                    if not self._key_service.key_exists(m.message.key_id):
                        _, key = self._encryption_service.dh_exchange(m.sender_dh_pub_key.y, self.dh_private_key)
                        key_id = SHA256.new(key).digest()[0:16]
                        self._key_service.add_key(key_id, key)
                        self.chat_keys[m.sender] = key_id, m.sender_dh_pub_key.y
                    encrypted_message = dnschat_pb2.EncryptedMessage().FromString(m.message.message)
                    signed_message = cast(dnschat_pb2.SignedMessage, self._encryption_service.decrypt_message(encrypted_message))
                    message = self._encryption_service.verify(signed_message, force_verify=False)
                    t = make_aware(datetime.fromtimestamp(m.timestamp.seconds + m.timestamp.nanos / 1e9))
                    if not m.group_name:
                        if message.DESCRIPTOR.name == 'Simple':
                            self.messages[m.sender].append({
                                'you': False,
                                'text': message.text,
                                'timestamp': t,
                            })
                        elif message.DESCRIPTOR.name == 'GroupChatKey':
                            group_key_id = SHA256.new(message.key).digest()[0:16]
                            self._key_service.add_key(group_key_id, message.key)
                            self.group_keys[message.group_name] = group_key_id
                            self.messages[m.sender].append({
                                'you': False,
                                'text': f'You have been added to group {m.sender}',
                                'timestamp': t,
                            })
                    else:
                        self.group_messages[m.group_name].append({
                            'you': False,
                            'text': message.text,
                            'timestamp': t,
                            'sender': m.sender,
                        })
            time.sleep(5)


class KeyService(AbstractKeyService):
    def __init__(self):
        self._keys = {}

    def add_key(self, key_id, key):
        self._keys[key_id.hex()] = key

    def get_key(self, key_id):
        return self._keys[key_id.hex()]

    def key_exists(self, key_id):
        return key_id.hex() in self._keys


class RSAKeyService(AbstractRSAKeyService):
    def __init__(self):
        super().__init__()
        self.private_keys = {}
        self.public_keys = {}

    def add_rsa_private_key(self, key_id, key):
        self.private_keys[key_id.hex()] = key

    def add_rsa_public_key(self, key_id, key):
        self.public_keys[key_id.hex()] = key

    def get_rsa_private_key(self, key_id):
        return self.private_keys[key_id.hex()]

    def get_rsa_public_key(self, key_id):
        return self.public_keys[key_id.hex()]
