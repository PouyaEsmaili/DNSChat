from collections import defaultdict
from typing import cast, Tuple, Any, Optional

import grpc
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from django.utils import timezone

from google.protobuf import empty_pb2, timestamp_pb2

from common.api import dnschat_pb2_grpc, dnschat_pb2
from common.services import EncryptionService, AbstractKeyService, AbstractRSAKeyService
from server.models import Session, Configuration, User, Key, ChatMessage, Group, GroupMessage


class ChatServicer(dnschat_pb2_grpc.ChatServicer):
    def __init__(self):
        if Configuration.get('rsa_key'):
            self.rsa_key = RSA.import_key(Configuration.get('rsa_key'))
        else:
            self.rsa_key = RSA.generate(2048)
            Configuration.set('rsa_key', self.rsa_key.export_key(format='PEM'))
        self.rsa_key_id = SHA256.new(self.rsa_key.public_key().export_key(format='PEM')).digest()[0:16]

        self.encryption_service = EncryptionService(KeyService(), RSAKeyService(self.rsa_key_id, self.rsa_key))
        if Configuration.get('dh_params'):
            self.encryption_service.dh_params = serialization.load_pem_parameters(
                Configuration.get('dh_params'), backend=None
            )
        else:
            self.encryption_service.dh_params = dh.generate_parameters(generator=2, key_size=2048, backend=None)
            Configuration.set('dh_params', self.encryption_service.dh_params.parameter_bytes(
                encoding=serialization.Encoding.PEM, format=serialization.ParameterFormat.PKCS3
            ))

    def GetPublicKey(self, request: empty_pb2.Empty, context):
        return dnschat_pb2.RSAPubKey(public_key=self.rsa_key.public_key().export_key(format='PEM'))

    def GetDHParams(self, request: empty_pb2.Empty, context):
        dh_params = dnschat_pb2.DHParams(params=self.encryption_service.dh_params.parameter_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.ParameterFormat.PKCS3
        ))
        return self.encryption_service.sign(dh_params, self.rsa_key_id)

    def NewSession(self, request: dnschat_pb2.DHPubKey, context):
        private_key, derived_key = self.encryption_service.dh_exchange(request.y)
        key_id = SHA256.new(derived_key).digest()[0:16]

        Session.objects.create(key=derived_key, key_id=key_id)
        dh_pub_key = dnschat_pb2.DHPubKey(y=private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        print(f'New session: {key_id.hex()}')
        return self.encryption_service.sign(dh_pub_key, self.rsa_key_id)

    def Register(self, request: dnschat_pb2.EncryptedMessage, context):
        req = cast(dnschat_pb2.RegisterRequest, self.encryption_service.decrypt_message(request))
        if User.objects.filter(username=req.username).exists():
            signed_response = self.encryption_service.sign(dnschat_pb2.RegisterResponse(
                success=False, duplicate=True
            ), self.rsa_key_id)
            return self.encryption_service.encrypt_message(signed_response, request.key_id)
        salt = self.encryption_service.generate_salt()
        password_hash = self.encryption_service.hash_password(req.password, salt)
        user = User.objects.create(username=req.username, password_hash=password_hash, password_salt=salt)

        for key in req.keys:
            Key.objects.create(
                user=user,
                key_id=SHA256.new(key.public_key).digest()[0:16],
                public_key=key.public_key,
                encrypted_private_key=key.encrypted_private_key,
                is_active=False,
                is_used=False,
                is_rsa=key.is_rsa,
            )
            if key.is_rsa:
                rsa_key = RSA.import_key(key.public_key)

        chosen_key = Key.objects.filter(user=user, is_used=False, is_active=False, is_rsa=False).first()
        chosen_key.is_active = True
        chosen_key.is_used = True
        chosen_key.save()

        signed_response = self.encryption_service.sign(dnschat_pb2.RegisterResponse(success=True), self.rsa_key_id)
        return self.encryption_service.encrypt_message(signed_response, request.key_id)

    def Login(self, request: dnschat_pb2.EncryptedMessage, context):
        req = cast(dnschat_pb2.LoginRequest, self.encryption_service.decrypt_message(request))
        try:
            user = User.objects.get(username=req.username)
            if user.password_hash != self.encryption_service.hash_password(req.password, user.password_salt):
                signed_response = self.encryption_service.sign(dnschat_pb2.LoginResponse(success=False),
                                                               self.rsa_key_id)
                return self.encryption_service.encrypt_message(signed_response, request.key_id)
            session = Session.objects.get(key_id=request.key_id)
            session.user = user
            session.save()

            active_key = Key.objects.get(user=user, is_active=True)
            rsa_key = Key.objects.get(user=user, is_rsa=True)
            response = dnschat_pb2.LoginResponse(
                success=True,
                key=dnschat_pb2.Key(
                    public_key=active_key.public_key, encrypted_private_key=active_key.encrypted_private_key
                ),
                rsa_key=dnschat_pb2.Key(
                    public_key=rsa_key.public_key, encrypted_private_key=rsa_key.encrypted_private_key
                )
            )
            signed_response = self.encryption_service.sign(response, self.rsa_key_id)
            return self.encryption_service.encrypt_message(signed_response, request.key_id)
        except User.DoesNotExist:
            signed_response = self.encryption_service.sign(dnschat_pb2.LoginResponse(success=False), self.rsa_key_id)
            return self.encryption_service.encrypt_message(signed_response, request.key_id)

    def ListUsers(self, request: dnschat_pb2.EncryptedMessage, context):
        req, _ = self._decrypt_and_verify_request(request)
        if not req:
            return self._sign_and_encrypt_response(dnschat_pb2.ListUsersResponse(success=False), request.key_id)

        users = User.objects.all()
        users_pb = [
            dnschat_pb2.UserStatus(
                username=user.username,
                online=user.online
            ) for user in users
        ]
        response = dnschat_pb2.ListUsersResponse(success=True, users=users_pb)
        return self._sign_and_encrypt_response(response, request.key_id)

    def NewChatSession(self, request: dnschat_pb2.EncryptedMessage, context):
        req, _ = self._decrypt_and_verify_request(request)
        if not req:
            return self._sign_and_encrypt_response(dnschat_pb2.NewChatSessionResponse(success=False), request.key_id)
        req = cast(dnschat_pb2.NewChatSessionRequest, req)
        try:
            peer = User.objects.get(username=req.recipient)
            peer_dh_public_key = peer.keys.get(is_active=True, is_rsa=False).public_key
            peer_rsa_public_key = peer.keys.get(is_rsa=True).public_key
            response = dnschat_pb2.NewChatSessionResponse(
                success=True,
                dh_pub_key=dnschat_pb2.DHPubKey(y=peer_dh_public_key),
                rsa_pub_key=dnschat_pb2.RSAPubKey(public_key=peer_rsa_public_key)
            )
            return self._sign_and_encrypt_response(response, request.key_id)
        except User.DoesNotExist:
            response = dnschat_pb2.NewChatSessionResponse(success=False)
            return self._sign_and_encrypt_response(response, request.key_id)

    def SendChatMessage(self, request, context):
        req, user = self._decrypt_and_verify_request(request)
        if not req:
            return self._sign_and_encrypt_response(dnschat_pb2.SendChatMessageResponse(success=False), request.key_id)
        req = cast(dnschat_pb2.SendChatMessageRequest, req)

        if not req.is_group:
            try:
                peer = User.objects.get(username=req.recipient)
                peer_dh_public_key = peer.keys.get(is_active=True, is_rsa=False).public_key
                peer_dh_key_id = SHA256.new(peer_dh_public_key).digest()[0:16]
                if peer_dh_key_id != req.peer_dh_key_id:
                    response = dnschat_pb2.SendChatMessageResponse(success=False, session_expired=True)
                    return self._sign_and_encrypt_response(response, request.key_id)
                ChatMessage.objects.create(
                    sender=user,
                    recipient=peer,
                    message=req.message,
                    recipient_key_id=peer_dh_key_id,
                    sender_dh_public_key=user.keys.get(is_active=True, is_rsa=False).public_key,
                    sender_rsa_public_key=user.keys.get(is_rsa=True).public_key,
                    key_id=req.key_id,
                )
                response = dnschat_pb2.SendChatMessageResponse(success=True)
                return self._sign_and_encrypt_response(response, request.key_id)
            except User.DoesNotExist:
                response = dnschat_pb2.NewChatSessionResponse(success=False)
                return self._sign_and_encrypt_response(response, request.key_id)
        else:
            try:
                group = Group.objects.get(name=req.recipient)
                for member in group.members.split(','):
                    ChatMessage.objects.create(
                        sender=user,
                        recipient=User.objects.get(username=member),
                        group=group,
                        message=req.message,
                        sender_dh_public_key=user.keys.get(is_active=True, is_rsa=False).public_key,
                        sender_rsa_public_key=user.keys.get(is_rsa=True).public_key,
                        key_id=req.key_id,
                    )
                response = dnschat_pb2.SendChatMessageResponse(success=True)
                return self._sign_and_encrypt_response(response, request.key_id)
            except Group.DoesNotExist:
                response = dnschat_pb2.NewChatSessionResponse(success=False)
                return self._sign_and_encrypt_response(response, request.key_id)

    def PullMessages(self, request, context):
        req, user = self._decrypt_and_verify_request(request)
        if not req:
            return self._sign_and_encrypt_response(dnschat_pb2.PullMessageResponse(success=False), request.key_id)
        chat_messages = ChatMessage.objects.order_by('created_at').filter(recipient=user)
        chat_messages_pb = [
            dnschat_pb2.EncryptedChatMessage(
                message=dnschat_pb2.EncryptedMessage(message=m.message, key_id=m.key_id),
                sender=m.sender.username,
                timestamp=timestamp_pb2.Timestamp(seconds=int(m.created_at.timestamp())),
                group_name=m.group.name if m.group else None,
                sender_dh_pub_key=dnschat_pb2.DHPubKey(y=m.sender_dh_public_key),
                sender_rsa_pub_key=dnschat_pb2.RSAPubKey(public_key=m.sender_rsa_public_key),
            ) for m in chat_messages
        ]
        chat_messages.delete()
        user.last_pull = timezone.now()
        user.save()
        response = dnschat_pb2.PullMessageResponse(success=True, messages=chat_messages_pb)
        return self._sign_and_encrypt_response(response, request.key_id)

    def ExpireSession(self, request, context):
        req, user = self._decrypt_and_verify_request(request)
        if not req:
            return self._sign_and_encrypt_response(dnschat_pb2.Key(), request.key_id)
        user.keys.filter(is_active=True).update(is_active=False, is_used=True)
        chosen_key = user.keys.filter(is_used=False).first()
        chosen_key.is_active = True
        chosen_key.save()
        response = dnschat_pb2.Key(public_key=chosen_key.public_key,
                                   encrypted_private_key=chosen_key.encrypted_private_key)
        return self._sign_and_encrypt_response(response, request.key_id)

    def CreateGroup(self, request, context):
        req, user = self._decrypt_and_verify_request(request)
        if not req:
            return self._sign_and_encrypt_response(dnschat_pb2.CreateGroupResponse(), request.key_id)
        req = cast(dnschat_pb2.CreateGroupRequest, req)
        if Group.objects.filter(name=req.group_name).exists():
            return self._sign_and_encrypt_response(dnschat_pb2.CreateGroupResponse(duplicate=True), request.key_id)
        Group.objects.create(
            name=req.group_name,
            admin=user,
            members=user.username,
        )
        response = dnschat_pb2.CreateGroupResponse(success=True, duplicate=False)
        return self._sign_and_encrypt_response(response, request.key_id)

    def AddUserToGroup(self, request, context):
        req, user = self._decrypt_and_verify_request(request)
        if not req:
            return self._sign_and_encrypt_response(dnschat_pb2.AddUserToGroupResponse(success=False), request.key_id)
        req = cast(dnschat_pb2.AddUserToGroupRequest, req)
        try:
            group = Group.objects.get(name=req.group_name)
            user = User.objects.get(username=req.user)
            if req.user in group.members.split(','):
                return self._sign_and_encrypt_response(dnschat_pb2.AddUserToGroupResponse(
                    success=False, duplicate=True
                ), request.key_id)

            group.members += f',{user.username}'
            group.save()

            public_keys = {}
            for username in group.members.split(','):
                public_keys[username] = dnschat_pb2.DHPubKey(
                    y=User.objects.get(username=username).keys.get(is_active=True, is_rsa=False).public_key
                )
            response = dnschat_pb2.AddUserToGroupResponse(success=True, user_dh_pub_keys=public_keys)
            return self._sign_and_encrypt_response(response, request.key_id)
        except (Group.DoesNotExist, User.DoesNotExist):
            return self._sign_and_encrypt_response(dnschat_pb2.AddUserToGroupResponse(success=False), request.key_id)

    def RemoveUserFromGroup(self, request, context):
        req, user = self._decrypt_and_verify_request(request)
        if not req:
            return self._sign_and_encrypt_response(dnschat_pb2.RemoveUserFromGroupResponse(success=False),
                                                   request.key_id)
        req = cast(dnschat_pb2.RemoveUserFromGroupRequest, req)
        try:
            group = Group.objects.get(name=req.group_name)
            user = User.objects.get(username=req.user)
            members = group.members.split(',')

            if req.user not in members:
                return self._sign_and_encrypt_response(dnschat_pb2.RemoveUserFromGroupResponse(
                    success=False, not_found=True
                ), request.key_id)

            members.remove(user)
            group.members = ','.join(members)
            group.save()

            public_keys = {}
            for username in members:
                public_keys[username] = dnschat_pb2.DHPubKey(
                    y=User.objects.get(username=username).keys.get(is_active=True, is_rsa=False).public_key
                )
            response = dnschat_pb2.RemoveUserFromGroupResponse(success=True, user_dh_pub_keys=public_keys)
            return self._sign_and_encrypt_response(response, request.key_id)
        except (Group.DoesNotExist, User.DoesNotExist):
            return self._sign_and_encrypt_response(dnschat_pb2.RemoveUserFromGroupResponse(success=False),
                                                   request.key_id)

    def _decrypt_and_verify_request(self, request: dnschat_pb2.EncryptedMessage) -> Tuple[Any, Optional[User]]:
        signed_req = cast(dnschat_pb2.SignedMessage, self.encryption_service.decrypt_message(request))
        req = self.encryption_service.verify(signed_req)
        user = Session.objects.get(key_id=request.key_id).user
        if not user:
            return None, None
        user_signature_id = SHA256.new(
            user.keys.filter(is_rsa=True).first().public_key
        ).digest()[0:16]
        if signed_req.key_id != user_signature_id:
            return None, None
        return req, user

    def _sign_and_encrypt_response(self, response, key_id) -> dnschat_pb2.EncryptedMessage:
        signed_response = self.encryption_service.sign(response, self.rsa_key_id)
        return self.encryption_service.encrypt_message(signed_response, key_id)


class KeyService(AbstractKeyService):
    def get_key(self, key_id: bytes) -> bytes:
        return Session.objects.get(key_id=key_id).key


class RSAKeyService(AbstractRSAKeyService):
    def __init__(self, server_key_id: bytes, server_private_key: RSA.RsaKey):
        super().__init__()
        self.server_key_id = server_key_id
        self.server_private_key = server_private_key

    def get_rsa_private_key(self, key_id):
        if key_id == self.server_key_id:
            return self.server_private_key

    def get_rsa_public_key(self, key_id):
        if key_id == self.server_key_id:
            return self.server_private_key.publickey()
        key = Key.objects.filter(key_id=key_id).first()
        if not key:
            return None
        return RSA.import_key(key.public_key)
