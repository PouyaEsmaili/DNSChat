from abc import ABC, abstractmethod
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from google.protobuf import message_factory, timestamp_pb2
from google.protobuf import descriptor_pb2
from google.protobuf import message as pb_message
from google.protobuf import empty_pb2

from Crypto.Cipher import AES
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from common.api import dnschat_pb2


class AbstractKeyService(ABC):
    @abstractmethod
    def get_key(self, key_id: bytes) -> bytes:
        pass

class AbstractRSAKeyService(ABC):
    @abstractmethod
    def get_rsa_public_key(self, key_id: bytes) -> RSA.RsaKey:
        pass

    @abstractmethod
    def get_rsa_private_key(self, key_id: bytes) -> RSA.RsaKey:
        pass


class EncryptionService:

    def __init__(self, key_service: AbstractKeyService, rsa_key_service: AbstractRSAKeyService):
        descriptor_proto = descriptor_pb2.FileDescriptorProto().FromString(dnschat_pb2.DESCRIPTOR.serialized_pb)
        empty_descriptor_proto = descriptor_pb2.FileDescriptorProto().FromString(empty_pb2.DESCRIPTOR.serialized_pb)
        timestamp_descriptor_proto = descriptor_pb2.FileDescriptorProto().FromString(timestamp_pb2.DESCRIPTOR.serialized_pb)
        self.message_classes = message_factory.GetMessages([empty_descriptor_proto, timestamp_descriptor_proto, descriptor_proto])

        self.dh_params: dh.DHParameters = None

        self._key_service = key_service
        self._rsa_key_service = rsa_key_service

    def _get_key(self, key_id: bytes) -> bytes:
        return self._key_service.get_key(key_id)

    def _get_private_key(self, key_id: bytes) -> RSA.RsaKey:
        return self._rsa_key_service.get_rsa_private_key(key_id)

    def _get_public_key(self, key_id: bytes) -> RSA.RsaKey:
        return self._rsa_key_service.get_rsa_public_key(key_id)

    def encrypt(self, message: bytes, key_id: bytes) -> bytes:
        key = self._get_key(key_id)
        cipher = AES.new(key, AES.MODE_EAX)
        cipher_text, tag = cipher.encrypt_and_digest(message)
        return cipher.nonce + tag + cipher_text

    def decrypt(self, message: bytes, key_id: bytes) -> bytes:
        key = self._get_key(key_id)
        nonce, tag, ciphertext = message[:16], message[16:32], message[32:]
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext

    def encrypt_message(self, message: pb_message.Message, key_id: bytes) -> dnschat_pb2.EncryptedMessage:
        base_message = dnschat_pb2.BaseMessage(
            message=message.SerializeToString(),
            message_full_name=message.DESCRIPTOR.full_name,
        )
        serialized_base_message = base_message.SerializeToString()
        return dnschat_pb2.EncryptedMessage(
            message=self.encrypt(serialized_base_message, key_id),
            key_id=key_id,
        )

    def decrypt_message(self, message: dnschat_pb2.EncryptedMessage) -> pb_message.Message:
        serialized_base_message = self.decrypt(message.message, message.key_id)
        base_message = dnschat_pb2.BaseMessage.FromString(serialized_base_message)
        message_class = self.message_classes[base_message.message_full_name]
        return message_class.FromString(base_message.message)

    def sign(self, message: pb_message.Message, key_id: bytes) -> dnschat_pb2.SignedMessage:
        private_key = self._get_private_key(key_id)
        base_message = dnschat_pb2.BaseMessage(
            message=message.SerializeToString(),
            message_full_name=message.DESCRIPTOR.full_name,
        )
        serialized_base_message = base_message.SerializeToString()
        h = SHA256.new(serialized_base_message)
        signature = pkcs1_15.new(private_key).sign(h)
        return dnschat_pb2.SignedMessage(message=serialized_base_message, signature=signature, key_id=key_id)

    def verify(self, message: dnschat_pb2.SignedMessage, force_verify=True) -> pb_message.Message:
        if force_verify:
            public_key = self._get_public_key(message.key_id).public_key()
            h = SHA256.new(message.message)
            pkcs1_15.new(public_key).verify(h, message.signature)
        base_message = dnschat_pb2.BaseMessage.FromString(message.message)
        message_class = self.message_classes[base_message.message_full_name]
        return message_class.FromString(base_message.message)

    def dh_exchange(self, y: bytes, private_key: Optional[dh.DHPrivateKey] = None) -> (dh.DHPrivateKey, bytes):
        if not private_key:
            private_key = self.dh_params.generate_private_key()
        peer_public_key = serialization.load_pem_public_key(y, backend=None)
        shared_key = private_key.exchange(peer_public_key)
        derived_key = SHA256.new(shared_key).digest()
        return private_key, derived_key

    def dh_new_private_key(self) -> dh.DHPrivateKey:
        return self.dh_params.generate_private_key()

    def dh_get_public_key_id(self, key) -> bytes:
        if isinstance(key, dh.DHPrivateKey):
            return SHA256.new(key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            ).digest()[0:16]
        elif isinstance(key, dh.DHPublicKey):
            return SHA256.new(key.public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            ).digest()[0:16]
        else:
            return b''

    def generate_salt(self):
        return get_random_bytes(16)

    def hash_password(self, password: str, salt: bytes) -> bytes:
        return SHA256.new(password.encode() + salt).digest()
