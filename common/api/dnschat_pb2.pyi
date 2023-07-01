from google.protobuf import empty_pb2 as _empty_pb2
from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Simple(_message.Message):
    __slots__ = ["text"]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    text: str
    def __init__(self, text: _Optional[str] = ...) -> None: ...

class GroupChatKey(_message.Message):
    __slots__ = ["key", "group_name"]
    KEY_FIELD_NUMBER: _ClassVar[int]
    GROUP_NAME_FIELD_NUMBER: _ClassVar[int]
    key: bytes
    group_name: str
    def __init__(self, key: _Optional[bytes] = ..., group_name: _Optional[str] = ...) -> None: ...

class BaseMessage(_message.Message):
    __slots__ = ["message", "message_full_name", "nonce"]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FULL_NAME_FIELD_NUMBER: _ClassVar[int]
    NONCE_FIELD_NUMBER: _ClassVar[int]
    message: bytes
    message_full_name: str
    nonce: str
    def __init__(self, message: _Optional[bytes] = ..., message_full_name: _Optional[str] = ..., nonce: _Optional[str] = ...) -> None: ...

class SignedMessage(_message.Message):
    __slots__ = ["message", "signature", "key_id"]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    KEY_ID_FIELD_NUMBER: _ClassVar[int]
    message: bytes
    signature: bytes
    key_id: bytes
    def __init__(self, message: _Optional[bytes] = ..., signature: _Optional[bytes] = ..., key_id: _Optional[bytes] = ...) -> None: ...

class EncryptedMessage(_message.Message):
    __slots__ = ["message", "key_id"]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    KEY_ID_FIELD_NUMBER: _ClassVar[int]
    message: bytes
    key_id: bytes
    def __init__(self, message: _Optional[bytes] = ..., key_id: _Optional[bytes] = ...) -> None: ...

class RSAPubKey(_message.Message):
    __slots__ = ["public_key"]
    PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    public_key: bytes
    def __init__(self, public_key: _Optional[bytes] = ...) -> None: ...

class DHParams(_message.Message):
    __slots__ = ["params"]
    PARAMS_FIELD_NUMBER: _ClassVar[int]
    params: bytes
    def __init__(self, params: _Optional[bytes] = ...) -> None: ...

class DHPubKey(_message.Message):
    __slots__ = ["y"]
    Y_FIELD_NUMBER: _ClassVar[int]
    y: bytes
    def __init__(self, y: _Optional[bytes] = ...) -> None: ...

class Key(_message.Message):
    __slots__ = ["public_key", "encrypted_private_key", "is_rsa"]
    PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTED_PRIVATE_KEY_FIELD_NUMBER: _ClassVar[int]
    IS_RSA_FIELD_NUMBER: _ClassVar[int]
    public_key: bytes
    encrypted_private_key: bytes
    is_rsa: bool
    def __init__(self, public_key: _Optional[bytes] = ..., encrypted_private_key: _Optional[bytes] = ..., is_rsa: bool = ...) -> None: ...

class RegisterRequest(_message.Message):
    __slots__ = ["username", "password", "keys", "rsa_pub_key"]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    PASSWORD_FIELD_NUMBER: _ClassVar[int]
    KEYS_FIELD_NUMBER: _ClassVar[int]
    RSA_PUB_KEY_FIELD_NUMBER: _ClassVar[int]
    username: str
    password: str
    keys: _containers.RepeatedCompositeFieldContainer[Key]
    rsa_pub_key: RSAPubKey
    def __init__(self, username: _Optional[str] = ..., password: _Optional[str] = ..., keys: _Optional[_Iterable[_Union[Key, _Mapping]]] = ..., rsa_pub_key: _Optional[_Union[RSAPubKey, _Mapping]] = ...) -> None: ...

class RegisterResponse(_message.Message):
    __slots__ = ["success", "duplicate"]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    DUPLICATE_FIELD_NUMBER: _ClassVar[int]
    success: bool
    duplicate: bool
    def __init__(self, success: bool = ..., duplicate: bool = ...) -> None: ...

class LoginRequest(_message.Message):
    __slots__ = ["username", "password"]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    PASSWORD_FIELD_NUMBER: _ClassVar[int]
    username: str
    password: str
    def __init__(self, username: _Optional[str] = ..., password: _Optional[str] = ...) -> None: ...

class LoginResponse(_message.Message):
    __slots__ = ["success", "key", "rsa_key"]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    RSA_KEY_FIELD_NUMBER: _ClassVar[int]
    success: bool
    key: Key
    rsa_key: Key
    def __init__(self, success: bool = ..., key: _Optional[_Union[Key, _Mapping]] = ..., rsa_key: _Optional[_Union[Key, _Mapping]] = ...) -> None: ...

class EncryptedChatMessage(_message.Message):
    __slots__ = ["message", "sender", "timestamp", "group_name", "sender_dh_pub_key", "sender_rsa_pub_key"]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    SENDER_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    GROUP_NAME_FIELD_NUMBER: _ClassVar[int]
    SENDER_DH_PUB_KEY_FIELD_NUMBER: _ClassVar[int]
    SENDER_RSA_PUB_KEY_FIELD_NUMBER: _ClassVar[int]
    message: EncryptedMessage
    sender: str
    timestamp: _timestamp_pb2.Timestamp
    group_name: str
    sender_dh_pub_key: DHPubKey
    sender_rsa_pub_key: RSAPubKey
    def __init__(self, message: _Optional[_Union[EncryptedMessage, _Mapping]] = ..., sender: _Optional[str] = ..., timestamp: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., group_name: _Optional[str] = ..., sender_dh_pub_key: _Optional[_Union[DHPubKey, _Mapping]] = ..., sender_rsa_pub_key: _Optional[_Union[RSAPubKey, _Mapping]] = ...) -> None: ...

class PullMessageResponse(_message.Message):
    __slots__ = ["success", "messages"]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    MESSAGES_FIELD_NUMBER: _ClassVar[int]
    success: bool
    messages: _containers.RepeatedCompositeFieldContainer[EncryptedChatMessage]
    def __init__(self, success: bool = ..., messages: _Optional[_Iterable[_Union[EncryptedChatMessage, _Mapping]]] = ...) -> None: ...

class NewChatSessionRequest(_message.Message):
    __slots__ = ["recipient"]
    RECIPIENT_FIELD_NUMBER: _ClassVar[int]
    recipient: str
    def __init__(self, recipient: _Optional[str] = ...) -> None: ...

class NewChatSessionResponse(_message.Message):
    __slots__ = ["success", "dh_pub_key", "rsa_pub_key"]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    DH_PUB_KEY_FIELD_NUMBER: _ClassVar[int]
    RSA_PUB_KEY_FIELD_NUMBER: _ClassVar[int]
    success: bool
    dh_pub_key: DHPubKey
    rsa_pub_key: RSAPubKey
    def __init__(self, success: bool = ..., dh_pub_key: _Optional[_Union[DHPubKey, _Mapping]] = ..., rsa_pub_key: _Optional[_Union[RSAPubKey, _Mapping]] = ...) -> None: ...

class SendChatMessageRequest(_message.Message):
    __slots__ = ["message", "recipient", "is_group", "key_id", "peer_dh_key_id"]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    RECIPIENT_FIELD_NUMBER: _ClassVar[int]
    IS_GROUP_FIELD_NUMBER: _ClassVar[int]
    KEY_ID_FIELD_NUMBER: _ClassVar[int]
    PEER_DH_KEY_ID_FIELD_NUMBER: _ClassVar[int]
    message: bytes
    recipient: str
    is_group: bool
    key_id: bytes
    peer_dh_key_id: bytes
    def __init__(self, message: _Optional[bytes] = ..., recipient: _Optional[str] = ..., is_group: bool = ..., key_id: _Optional[bytes] = ..., peer_dh_key_id: _Optional[bytes] = ...) -> None: ...

class SendChatMessageResponse(_message.Message):
    __slots__ = ["success", "session_expired"]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    SESSION_EXPIRED_FIELD_NUMBER: _ClassVar[int]
    success: bool
    session_expired: bool
    def __init__(self, success: bool = ..., session_expired: bool = ...) -> None: ...

class StoreEncryptedDataRequest(_message.Message):
    __slots__ = ["data"]
    DATA_FIELD_NUMBER: _ClassVar[int]
    data: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, data: _Optional[_Iterable[bytes]] = ...) -> None: ...

class StoreEncryptedDataResponse(_message.Message):
    __slots__ = ["success"]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    success: _containers.RepeatedScalarFieldContainer[bool]
    def __init__(self, success: _Optional[_Iterable[bool]] = ...) -> None: ...

class UserStatus(_message.Message):
    __slots__ = ["username", "online"]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    ONLINE_FIELD_NUMBER: _ClassVar[int]
    username: str
    online: bool
    def __init__(self, username: _Optional[str] = ..., online: bool = ...) -> None: ...

class ListUsersResponse(_message.Message):
    __slots__ = ["success", "users"]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    USERS_FIELD_NUMBER: _ClassVar[int]
    success: bool
    users: _containers.RepeatedCompositeFieldContainer[UserStatus]
    def __init__(self, success: bool = ..., users: _Optional[_Iterable[_Union[UserStatus, _Mapping]]] = ...) -> None: ...

class CreateGroupRequest(_message.Message):
    __slots__ = ["group_name"]
    GROUP_NAME_FIELD_NUMBER: _ClassVar[int]
    group_name: str
    def __init__(self, group_name: _Optional[str] = ...) -> None: ...

class CreateGroupResponse(_message.Message):
    __slots__ = ["success", "duplicate"]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    DUPLICATE_FIELD_NUMBER: _ClassVar[int]
    success: bool
    duplicate: bool
    def __init__(self, success: bool = ..., duplicate: bool = ...) -> None: ...

class AddUserToGroupRequest(_message.Message):
    __slots__ = ["group_name", "user"]
    GROUP_NAME_FIELD_NUMBER: _ClassVar[int]
    USER_FIELD_NUMBER: _ClassVar[int]
    group_name: str
    user: str
    def __init__(self, group_name: _Optional[str] = ..., user: _Optional[str] = ...) -> None: ...

class AddUserToGroupResponse(_message.Message):
    __slots__ = ["success", "duplicate", "user_dh_pub_keys"]
    class UserDhPubKeysEntry(_message.Message):
        __slots__ = ["key", "value"]
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: DHPubKey
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[DHPubKey, _Mapping]] = ...) -> None: ...
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    DUPLICATE_FIELD_NUMBER: _ClassVar[int]
    USER_DH_PUB_KEYS_FIELD_NUMBER: _ClassVar[int]
    success: bool
    duplicate: bool
    user_dh_pub_keys: _containers.MessageMap[str, DHPubKey]
    def __init__(self, success: bool = ..., duplicate: bool = ..., user_dh_pub_keys: _Optional[_Mapping[str, DHPubKey]] = ...) -> None: ...

class RemoveUserFromGroupRequest(_message.Message):
    __slots__ = ["group_name", "user"]
    GROUP_NAME_FIELD_NUMBER: _ClassVar[int]
    USER_FIELD_NUMBER: _ClassVar[int]
    group_name: str
    user: str
    def __init__(self, group_name: _Optional[str] = ..., user: _Optional[str] = ...) -> None: ...

class RemoveUserFromGroupResponse(_message.Message):
    __slots__ = ["success", "not_found", "user_dh_pub_keys"]
    class UserDhPubKeysEntry(_message.Message):
        __slots__ = ["key", "value"]
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: DHPubKey
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[DHPubKey, _Mapping]] = ...) -> None: ...
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    NOT_FOUND_FIELD_NUMBER: _ClassVar[int]
    USER_DH_PUB_KEYS_FIELD_NUMBER: _ClassVar[int]
    success: bool
    not_found: bool
    user_dh_pub_keys: _containers.MessageMap[str, DHPubKey]
    def __init__(self, success: bool = ..., not_found: bool = ..., user_dh_pub_keys: _Optional[_Mapping[str, DHPubKey]] = ...) -> None: ...
