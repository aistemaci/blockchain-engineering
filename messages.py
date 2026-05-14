from dataclasses import dataclass
from ipv8.messaging.payload_dataclass import DataClassPayload

@dataclass
class GroupRegistrationMessage(DataClassPayload[1]):
    pk1: bytes
    pk2: bytes
    pk3: bytes

@dataclass
class ResponseMessage(DataClassPayload[2]):
    success: bool
    group_id: str
    message: str

@dataclass
class ChallengeRequestMessage(DataClassPayload[3]):
    group_id: str

@dataclass
class ChallengeResponseMessage(DataClassPayload[4]):
    nonce: bytes
    round_number: int
    deadline: float

@dataclass
class SignatureBundleMessage(DataClassPayload[5]):
    group_id: str
    round_number: int
    sig1: bytes
    sig2: bytes
    sig3: bytes

@dataclass
class RoundResultMessage(DataClassPayload[6]):
    success: bool
    round_number: int
    rounds_completed: int
    message: str

@dataclass
class SignatureShareMessage(DataClassPayload[7]):
    round_number: int
    signature: bytes