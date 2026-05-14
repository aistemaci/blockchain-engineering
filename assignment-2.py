import argparse
import hashlib
from asyncio import run, to_thread, sleep
from dataclasses import dataclass
import time
from messages import *

from ipv8.community import Community, CommunitySettings
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.payload_dataclass import DataClassPayload, type_from_format
from ipv8.peer import Peer
from ipv8.util import run_forever
from ipv8_service import IPv8

# change only these two lines per member 
MY_KEY_PATH   = "../aiste_pk.pem"  # path to your private key
MY_SUBMIT_ROUND = 1                # Aiste=1, Aykut=2, Yurian=3

COMMUNITY_ID = bytes.fromhex("4c61623247726f75705369676e696e6732303236")
SERVER_PUBLIC_KEY = bytes.fromhex(
    "4c69624e61434c504b3a82e33614a342774e084af80835838d6dbdb64a537d3ddb6c1d82011a7f101553cda40cf5fa0e0fc23abd0a9c4f81322282c5b34566f6b8401f5f683031e60c96"
)
AYKUT_PUBLIC_KEY = bytes.fromhex(
    "4c69624e61434c504b3ad8e3c43d2221dcef7f94eb20d566afeba009e90eb999d69511ebcbf369a3303895c92c299356298f6f115c26fb14ad994347b8447ac028640344b0abc34221cd"
)
AISTE_PUBLIC_KEY = bytes.fromhex(
    "4c69624e61434c504b3a2513a65668a4c90fecaab284db8c782ed99a4bcab0284902e50127c9bcafda4998739097897c8ea911a9dff86f6ca2b71d3fd9086b1c4775d6bd3d5c00c818f9"
)
YURIAN_PUBLIC_KEY = bytes.fromhex(
    "4c69624e61434c504b3afbc497359b4d8bc2d70fc55a3261ad831872055bd13bca87379be73cf9246e1611d4b25ac771d74cc8628d2c44c85f5de40aa9c79f2d6e9901a967063b621fc4"
)
MEMBER_KEYS = [AISTE_PUBLIC_KEY, AYKUT_PUBLIC_KEY, YURIAN_PUBLIC_KEY]
ROUND_SUBMITTERS = {1: AISTE_PUBLIC_KEY, 2: AYKUT_PUBLIC_KEY, 3: YURIAN_PUBLIC_KEY}

ME_PUBLIC_KEY = None

# Response compilations
_ = ResponseMessage(False, "", "")

# Global references
server_peer = None

class DelftCommunity(Community):
    community_id = COMMUNITY_ID

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.add_message_handler(ResponseMessage, self.on_response)
        self.add_message_handler(ChallengeResponseMessage, self.on_challenge_response)
        self.add_message_handler(SignatureShareMessage, self.on_signature_share)
        self.add_message_handler(RoundResultMessage, self.on_round_result)
        self.group_id = None
        self.signed_rounds: set[int] = set()
        self.collected_sigs: dict[int, dict] = {1: {}, 2: {}, 3: {}}
        self.nonces: dict[int, bytes] = {}

    # === HELPERS ===

    def get_peer_by_key(self, pubkey: bytes) -> Peer | None:
        for peer in self.get_peers():
            if peer.public_key.key_to_bin() == pubkey:
                return peer
        return None

    def request_challenge(self) -> None:
        if self.group_id and server_peer:
            self.ez_send(server_peer, ChallengeRequestMessage(group_id=self.group_id))

    def try_submit_bundle(self, round_number: int) -> None:
        sigs = self.collected_sigs[round_number]
        if len(sigs) < 3:
            return
        sig1 = sigs.get(AISTE_PUBLIC_KEY.hex())
        sig2 = sigs.get(AYKUT_PUBLIC_KEY.hex())
        sig3 = sigs.get(YURIAN_PUBLIC_KEY.hex())
        if not all([sig1, sig2, sig3]):
            return
        print(f"[Round {round_number}] Submitting bundle...")
        self.ez_send(server_peer, SignatureBundleMessage(
            group_id=self.group_id,
            round_number=round_number,
            sig1=sig1, sig2=sig2, sig3=sig3
        ))

    # === RESPONSE HANDLERS ===
    @lazy_wrapper(ResponseMessage)
    def on_response(self, peer: Peer, payload: ResponseMessage) -> None:
        print(f"Response from {peer}: \n\tsuccess={payload.success}, \n\tgroup_id={payload.group_id}, \n\tmessage={payload.message}\n")
        if peer != server_peer:
            return
        if payload.success:
            self.group_id = payload.group_id
            self.request_challenge()

    @lazy_wrapper(ChallengeResponseMessage)
    def on_challenge_response(self, peer: Peer, payload: ChallengeResponseMessage) -> None:
        print(f"Challenge response from {peer}: \n\tnonce={payload.nonce.hex()}, \n\tround_number={payload.round_number}, \n\tdeadline={time.ctime(payload.deadline)}\n")
        if peer != server_peer:
            return
        r = payload.round_number
        self.nonces[r] = payload.nonce

        # Sign only once per round
        if r not in self.signed_rounds:
            self.signed_rounds.add(r)
            sig = self.my_peer.key.sign(payload.nonce)
            self.collected_sigs[r][ME_PUBLIC_KEY.hex()] = sig

            # Send signature to this round's submitter (if not us)
            submitter_key = ROUND_SUBMITTERS[r]
            if submitter_key != ME_PUBLIC_KEY:
                submitter_peer = self.get_peer_by_key(submitter_key)
                if submitter_peer:
                    self.ez_send(submitter_peer, SignatureShareMessage(round_number=r, signature=sig))
                else:
                    print(f"[Round {r}] WARNING: submitter peer not found!")

            # Pipeline: fire next challenge immediately
            if r < 3:
                self.request_challenge()

        # If we are the submitter, try to bundle
        if ROUND_SUBMITTERS[r] == ME_PUBLIC_KEY:
            self.try_submit_bundle(r)

    @lazy_wrapper(SignatureShareMessage)
    def on_signature_share(self, peer: Peer, payload: SignatureShareMessage) -> None:
        r = payload.round_number
        sender_key = peer.public_key.key_to_bin().hex()
        print(f"[Round {r}] Signature received from {sender_key[:16]}...")
        self.collected_sigs[r][sender_key] = payload.signature
        if ROUND_SUBMITTERS[r] == ME_PUBLIC_KEY:
            # Re-request challenge to get nonce if we don't have it yet
            if r not in self.nonces:
                self.request_challenge()
            else:
                self.try_submit_bundle(r)

    @lazy_wrapper(RoundResultMessage)
    def on_round_result(self, peer: Peer, payload: RoundResultMessage) -> None:
        if peer != server_peer:
            return
        print(f"[Round {payload.round_number}] Result: success={payload.success}, "
              f"rounds_completed={payload.rounds_completed}, message={payload.message}")

    # === MENU OPTIONS ===
    async def create_submission_bundle(self) -> None:
        payload = GroupRegistrationMessage(
            pk1=AISTE_PUBLIC_KEY,
            pk2=AYKUT_PUBLIC_KEY,
            pk3=YURIAN_PUBLIC_KEY
        )
        print(server_peer)
        self.ez_send(server_peer, payload)

    async def reqest_challenge(self) -> None:
        self.request_challenge()

    async def get_my_key(self) -> None:
        print(self.my_peer.key.pub().key_to_bin().hex(), "\n")

    async def find_peers(self) -> None:
        print(f"=== Peers {len(self.get_peers())} === {time.ctime()} ===")
        for peer in self.get_peers():
            print(peer, peer.public_key.key_to_bin().hex())
        print("\n")


    # Starting function
    async def started(self) -> None:
        global ME_PUBLIC_KEY, server_peer
        ME_PUBLIC_KEY = self.my_peer.key.pub().key_to_bin()

        attempts = 0
        while server_peer is None:
            await sleep(0.1)
            for peer in self.get_peers():
                if peer.public_key.key_to_bin() == SERVER_PUBLIC_KEY:
                    server_peer = peer
                    print(f"Found server peer: {server_peer} after {attempts} attempts")
                    break
            attempts += 1
            if attempts % 50 == 0:
                print(f"{attempts} attempts")
    

async def start_client() -> None:
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key("client", "curve25519", MY_KEY_PATH)
    builder.add_overlay(
        "DelftCommunity",
        "client",
        [WalkerDefinition(Strategy.RandomWalk, 20, {"timeout": 3.0})],
        default_bootstrap_defs,
        {},
        [("started",)],
    )
    ipv8_instance = IPv8(builder.finalize(),
        extra_communities={"DelftCommunity": DelftCommunity}
    )
    await ipv8_instance.start()

    # Wait for community to be initialized
    community = None
    for overlay in ipv8_instance.overlays:
        if isinstance(overlay, DelftCommunity):
            community = overlay
            break

    # Main menu loop
    while True:
        print("1. Get my public key")
        print("2. Find peers")
        print("3. Create submission bundle")
        print("4. Start rounds")
        choice = 2
        try:
            choice = int(input(""))
        except:
            pass
        match choice:
            case 1:
                await community.get_my_key()
            case 2:
                await community.find_peers()
            case 3:
                await community.create_submission_bundle()
            case 4:
                await community.reqest_challenge()
            case _: 
                exit(0)
        await sleep(1)


run(start_client())
