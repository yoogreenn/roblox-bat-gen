import base64
import hashlib
import time

from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes

SEPARATOR = "|"
SIGNATURE_VERSION = "v1"
HEADER_NAME = "x-bound-auth-token"


def _der_to_raw(der_sig: bytes) -> bytes:
    r, s = utils.decode_dss_signature(der_sig)
    return r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")


def hash_body(body: str | None) -> str:
    data = body.encode("utf-8") if body is not None else b"undefined"
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


def sign_payload(private_key: ec.EllipticCurvePrivateKey, payload: str) -> str:
    der_sig = private_key.sign(payload.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(_der_to_raw(der_sig)).decode("ascii")


def generate_bat(url: str, method: str = "GET", body: str | None = None) -> str:
    private_key = ec.generate_private_key(ec.SECP256R1())
    timestamp = str(int(time.time()))
    hashed_body = hash_body(body)
    method_upper = method.upper()

    payload1 = SEPARATOR.join([hashed_body, timestamp, url, method_upper])
    payload2 = SEPARATOR.join(["", timestamp, url, method_upper])

    sig1 = sign_payload(private_key, payload1)
    sig2 = sign_payload(private_key, payload2)

    return SEPARATOR.join([SIGNATURE_VERSION, hashed_body, timestamp, sig1, sig2])


token = generate_bat("https://roblox.com/", "GET")
print(token)
