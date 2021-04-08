import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    padding, rsa
)


class Asymmetric:

    def __init__(self):
        self._privateKey = None
        self._publicKey = None

    def get_keys_hex(self) -> list:
        """
        returns keys (hex)
        :return: keys
        """
        private_pem = self._privateKey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = self._privateKey.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return [private_pem.hex(), public_pem.hex()]

    def get_keys_hex_ssh(self) -> list:
        """
        returns keys (hex_ssh)
        :return: keys
        """
        private_ssh = self._privateKey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_ssh = self._privateKey.public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        )
        return [private_ssh.hex(), public_ssh.hex()]

    def set_keys(self, private_key, public_key) -> None:
        """
        setts public and private keys
        :param private_key:
        :param public_key:
        :return:
        """
        self._privateKey = serialization.load_pem_private_key(
            bytearray.fromhex(private_key),
            password=None,
        )
        self._publicKey = serialization.load_pem_public_key(bytearray.fromhex(public_key))

    def generate_keys(self) -> None:
        """
        generates random keys
        :return:
        """
        self._privateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self._publicKey = self._privateKey.public_key()

    def sign_message(self, msg: str) -> bytes:
        """
        signs message
        :param msg: message to sign
        :return:
        """
        return base64.b64encode(self._privateKey.sign(
                bytes(msg, "utf-8"),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        )

    def verify_message(self, msg: str, signature: str) -> bool:
        """
        verifies message
        :param msg: message to verify
        :param signature:
        :return:
        """
        decoded_sign = base64.b64decode(signature)
        try:
            self._publicKey.verify(
                decoded_sign,
                bytes(msg, "utf-8"),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    def encode_message(self, msg: str) -> bytes:
        """
        encodes message
        :param msg: message to encode
        :return:
        """
        return base64.b64encode(self._publicKey.encrypt(
                bytes(msg, "utf-8"),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        )

    def decode_message(self, msg: str) -> str:
        """
        decodes message
        :param msg: message to decode
        :return:
        """
        decoded_msg = base64.b64decode(msg)
        return self._privateKey.decrypt(
            decoded_msg,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )