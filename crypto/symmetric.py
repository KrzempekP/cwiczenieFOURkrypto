from cryptography.fernet import Fernet


class Symmetric:

    def __init__(self):

        self._key = None

    @staticmethod
    def generate_random_key() -> str:
        """
        generates key
        :return: generated key
        """
        return Fernet.generate_key().hex()

    def set_key(self, key: str) -> None:
        """
        set's key
        :param key: k
        :return:
        """
        self._key = Fernet(bytearray.fromhex(key))

    def encode_message(self, message: str) -> bytes:
        """
        encodes message
        :param message: message to encode
        :return: encoded message
        """
        return self._key.encrypt(bytes(message, "utf-8"))

    def decode_message(self, message: str) -> bytes:
        """
        decodes message
        :param message: message to decode
        :return: decoded message
        """
        return self._key.decrypt(bytes(message, "utf-8"))