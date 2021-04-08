from fastapi import FastAPI
from crypto.symmetric import Symmetric
from crypto.asymmetric import Asymmetric
from pydantic import BaseModel

symmetric = Symmetric()
asymmetric = Asymmetric()

app = FastAPI()


class Crypt(BaseModel):
    text: str


class SignedCrypto(BaseModel):
    text: str
    signature: str


@app.get("/symmetric/key")
def get_key():
    """
    Returns random key
    :return: key
    """
    return Symmetric.generate_random_key()


@app.post("/symmetric/key")
def post_key(key):
    """
    sets key on server
    :param key:
    :return: information about set key
    """
    symmetric.set_key(key)
    return {"Key set"}


@app.post("/symmetric/encode")
def post_encode(msg: Crypt):
    """
    encoding message
    :param msg: message to encode
    :return: returns encoded message
    """
    return {"Encoded message": symmetric.encode_message(msg.text)}


@app.post("/symmetric/decode")
def post_decode(msg: Crypt):
    """
    decoding message
    :param msg: message to decode
    :return: decoded message
    """
    return {"Decoded message": symmetric.decode_message(msg.text)}


@app.get("/asymmetric/key")
def get_asymmetric_keys():
    """
    returns new public and private keys and sets it on server
    :return: keys
    """
    asymmetric.generate_keys()
    keys = asymmetric.get_keys_hex()
    return {"Private Key": keys[0], "Public Key:": keys[1]}


@app.get("/asymmetric/key/ssh")
def get_asymmetric_keys_ssh():
    """
    returns public and privatge kets in OpenSSH format
    :return: keys
    """
    keys = asymmetric.get_keys_hex_ssh()
    return {"Private SSH Key": keys[0], "Public SSH Key:": keys[1]}


@app.post("/asymmetric/key")
def post_asymmetric_keys(private_key, public_key):
    """
    sets public and private keys in HEX form
    :param private_key:
    :param public_key:
    :return: information about setting games
    """
    asymmetric.set_keys(private_key, public_key)
    return {"Keys set"}


@app.post("/asymmetric/verify")
def post_asymmetric_sing_message(msg: SignedCrypto):
    """
    using actual set public key, verifies it and returns desyphered
    :param msg: message to verify
    :return: verified message
    """
    verification = asymmetric.verify_message(msg.text, msg.signature)
    return {"Sign verification": verification}


@app.post("/asymmetric/sign")
def post_asymmetric_sing_message(msg: Crypt):
    """
    using actual set private key, signs message and returns it signed
    :param msg: message to sign
    :return: signed message
    """
    signed_message = asymmetric.sign_message(msg.text)
    return {"Signed Message": signed_message}


@app.post("/asymmetric/encode")
def post_asymmetric_encode_message(msg: Crypt):
    """
    sends message and returns it encoded
    :param msg: message to encode
    :return: encoded message
    """
    encoded_message = asymmetric.encode_message(msg.text)
    return {"Encoded message": encoded_message}


@app.post("/asymmetric/decode")
def post_asymmetric_decode_message(msg: Crypt):
    """
    sends message to decode and returns it
    :param msg: message to decode
    :return: decoded message
    """
    decoded_message = asymmetric.decode_message(msg.text)
    return {"Decoded message": decoded_message}
