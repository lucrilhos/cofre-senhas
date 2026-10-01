import os
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from cofre import derivar_chave, PARAMS_PADRAO


def test_mesma_senha_mesmo_salt_mesma_chave():
    salt = os.urandom(16)
    assert derivar_chave("abc", salt, PARAMS_PADRAO) == derivar_chave("abc", salt, PARAMS_PADRAO)


def test_adulteracao_e_detectada():
    chave = derivar_chave("abc", os.urandom(16), PARAMS_PADRAO)
    nonce = os.urandom(12)
    cifrado = bytearray(AESGCM(chave).encrypt(nonce, b"segredo", None))
    cifrado[0] ^= 1
    with pytest.raises(InvalidTag):
        AESGCM(chave).decrypt(nonce, bytes(cifrado), None)