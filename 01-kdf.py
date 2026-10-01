import os
import time
import hashlib
from argon2.low_level import hash_secret_raw, Type

def derivar_chave(senha: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=senha.encode("utf-8"), # criptografia transforma texto em bytes
        salt=salt,
        time_cost=3, # quantas passadas pela memoria
        # em kebibytes
        memory_cost=64 * 1024, # 64 mebibytes de ram por tentativa
        parallelism=4, # threads funcionando simultaneamente
        hash_len=32, # chave aes-256 -> corresponde a 256 bits (32 bytes)
        type=Type.ID,
    )

salt = os.urandom(16)

inicio = time.perf_counter()
k1 = derivar_chave("1234", salt)
tempo_argon = time.perf_counter() - inicio
print(f"O Argon levou {tempo_argon}s")
print(f"k1 = {k1}", k1.hex())

print(type(salt))   # <class 'bytes'>
print(len(salt))    # 16
print(salt.hex())   # algo como 3f9a1c... (muda toda vez que roda)