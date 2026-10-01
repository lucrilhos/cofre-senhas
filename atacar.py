import json
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from cofre import ARQUIVO, de_b64, derivar_chave

conteudo = json.loads(ARQUIVO.read_text())
kdf = conteudo['kdf']
params = {k: kdf[k] for k in ("time_cost", "memory_cost", "parallelism")}
salt, nonce, dados = de_b64(kdf["salt"]), de_b64(conteudo["nonce"]), de_b64(conteudo["dados"])

lista = ['1234', 'password', 'qwerty', 'senha', 'admin', 'abcd123', '1234', 'lucas']

inicio = time.perf_counter()
for i, tentativa in enumerate(lista, 1):
    chave = derivar_chave(tentativa, salt, params)
    try:
        AESGCM(chave).decrypt(nonce, dados, None)
        print(f"Quebrado na tentativa {i}: {tentativa}")
        break
    except InvalidTag:
        pass
    tempo_por = (time.perf_counter() - inicio) / i
    print(f"~{tempo_por:.2f}s por tentativa")
    print(f"rockyou.txt (14 milhões de senhas) levaria ~{tempo_por * 14000000 / 86400:.0f} dias")