import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

chave = AESGCM.generate_key(bit_length=256) # geraçao de chave aleatoria; origem: argon2
aes = AESGCM(chave) # monta o cofre a partir dessa chave aleatoria

nonce = os.urandom(12) # nonce como numero de serie unico
mensagem = b"senha: 1234" # 'b' retorna em bytes

cifrado = aes.encrypt(nonce, mensagem, None) # encrypt do numero e mensagem; tranca ativa
print("cifrado:", cifrado.hex())
print("tamanho original:", len(mensagem), "| tamanho cifrado:", len(cifrado))

aberto = aes.decrypt(nonce, cifrado, None)
print("aberto:", aberto)

####### TESTE 01 - alteração em 1 bit do arquivo #######
adulterado = bytearray(cifrado) # nao é possivel modificar bytes, mas um byterray sim
adulterado[0] ^= 1 # '^=' inversão de 1 único bit do primeiro byte

try:
    aes.decrypt(nonce, bytes(adulterado), None)
except InvalidTag:
    print("-------- TESTE 1: Alteração detectada, cofre recusa abrir --------")

####### TESTE 02 - chave errada #######
chave2 = AESGCM(AESGCM.generate_key(bit_length=256))
try:
    chave2.decrypt(nonce, cifrado, None)
except InvalidTag:
    print("-------- TESTE 2: chave errada, cofre recusa abrir --------")
