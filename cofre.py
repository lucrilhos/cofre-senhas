import argparse
import base64
import getpass # lê a senha sem mostrar na tela
import json
import os
import secrets # gera senhas aleatorias criptografadas
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from argon2.low_level import hash_secret_raw, Type

ARQUIVO = Path("cofre.json")
VERSAO = 1
PARAMS_PADRAO = {"time_cost": 3, "memory_cost": 64 * 1024, "parallelism": 4,}

def b64(dados: bytes) -> str:
    return base64.b64encode(dados).decode('ascii')

def de_b64(texto: str) -> bytes:
    return base64.b64decode(texto)

# importado do arquivo '01-kdf.py1'
def derivar_chave(senha: str, salt: bytes, params: dict) -> bytes:
    return hash_secret_raw(
        secret=senha.encode("utf-8"), # criptografia transforma texto em bytes
        salt=salt,
        time_cost=params["time_cost"], # quantas passadas pela memoria
        # em kebibytes
        memory_cost=params["memory_cost"], # 64 mebibytes de ram por tentativa
        parallelism=params["parallelism"], # threads funcionando simultaneamente
        hash_len=32, # chave aes-256 -> corresponde a 256 bits (32 bytes)
        type=Type.ID,
    )

def salvar(entradas: dict, chave: bytes, salt: bytes, params: dict) -> None:
    nonce = os.urandom(12)
    texto = json.dumps(entradas).encode('utf-8')
    cifrado = AESGCM(chave).encrypt(nonce, texto, None)
    conteudo = {
        "versao": VERSAO,
        "kdf": {"algoritmo": "argon2id", **params, "salt": b64(salt)},
        "nonce": b64(nonce),
        "dados": b64(cifrado),
    }
    escrever_atomico(conteudo)

def escrever_atomico(conteudo: dict) -> None:
    temp = ARQUIVO.with_suffix(".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(conteudo, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, ARQUIVO)

def abrir(senha: str):
    conteudo = json.loads(ARQUIVO.read_text())
    kdf = conteudo['kdf']
    params = {k: kdf[k] for k in ("time_cost", "memory_cost", "parallelism")}
    salt = de_b64(kdf['salt'])
    chave = derivar_chave(senha, salt, params)
    try:
        texto = AESGCM(chave).decrypt(de_b64(conteudo['nonce']),  de_b64(conteudo["dados"]), None)
    except InvalidTag:
        sys.exit("Erro: senha-mestra incorreta ou cofre corrompido.")
    return json.loads(texto), chave, salt, params

def pedir_senha_mestra() -> str:
    return getpass.getpass("Senha-mestra: ")

def cmd_init() -> None:
    if ARQUIVO.exists():
        sys.exit("Já existe um cofre nesse diretório.")
    senha = getpass.getpass("Crie uma senha-mestra (Mín. 12 caracteres): ")
    if len(senha) <12:
        sys.exit("Senha curta demais!")
    if senha != getpass.getpass("Repita a senha: "):
        sys.exit("As senhas não batem.")
    salt = os.urandom(16)
    chave = derivar_chave(senha, salt, PARAMS_PADRAO)
    salvar({}, chave, salt, PARAMS_PADRAO)
    print("Cofre criado!")

def cmd_add(nome: str) -> None:
    entradas, chave, salt, params = abrir(pedir_senha_mestra())
    usuario = input("Usuário/email: ")
    senha = getpass.getpass("Senha (deixar campo vazio para criar uma): ")
    if not senha:
        senha = secrets.token_urlsafe(20)
        print("Senha gerada automaticamente.")
    entradas[nome] = {"usuario": usuario, "senha": senha}
    salvar(entradas, chave, salt, params)
    print(f"'{nome}' salvo")

def cmd_get(nome: str) -> None:
    entradas, *_ = abrir(pedir_senha_mestra())
    if nome not in entradas:
        sys.exit(f"'{nome}' não existe no cofre.")
    print("Usuário:", entradas[nome]["usuario"])
    print("Senha: ", entradas[nome]["senha"])

def cmd_list() -> None:
    entradas, *_ = abrir(pedir_senha_mestra())
    for nome in sorted(entradas):
        print("-", nome)

def cmd_delete(nome: str) -> None:
    entradas, chave, salt, params = abrir(pedir_senha_mestra())
    if entradas.pop(nome, None) is None:
        sys.exit(f"'{nome}' não existe no cofre.")
    salvar(entradas, chave, salt, params)
    print(f"'{nome}' removido.")

def main() -> None:
    parser = argparse.ArgumentParser(description="Cofre de senhas (Argon2Id + AES-256-GCM)")
    sub = parser.add_subparsers(dest="comando", required=True)
    sub.add_parser("init", help="cria um cofre novo")
    sub.add_parser("list", help="lista dos nomes salvos")
    for cmd in ("add", "get", "delete"):
        p = sub.add_parser(cmd)
        p.add_argument("nome")
    args = parser.parse_args()

    if args.comando == "init":
        cmd_init()
    elif args.comando == "add":
        cmd_add(args.nome)
    elif args.comando == "get":
        cmd_get(args.nome)
    elif args.comando == "list":
        cmd_list()
    elif args.comando == "delete":
        cmd_delete(args.nome)

if __name__ == "__main__":
    main()