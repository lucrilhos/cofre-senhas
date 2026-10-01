# 🔐 cofre-senhas

Gerenciador de senhas de linha de comando escrito em Python, com **Argon2id** para derivar a chave a partir da senha-mestra e **AES-256-GCM** para criptografar o cofre. Nenhuma senha é guardada em texto puro, nem a senha-mestra.

> Projeto de estudo em criptografia aplicada. O objetivo foi entender **por que** cada decisão de segurança existe e **como** cada uma falha quando é feita errado.

---

## ✨ Funcionalidades

- `init`: cria um cofre novo protegido por senha-mestra (mínimo de 12 caracteres)
- `add <nome>`: adiciona uma credencial (usuário + senha); se a senha ficar em branco, gera uma senha forte automaticamente
- `get <nome>`: mostra uma credencial
- `list`: lista os nomes salvos
- `delete <nome>`: remove uma credencial

---

## 🚀 Como usar

**Requisitos:** Python 3.10+ e Linux/macOS.

```bash
git clone https://github.com/lucrilhos/cofre-senhas.git
cd cofre-senhas
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

```bash
python cofre.py init           # cria o cofre e define a senha-mestra
python cofre.py add gmail      # pede usuário e senha (vazio = gera uma)
python cofre.py list           # lista os nomes salvos
python cofre.py get gmail      # mostra usuário e senha
python cofre.py delete gmail   # remove a entrada
python cofre.py --help         # ajuda
```

As senhas são sempre digitadas de forma oculta, nunca passadas como argumento.

---

## ⚙️ Como funciona

```
senha-mestra + salt aleatório ──[ Argon2id ]──► chave de 256 bits (só existe na memória)
                                                        │
dicionário de credenciais (JSON) + nonce aleatório ──[ AES-256-GCM ]──► texto cifrado + tag
```

O arquivo `cofre.json` guarda apenas o que é **público** e necessário para reabrir o cofre:

```json
{
  "versao": 1,
  "kdf": {
    "algoritmo": "argon2id",
    "time_cost": 3,
    "memory_cost": 65536,
    "parallelism": 4,
    "salt": "<base64>"
  },
  "nonce": "<base64>",
  "dados": "<base64 do texto cifrado + tag>"
}
```

| Elemento | Função | É segredo? |
|---|---|---|
| Senha-mestra | Origem da chave | **Sim**, nunca é salva |
| Salt (16 bytes) | Torna a chave única por cofre e inutiliza *rainbow tables* | Não |
| Parâmetros do Argon2 | "Receita" para recriar a mesma chave no futuro | Não |
| Chave (32 bytes) | Criptografa e descriptografa os dados | **Sim**, só existe na RAM |
| Nonce (12 bytes) | Garante que cada gravação gere um cifrado diferente | Não, mas nunca se repete |
| Tag do GCM (16 bytes) | Detecta qualquer alteração no arquivo | Não |

Todas as credenciais ficam em **um único bloco cifrado**, então quem tiver o arquivo não sabe nem **quais** serviços estão salvos.

---

## 🛡️ Decisões de segurança

**1. Argon2id em vez de SHA-256.**
Hashes como o SHA-256 são feitos para ser rápidos, e isso favorece o atacante, que testa bilhões de senhas por segundo em GPU. O Argon2id é **lento de propósito** e **memory-hard** (64 MiB por tentativa), o que encarece cada tentativa de força bruta e trava o paralelismo das GPUs.

Medição na minha máquina:

| Algoritmo | Tempo |
|---|---|
| SHA-256, 100.000 senhas | `<PREENCHER>` s |
| Argon2id, 1 senha | `<PREENCHER>` s |
| Argon2id, 100.000 senhas (estimado) | `<PREENCHER>` horas |

**2. AES-256-GCM (criptografia autenticada).**
Além de esconder os dados, o GCM gera uma *tag* de integridade. Alterar **um único bit** do arquivo faz o cofre recusar abrir. Senha errada e arquivo adulterado geram o mesmo erro, então o programa não dá pistas ao atacante.

**3. Nonce novo a cada gravação.**
Reutilizar nonce com a mesma chave no GCM quebra tanto a confidencialidade quanto a integridade. Por isso o cofre é recriptografado com um nonce aleatório novo sempre que é salvo.

**4. Parâmetros salvos no arquivo.**
Se a biblioteca mudar seus valores padrão no futuro, o cofre continua abrindo, porque a receita da chave está registrada.

**5. Aleatoriedade segura.**
Salt, nonce e senhas geradas vêm de `os.urandom` e `secrets`, nunca do módulo `random`, que é previsível.

**6. Senhas nunca como argumento de linha de comando.**
Argumentos ficam gravados no histórico do shell (`~/.bash_history`) e aparecem para outros usuários no `ps`. Todas as senhas são lidas com `getpass`.

**7. Escrita atômica.**
O cofre é gravado primeiro num arquivo temporário e só então substitui o original (`os.replace`). Se a energia cair no meio da gravação, o cofre antigo continua intacto.

**8. Permissão 600 desde a criação.**
O arquivo já nasce com `-rw-------` (só o dono lê e escreve). Criar e só depois aplicar `chmod` deixaria uma janela de tempo em que ele ficaria legível (*race condition*).

**9. Falhar fechado.**
Qualquer falha de verificação encerra o programa imediatamente (`sys.exit`), em vez de seguir "do jeito que der".

---

## 🎯 Modelo de ameaça

**Protege contra:** alguém que obteve uma cópia do `cofre.json` (notebook roubado, backup vazado, arquivo enviado por engano) e tenta descobrir as senhas por força bruta offline.

**Não protege contra:**
- malware ou keylogger rodando na máquina enquanto a senha-mestra é digitada;
- alguém com acesso à sua sessão enquanto o cofre está aberto;
- senha-mestra fraca (ver a seção abaixo).

---

## 🗡️ Atacando o próprio cofre

Para validar as defesas, escrevi um script de força bruta (`atacar.py`) que tenta abrir o cofre com uma lista de senhas comuns, como um atacante faria.

| Cenário | Resultado |
|---|---|
| Senha-mestra `1234` | Quebrada em `<PREENCHER>` s |
| Tempo por tentativa (Argon2id) | `<PREENCHER>` s |
| Wordlist *rockyou.txt* inteira (~14 milhões), estimado | `<PREENCHER>` dias |

**Conclusão:** a KDF deixa **cada tentativa** cara, mas não salva uma senha que está no topo de qualquer wordlist. Por isso o `init` exige no mínimo 12 caracteres. Segurança depende do algoritmo **e** da senha.

---

## ⚠️ Limitações conhecidas

- O Python não permite apagar com garantia a senha-mestra e a chave da memória RAM depois do uso.
- O comando `get` exibe a senha no terminal; ainda não há cópia para a área de transferência com limpeza automática.
- Não há troca de senha-mestra (seria necessário recriar o cofre).
- Não há sincronização entre dispositivos: é um cofre local.
- Projeto educacional, **não auditado**. Para uso real, prefira ferramentas consolidadas como Bitwarden, KeePassXC ou `pass`.

---

## 🧰 Tecnologias

- Python 3
- [`argon2-cffi`](https://pypi.org/project/argon2-cffi/): Argon2id
- [`cryptography`](https://pypi.org/project/cryptography/): AES-256-GCM
- Biblioteca padrão: `argparse`, `getpass`, `secrets`, `os`, `json`, `base64`, `pathlib`

---

## 📚 O que aprendi

- A diferença entre **hash**, **KDF** e **criptografia**, e por que hash rápido é péssimo para senhas
- O papel do salt, do nonce e da tag de autenticação, e o que é público ou secreto em cada um
- Como pequenos detalhes (argumentos de linha de comando, permissões, escrita não atômica, reúso de nonce) viram vulnerabilidades reais
- A visão de quem ataca: medir o custo real de um brute force offline

---

## 👤 Autor

**Lucas M. Moraes**, estudante de Ciência da Computação (FIAP), focado em cibersegurança.

- GitHub: [@lucrilhos](https://github.com/lucrilhos)
- LinkedIn: [lucas-mendes-473678339](https://www.linkedin.com/in/lucas-mendes-473678339)
