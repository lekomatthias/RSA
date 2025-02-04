
from random import randint
from math import gcd
from hashlib import sha3_256
from base64 import b64encode, b64decode

"""
Código feito para disciplina de segunraça computacional. UnB 2024/2

Aqui é implementada a função de criptografia RSA com o objetivo de fazer uma
verificação de assinatura digital.
As chaves geradas tem como base números primos de 1024 bits, com verificação de
primalidade Miller-Rabin.
O padding utilizado é o OAEP.
É utilizado o hash SHA3 com 256 bits para verificação de originalidade da mensagem.
A mensagem é codificada em BASE64 para ser criptografada.
"""

# ---------- Teste de Primalidade Miller-Rabin ----------
def miller_rabin(n, k=100):
    """
    Verifica se um numero e primo usando o teste de Miller-Rabin.
    """
    if n % 2 == 0:
        return False
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = randint(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


# ---------- Geracao de Chaves RSA ----------
def rsa_keygen(bits):
    """
    Geracao de chaves RSA com primitivas criptograficas de 'bits' bits.
    """
    def find_e(phi):
        """Encontra um 'e' coprimo de phi."""
        for e in range(3, phi, 2):  # Evitar números pares
            if gcd(e, phi) == 1:
                return e

    nbm, nb = 2 ** (bits - 1), 2 ** bits

    while True:
        p = randint(nbm, nb)
        if miller_rabin(p):
            break

    while True:
        q = randint(nbm, nb)
        if miller_rabin(q) and p != q:
            break

    n, phi = p * q, (p - 1) * (q - 1)
    e = find_e(phi)
    d = pow(e, -1, phi)

    print(f"Chave Publica (e, n): ({e}, {n})")
    print(f"Chave Privada (d, n): ({d}, {n})")

    return (e, n), (d, n)


# ---------- Mascara OAEP ----------
def mgf(seed, mask_len):
    """
    Gera mascara MGF1 usando SHA3-256.
    """
    h_len = sha3_256().digest_size
    mask = b""
    for i in range((mask_len + h_len - 1) // h_len):
        C = i.to_bytes(4, byteorder="big")
        mask += sha3_256(seed + C).digest()
    return mask[:mask_len]


def oaep_encode(message, k, label=b""):
    """
    Aplica padding OAEP na mensagem antes da criptografia RSA.
    """
    h_len = sha3_256().digest_size
    l_hash = sha3_256(label).digest()

    ps = b"\x00" * (k - len(message) - 2 * h_len - 2)
    db = l_hash + ps + b"\x01" + message

    seed = sha3_256(str(randint(0, 2**64)).encode()).digest()[:h_len]

    db_mask = mgf(seed, k - h_len - 1)
    masked_db = bytes(x ^ y for x, y in zip(db, db_mask))

    seed_mask = mgf(masked_db, h_len)
    masked_seed = bytes(x ^ y for x, y in zip(seed, seed_mask))

    encoded = b"\x00" + masked_seed + masked_db

    return encoded


def oaep_decode(encoded, k, label=b""):
    """
    Remove o padding OAEP apos a descriptografia RSA.
    """
    h_len = sha3_256().digest_size
    l_hash = sha3_256(label).digest()

    if len(encoded) < k:
        encoded = (b"\x00" * (k - len(encoded))) + encoded

    masked_seed = encoded[1:h_len + 1]
    masked_db = encoded[h_len + 1:]

    seed_mask = mgf(masked_db, h_len)
    seed = bytes(x ^ y for x, y in zip(masked_seed, seed_mask))

    db_mask = mgf(seed, k - h_len - 1)
    db = bytes(x ^ y for x, y in zip(masked_db, db_mask))

    extracted_l_hash = db[:h_len]
    if extracted_l_hash != l_hash:
        print("Erro na verificacao do l_hash! Padding OAEP pode estar incorreto.")
        print(f"Esperado: {l_hash.hex()}")
        print(f"Extraido: {extracted_l_hash.hex()}")
        return None

    try:
        index = db.index(b"\x01", h_len)
        return db[index + 1:]
    except ValueError:
        print("Falha ao remover OAEP. Delimitador '0x01' nao encontrado.")
        return None


# ---------- Criptografia e Descriptografia RSA ----------
def rsa_sign(Pr, message):
    """
    Assina uma mensagem usando RSA e OAEP.
    """
    d, n = Pr
    k = (n.bit_length() + 7) // 8
    message_hash = sha3_256(message.encode()).digest()
    encoded = oaep_encode(message_hash, k)

    m = int.from_bytes(encoded, byteorder="big")

    signature = pow(m, d, n)

    # Convertendo a assinatura para base 64
    signature_b64 = b64encode(signature.to_bytes((signature.bit_length() + 7) // 8, byteorder="big")).decode()

    return signature_b64

def rsa_verify(Pu, message, signature_b64):
    """
    Verifica a assinatura de uma mensagem usando RSA e OAEP.
    """
    e, n = Pu
    k = (n.bit_length() + 7) // 8

    # Decodificando a assinatura de base 64
    signature = int.from_bytes(b64decode(signature_b64), byteorder="big")

    decrypted_int = pow(signature, e, n)
    decrypted_bytes = decrypted_int.to_bytes(k, byteorder="big")

    if decrypted_bytes[0] == 0x00:
        decrypted_bytes = decrypted_bytes[1:]

    try:
        decoded = oaep_decode(decrypted_bytes, k)
        decoded_hash = decoded if decoded else b""
        message_hash = sha3_256(message.encode()).digest()
        print(f"Hash da mensagem: {message_hash.hex()}")
        print(f"Hash decodificado: {decoded_hash.hex()}")
        if decoded_hash == message_hash:
            return True
        else:
            print("Falha na verificacao da assinatura!")
            return False
    except UnicodeDecodeError:
        return False

# ---------- Teste do RSA com OAEP ----------

if __name__ == "__main__":
    print("Gerando chaves RSA...")
    Pu, Pr = rsa_keygen(1024)
    print("Chaves geradas com sucesso!")

    mensagem = "Mensagem secreta que tenha 'ç!@' car4ct3re$ 3sp3c!a!5 e tamanho indeterminado ->"
    mensagem = mensagem + ('*'*10000)
    print(f"Mensagem original: {mensagem}")

    # Assinatura e Verificação
    assinatura = rsa_sign(Pr, mensagem)
    print("Mensagem assinada com sucesso!")
    verificada = rsa_verify(Pu, mensagem, assinatura)
    print(f"Assinatura verificada: {verificada}")