
from random import randint # número aleatório
from math import gcd # mdc
from hashlib import sha3_256 # hash especificado
from base64 import b64encode, b64decode # codificação especificada

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

# Obs.: Para quem não conhece a função pow, ela consegue fazer o cálculo mais utilizado
# neste trabalho, que é a^b mod(n). Seus parâmetros são pow(a, b, n).
# -->> Não usa lib prof :D <<--

def Miller_Rabin(n, k=1000):
    """
    Teste de primalidade de Miller-Rabin.
    """
    # Se for par não é primo
    if n % 2 == 0:
        return False
    
    # Calcula parâmetros necessário para o teste
    r = 0
    s = n-1
    while s % 2 == 0:
        r += 1
        s //= 2

    # Testa k vezes
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

def RSA_keygen(bits):
    """
    Geração de chaves RSA com primitivas criptográficas de "bits" bits.
    """
    # Menor 'e' com mdc = 1
    def find_e(phi):
        for e in range(2, phi):
            # gcd é uma função que calcula o mdc
            if gcd(e, phi) == 1:
                return e
            
    # Múmero de bits para gerar p e q (mínimo)
    nbm = 2 ** (bits - 1)
    # (máximo)
    nb = 2 ** bits
    # Gera números primos p e q aleatoriamente
    p = randint(nbm, nb)
    while not Miller_Rabin(p):
        p = randint(nbm, nb)
    q = randint(nbm, nb)
    while not Miller_Rabin(q):
        q = randint(nbm, nb)
    # Calcula n e phi pela definição
    n = p * q
    phi = (p - 1) * (q - 1)
    # Escolhe o menor 'e' com mdc(e, phi) = 1
    e = find_e(phi)
    # Pega o 'd' de acordo com o 'e' escolhido
    d = pow(e, -1, phi)
    return (e, n), (d, n)

def MGF(seed, mask_len):
    """
    Gera a máscara de acordo com o seed e o tamanho desejado.
    """
    # Pega o tamanho padrão do hash
    h_len = sha3_256().digest_size
    # Gera a máscara binaria
    mask = b""
    for i in range((mask_len + h_len - 1) // h_len):
        C = i.to_bytes(4, byteorder='big')
        mask += sha3_256(seed + C).digest()
    return mask[:mask_len]

def OAEP_encode(message, k, label=b""):
    """
    Padding OAEP.
    """
    h_len = sha3_256().digest_size
    l_hash = sha3_256(label).digest()
    # Padding string
    ps = b"\x00" * (k - len(message) - 2 * h_len - 2)
    # Data block
    db = l_hash + ps + b"\x01" + message
    # Semente aleatória
    seed = randint(0, 2 ** (8 * h_len) - 1).to_bytes(h_len, byteorder='big')
    # Máscara para o data block
    db_mask = MGF(seed, k - h_len - 1)
    masked_db = bytes(x ^ y for x, y in zip(db, db_mask))
    # Máscara da semente
    seed_mask = MGF(masked_db, h_len)
    masked_seed = bytes(x ^ y for x, y in zip(seed, seed_mask))
    # Devolve a concatenação de acordo com OAEP
    return b"\x00" + masked_seed + masked_db

def OAEP_decode(encoded, k, label=b""):
    """
    Decodificação OAEP.
    Processo inverso do padding.
    """
    h_len = sha3_256().digest_size
    l_hash = sha3_256(label).digest()
    masked_seed = encoded[1:h_len + 1]
    masked_db = encoded[h_len + 1:]
    seed_mask = MGF(masked_db, h_len)
    seed = bytes(x ^ y for x, y in zip(masked_seed, seed_mask))
    db_mask = MGF(seed, k - h_len - 1)
    db = bytes(x ^ y for x, y in zip(masked_db, db_mask))
    # Verifica se o hash está correto
    l_hash_prime = db[:h_len]
    if l_hash_prime != l_hash:
        print("Hash incorreto!!!")
        return "Mensagem foi alterada."
    # Separa a msg do padding
    ps_index = db.index(b'\x01', h_len) + 1
    message = db[ps_index:]
    return message.decode()

def RSA_encrypt(Pu, message):
    """
    Pega a mensagem, passa para BASE64, usa OAEP e criptografa com RSA.
    """
    e, n = Pu
    k = n.bit_length() // 8
    message = b64encode(message.encode())
    # Codifica a mensagem com OAEP com k bytes de tamanho de bloco.
    encoded = OAEP_encode(message, k)
    m = int.from_bytes(encoded, byteorder='big')
    return pow(m, e, n)

def RSA_decrypt(Pr, cipher):
    """
    Decodifica a mensagem criptografada com RSA.
    Processo inverso da criptografia vista na outra função.
    """
    d, n = Pr
    k = n.bit_length() // 8
    m = pow(cipher, d, n)
    encoded = m.to_bytes(k, byteorder='big')
    message = OAEP_decode(encoded, k)
    # Verifica se o padding foi feito corretamente,
    # ele retorna False se o hash estiver errado.
    if message is False:
        return False
    # Converte a mensagem de volta para string
    return b64decode(message).decode()

if __name__ == "__main__":
    from time import time

    it = time()
    print("Gerando chaves RSA...")
    Pu, Pr = RSA_keygen(1024)
    print("chaves geradas com sucesso!")
    print(f"Tempo de execução: {time() - it:.1f}s")

    message = "Mensagem secreta"
    print(f"Mensagem original: {message}")
    print("Criptografando mensagem...")
    cipher = RSA_encrypt(Pu, message)
    print(f"Mensagem criptografada com sucesso")
    print("Descriptografando mensagem...")
    message = RSA_decrypt(Pr, cipher)
    print(f"Mensagem descriptografada: {message}")
