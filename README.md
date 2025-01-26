# RSA
Código feito para disciplina de segunraça computacional. UnB 2024/2

Aqui é implementada a função de criptografia RSA com o objetivo de fazer uma verificação de assinatura digital.
 - As chaves geradas tem como base números primos de 1024 bits, com verificação de primalidade Miller-Rabin.
 - O padding utilizado é o OAEP.
 - É utilizado o hash SHA3 com 256 bits para verificação de originalidade da mensagem.
 - A mensagem é codificada em BASE64 para ser criptografada.
