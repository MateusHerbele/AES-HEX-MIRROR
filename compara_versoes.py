import subprocess
import time
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

def medir_tempo_criptografia():
    if len(sys.argv) < 2:
        print("Uso: python script.py <arquivo>")
        return

    arquivo = sys.argv[1]
    arquivo_criptografado1 = "texto1.txt.aes"
    arquivo_criptografado2 = "texto1_criptografado.aes"
    arquivo_descriptografado2 = "texto1_descriptografado.txt"
    
    command1 = [
        "python3", "./ver-final/AES.py", "-ce", arquivo, "-c", "128"
    ]
    command2 = [
        "python3", "./ver-final/AES.py", "-cd", arquivo_criptografado1, "-c", "128"
    ]

    print("\n------------------------------CRIPTOGRAFIA------------------------------------------")
    print("Executando a criptografia do primeiro algoritmo...")
    try:
        subprocess.run(command1, check=True)
    except subprocess.CalledProcessError as e:
        print("Erro ao executar o comando 1:", e)
        return

    print("\nExecutando a criptografia do segundo algoritmo...")
    chave = b"1234567891234567" 
    iv = os.urandom(16) 

    cipher = AES.new(chave, AES.MODE_CBC, iv) 

    with open(arquivo, 'rb') as arquivo_original:
        arquivo_conteudo = arquivo_original.read()

    inicio2 = time.time()
    token = cipher.encrypt(pad(arquivo_conteudo, AES.block_size))  
    fim2 = time.time()
    tempo_criptografia2 = fim2 - inicio2
    print(f"Tempo de execução da criptografia do segundo algoritmo: {tempo_criptografia2:.6f} segundos")

    with open(arquivo_criptografado2, 'wb') as arquivo2_criptografado:
        arquivo2_criptografado.write(iv + token)

    print("\n------------------------------DESCRIPTOGRAFIA------------------------------------------")

    print("Executando a descriptografia do primeiro algoritmo...")
    try:
        subprocess.run(command2, check=True)
    except subprocess.CalledProcessError as e:
        print("Erro ao executar o comando 2:", e)
        return

    print("\nExecutando a descriptografia do segundo algoritmo...")
    with open(arquivo_criptografado2, 'rb') as arquivo_criptografado:
        iv = arquivo_criptografado.read(16) 
        token_criptografado = arquivo_criptografado.read() 

    cipher_decrypt = AES.new(chave, AES.MODE_CBC, iv)  

    inicio4 = time.time()
    conteudo_original = unpad(cipher_decrypt.decrypt(token_criptografado), AES.block_size) 
    fim4 = time.time()
    tempo_descriptografia2 = fim4 - inicio4
    print(f"Tempo de execução da descriptografia do segundo algoritmo: {tempo_descriptografia2:.6f} segundos")

    with open(arquivo_descriptografado2, 'wb') as arquivo_descriptografado:
        arquivo_descriptografado.write(conteudo_original)

medir_tempo_criptografia()
