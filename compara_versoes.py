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
    arquivo_criptografado1 = sys.argv[1] + ".aes"
    arquivo_criptografado2 = "texto_criptografado_original.aes"
    arquivo_descriptografado2 = "texto_descriptografado_original.txt"
    
    command1 = [
        "python3", "./ver-final/AES.py", "-ce", arquivo, "-c", "128"
    ]
    command2 = [
        "python3", "./ver-final/AES.py", "-cd", arquivo_criptografado1, "-c", "128"
    ]

    print("\n------------------------------CRIPTOGRAFIA------------------------------------------")
    print("(HexMirror) Executando a criptografia...")
    try:
        subprocess.run(command1, check=True)
    except subprocess.CalledProcessError as e:
        print("Erro ao executar o comando 1:", e)
        return

    print("\n(Original) Executando a criptografia...")
    chave = input("Digite a chave de 16 bytes: ").encode()
    iv = os.urandom(16) 

    cipher = AES.new(chave, AES.MODE_CBC, iv) 

    with open(arquivo, 'rb') as arquivo_original:
        arquivo_conteudo = arquivo_original.read()

    inicio2 = time.time()
    token = cipher.encrypt(pad(arquivo_conteudo, AES.block_size))  
    fim2 = time.time()
    tempo_criptografia2 = fim2 - inicio2
    print(f"Tempo de execução: {tempo_criptografia2:.6f} segundos")

    with open(arquivo_criptografado2, 'wb') as arquivo2_criptografado:
        arquivo2_criptografado.write(iv + token)

    print("\n------------------------------DESCRIPTOGRAFIA------------------------------------------")

    print("(HexMirror) Executando a descriptografia ...")
    try:
        subprocess.run(command2, check=True)
    except subprocess.CalledProcessError as e:
        print("Erro ao executar o comando 2:", e)
        return

    print("\n(Original) Executando a descriptografia...")
    with open(arquivo_criptografado2, 'rb') as arquivo_criptografado:
        iv = arquivo_criptografado.read(16) 
        token_criptografado = arquivo_criptografado.read() 

    cipher_decrypt = AES.new(chave, AES.MODE_CBC, iv)  

    inicio4 = time.time()
    conteudo_original = unpad(cipher_decrypt.decrypt(token_criptografado), AES.block_size) 
    fim4 = time.time()
    tempo_descriptografia2 = fim4 - inicio4
    print(f"Tempo de execução: {tempo_descriptografia2:.6f} segundos")

    with open(arquivo_descriptografado2, 'wb') as arquivo_descriptografado:
        arquivo_descriptografado.write(conteudo_original)

medir_tempo_criptografia()
