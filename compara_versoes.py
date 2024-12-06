import subprocess
import time
import sys

def medir_tempo_criptografia():
    if len(sys.argv) < 2:
        print("Uso: python script.py <arquivo>")
        return

    arquivo = sys.argv[1]
    
    command1 = [
        "python3", "./ver-final/AES.py", "-e", arquivo, "-c", "128"
    ]
    command2 = [
        "python3", "./Python-AES/AES.py", "-e", arquivo, "-c", "128"
    ]

    print("Executando o comando 1...")
    inicio1 = time.time()
    try:
        subprocess.run(command1, check=True)
    except subprocess.CalledProcessError as e:
        print("Erro ao executar o comando 1:", e)
        return
    fim1 = time.time()
    tempo_total1 = fim1 - inicio1
    print(f"Tempo de execução do comando 1: {tempo_total1:.6f} segundos")

    print("Executando o comando 2...")
    inicio2 = time.time()
    try:
        subprocess.run(command2, check=True)
    except subprocess.CalledProcessError as e:
        print("Erro ao executar o comando 2:", e)
        return
    fim2 = time.time()
    tempo_total2 = fim2 - inicio2
    print(f"Tempo de execução do comando 2: {tempo_total2:.6f} segundos")

# Chama a função
medir_tempo_criptografia()
