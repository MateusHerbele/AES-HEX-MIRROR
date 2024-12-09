# criptografia-T1
Criptografia T1

# Calcular o tempo total para cifrar e decifrar arquivos de tamanhos diversos:
    Executar programa com opção [-ce] para criptografar e [-cd] para descriptografar.
    Para criptografar:
    python3 AES.py -ce <texto> -c 128
    Para descriptografar:
    python3 AES.py -cd <texto> -c 128


# Calcular o custo para cifrar e decifrar de cada fase do algoritmo.
    Abaixo está a descrição do cálculo do custo para cifrar e decifrar de cada fase do algoritmo:

    1. Custo AddRoundKey:
        A operação XOR tem um custo O(1) por byte (constante).
        Para um bloco de dados de 16 bytes (pois usa um bloco de 128 bits), a complexidade de AddRoundKey é O(16).
    2. Custo HexMirror:
        A operação tem um custo O(1) por byte (constante).
        Para um bloco de 16 bytes, o custo seria O(16).
    3. Custo ShiftRows:
        O custo do ShiftRows é O(1) por linha, já que ele desloca os bytes de forma cíclica.
        Para 4 linhas de 4 bytes (no AES), o custo de ShiftRows é O(4), pois cada byte de cada linha é movido para uma nova posição.
    4. Custo MixColumns:
        O custo de MixColumns pode ser estimado como O(16), já que envolve multiplicações e somas para cada coluna (4 operações por coluna para cada um dos 4 bytes).
        Como são 4 colunas, o custo total seria O(16).
    5. Custo da fase de rodada:
        Para cada rodada (exceto a última):

        HexMirror: O(16) (operando sobre os 16 bytes)
        ShiftRows: O(4) (4 linhas)
        MixColumns: O(16) (operando sobre as 4 colunas de 4 bytes)
        AddRoundKey: O(16) (XOR entre a chave e o estado)
        Total: O(16) (hexMirror) + O(4) (ShiftRows) + O(16) (MixColumns) + O(16) (AddRoundKey) = O(52).

        * Na última rodada, não há MixColumns, então o custo seria O(16) (hexMirror) + O(4) (ShiftRows) + O(16) (AddRoundKey) = O(36).

# Comparação de tempo entre nossa versão do AES com a versão recomendada pelo OpenSSL:
    O algoritmo compara o tempo de execução no modo de 128
    Executar:
	source venv/bin/activate
        python3 compara_versoes.py <texto>
