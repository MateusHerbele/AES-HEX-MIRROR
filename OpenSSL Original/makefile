# Nome do executável
TARGET = teste

# Compilador e flags
CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lssl -lcrypto

# Arquivos fonte e objetos
SRC = main.c aux.c
OBJ = $(SRC:.c=.o)

# Regra padrão
all: $(TARGET)

# Regra para criar o executável
$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJ) $(LDFLAGS)

# Regra para criar arquivos objeto
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Limpa arquivos objeto
clean:
	rm -f $(OBJ)

# Limpa arquivos objeto e o executável
purge: clean
	rm -f $(TARGET)

# Declaração de phony targets
.PHONY: all clean purge
