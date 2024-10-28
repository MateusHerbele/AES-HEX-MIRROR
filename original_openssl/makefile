# Name of the executable
TARGET = teste-original

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lssl -lcrypto

# Source and object files
SRC = main.c aux.c
OBJ = $(SRC:.c=.o)

# Default rule
all: $(TARGET)

# Rule to create the executable
$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJ) $(LDFLAGS)

# Rule to create object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean object files
clean:
	rm -f $(OBJ)

# Clean object files and the executable
purge: clean
	rm -f $(TARGET)

# Declaration of phony targets
.PHONY: all clean purge
