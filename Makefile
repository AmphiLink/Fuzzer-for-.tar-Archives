# Variables
CC = gcc
SRC_DIR = src
EXEC = fuzzer

# Liste des fichiers source
SRCS = $(SRC_DIR)/main.c $(SRC_DIR)/utils.c

# Cible par défaut
all: $(EXEC)

# Règle pour générer l'exécutable
$(EXEC): $(SRCS)
	$(CC) -o $@ $^

# Cible pour nettoyer l'exécutable
clean:
	rm -f $(EXEC)

# Cible pour forcer la recompilation
rebuild: clean all
