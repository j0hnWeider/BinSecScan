# Makefile do BinSecScan
# 
# Minha ideia aqui é ter um jeito simples de compilar o projeto,
# com opcoes pra limpar os objetos e instalar o binario no sistema.
# Preferi usar o gcc pq é o compilador mais comum em ambientes Linux,
# mas futuramente posso adicionar suporte a clang tambem.

CC = gcc
CFLAGS = -Wall -Wextra -O2 -lm
TARGET = binsecscan
SRCS = main.c entropy.c parser_elf.c parser_pe.c
OBJS = $(SRCS:.c=.o)

# Alvo padrao: compila tudo
all: $(TARGET)

# Linkagem: junta os objetos num executavel unico
$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS)
	@echo "Compilacao concluida. Execute ./$(TARGET) -h para ajuda."

# Compilacao de cada .c pra .o
%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS)

# Limpa os arquivos gerados
clean:
	rm -f $(OBJS) $(TARGET)
	@echo "Arquivos objetos e executavel removidos."

# Instala o binario no sistema (precisa de sudo)
install: $(TARGET)
	cp $(TARGET) /usr/local/bin/
	@echo "Binario instalado em /usr/local/bin/$(TARGET)"

# Desinstala
uninstall:
	rm -f /usr/local/bin/$(TARGET)
	@echo "Binario removido do sistema."

# Alvos que nao sao arquivos
.PHONY: all clean install uninstall