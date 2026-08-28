# Makefile do BinSecScan


CC = gcc
CFLAGS = -Wall -Wextra -O2 -lm
TARGET = binsecscan

# Diz pro make procurar os fontes na pasta src/
VPATH = src

# Lista os arquivos fonte (sem o caminho)
SRCS = main.c entropy.c parser_elf.c parser_pe.c

# Gera os nomes dos objetos (vão ficar na raiz, mas podem ser movidos)
OBJS = $(SRCS:.c=.o)

# Alvo padrao
all: $(TARGET)

# Linkagem: junta os objetos
$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS)
	@echo "Compilacao concluida. Execute ./$(TARGET) -h para ajuda."

# Compilacao de cada .c -> .o
# Usa a regra implicita do make com VPATH
%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

# Limpeza
clean:
	rm -f $(OBJS) $(TARGET)
	@echo "Arquivos objetos e executavel removidos."

# Instala
install: $(TARGET)
	cp $(TARGET) /usr/local/bin/
	@echo "Binario instalado em /usr/local/bin/$(TARGET)"

# Desinstala
uninstall:
	rm -f /usr/local/bin/$(TARGET)
	@echo "Binario removido do sistema."

# Alvos que nao sao arquivos
.PHONY: all clean install uninstall