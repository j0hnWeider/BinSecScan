# Makefile do BinSecScan
#
# Minha ideia aqui é compilar os fontes que estão dentro da pasta src/
# e gerar o binario na raiz. Usei o VPATH pra dizer pro make onde
# procurar os .c e .h. Assim fica mais organizado.
# 
# Separei as flags de compilacao (CFLAGS) das de linkagem (LDFLAGS)
# pra evitar warnings como '-lm: linker input unused' no macOS.
# No Windows, o gcc do MinGW funciona bem com essas flags.

CC = gcc
CFLAGS = -Wall -Wextra -O2 -D_GNU_SOURCE
LDFLAGS = -lm
TARGET = binsecscan

# Diz pro make procurar os fontes na pasta src/
VPATH = src

# Lista os arquivos fonte (sem o caminho)
SRCS = main.c entropy.c parser_elf.c parser_pe.c

# Gera os nomes dos objetos (vão ficar na raiz)
OBJS = $(SRCS:.c=.o)

# Alvo padrao
all: $(TARGET)

# Linkagem: junta os objetos com as libs
$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)
	@echo "Compilacao concluida. Execute ./$(TARGET) -h para ajuda."

# Compilacao de cada .c -> .o
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

.PHONY: all clean install uninstall