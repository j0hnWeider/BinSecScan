#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "parser_elf.h"
#include "parser_pe.h"

#define DEFAULT_THRESHOLD 4.5 // Entropia máxima teórica é 8.0. 4.5+ indica alta aleatoriedade.

void print_usage(const char *prog) {
    fprintf(stderr, "Uso: %s [-t threshold] <arquivo_binario>\n", prog);
    fprintf(stderr, "  -t: Limiar de entropia (padrão: %.1f)\n", DEFAULT_THRESHOLD);
}

int main(int argc, char *argv[]) {
    double threshold = DEFAULT_THRESHOLD;
    char *filename = NULL;

    // Parse simples de argumentos
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            threshold = atof(argv[++i]);
        } else if (filename == NULL) {
            filename = argv[i];
        } else {
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!filename) {
        print_usage(argv[0]);
        return 1;
    }

    printf("BinSecScan: Analisando %s (Threshold: %.2f)\n", filename, threshold);

    // Detecta tipo de arquivo pelo magic number inicial
    FILE *f = fopen(filename, "rb");
    if (!f) {
        perror("Não foi possível abrir o arquivo");
        return 1;
    }

    unsigned char magic[4];
    if (fread(magic, 1, 4, f) != 4) {
        fclose(f);
        fprintf(stderr, "Arquivo muito pequeno ou vazio.\n");
        return 1;
    }
    fclose(f);

    int result = -1;
    
    // ELF Magic: 7f 45 4c 46
    if (magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F') {
        result = analyze_elf(filename, threshold);
    } 
    // PE Magic: 4d 5a ("MZ")
    else if (magic[0] == 'M' && magic[1] == 'Z') {
        result = analyze_pe(filename, threshold);
    } 
    else {
        fprintf(stderr, "Formato de arquivo não suportado. Suporta apenas ELF e PE.\n");
        return 1;
    }

    if (result == 0) {
        printf("Análise concluída.\n");
    } else {
        fprintf(stderr, "Erro durante a análise.\n");
        return 1;
    }

    return 0;
}
