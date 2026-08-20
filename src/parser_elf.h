#ifndef PARSER_ELF_H
#define PARSER_ELF_H

#include <stdio.h>

// Analisa um arquivo ELF e extrai strings da seção .rodata ou similar
int analyze_elf(const char *filepath, double threshold);

#endif
