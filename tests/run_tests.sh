#!/bin/bash
# Script pra rodar os testes do BinSecScan
#
# Meu objetivo aqui é ter um jeito simples de executar os testes
# sem precisar lembrar dos comandos do Criterion.
# Futuramente posso adicionar mais testes alem do modulo de entropia.

set -e

echo "========================================="
echo "  BinSecScan - Test Suite"
echo "========================================="

# Verifica se o Criterion ta instalado
if ! pkg-config --exists criterion; then
    echo "Erro: Criterion nao encontrado."
    echo "Instale com: sudo apt-get install libcriterion-dev (Ubuntu/Debian)"
    echo "Ou: brew install criterion (macOS)"
    exit 1
fi

# Compila os testes
echo "Compilando testes..."
gcc -o tests/test_entropy tests/test_entropy.c entropy.c -lcriterion -lm

# Roda os testes
echo ""
echo "Executando testes..."
./tests/test_entropy

# Limpeza opcional
rm -f tests/test_entropy

echo ""
echo "========================================="
echo "  Todos os testes passaram! \\o/"
echo "========================================="