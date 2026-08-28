<div align="center">
  <img src="./imagem/banner.gif" alt="BinSecScan Banner" width="100%">
</div>

# Detector de Segredos em Binários Compilados

Muitos desenvolvedores acham que remover hardcoded secrets do código-fonte resolve o problema, mas esquecem que eles podem permanecer nas strings do binário compilado.
Ferramentas como trufflehog focam em repositórios Git; poucas focam em artefatos de build de forma eficiente.
Chaves de API, tokens JWT ou senhas deixadas em strings constantes dentro de executáveis ELF/PE.

Então resolvi criar essa ferramenta em C que lê o cabeçalho de arquivos binários (ELF para Linux, PE para Windows), mapeia as seções de dados (`.rodata`, `.data`) e aplica heurísticas de entropia (Shannon Entropy) para detectar strings que parecem ser segredos criptográficos ou chaves.

Baixo uso de memória (streaming do arquivo, não carrega tudo na RAM).
Detecção baseada em entropia matemática, não apenas regex, reduzindo falsos positivos.
Integração direta como step em um Dockerfile ou GitHub Action.

**Stack:** C puro, manipulação de file descriptors, algoritmos de cálculo de entropia.
Scanners de container são pesados e lentos.
**BinSecScan** foi projetado para ser leve, rápido e integrado diretamente ao pipeline de build, validando o binário antes do deploy.
