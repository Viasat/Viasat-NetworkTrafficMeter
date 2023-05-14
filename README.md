# Viasat-WebTrafficMeter

Para que você possa construir a sua aplicação baseada no problema apresentado, criamos um back-end simples que pode te ajudar a alimentar seu aplicativo de forma efetiva.

## Requisitos
1. É necessário que você tenha [Python](https://www.python.org/downloads/) instalado e uma IDE para trabalhar.
2. É necessário que você tenha o [NodeJS](https://nodejs.org/en) instalado.
3. A instalação do [npcap](https://npcap.com/#download) também é necessária.

## Execução
1. Primeiramente, digite no terminal para clonar o repositório:

    ```
    git clone https://github.com/Viasat/Viasat-NetworkTrafficMeter.git
    ```
2. Entrar na pasta do projeto 
   ```
   cd Viasat-NetworkTrafficMeter
   ```
3. Altere seu projeto para a Branch correta
    ```
    git checkout broken-pipe-fix 
    ```
4. Após instalar o projeto, execute o seguinte comando para instalar as dependências do python:
    ```
    pip install -r requirements.txt
    ```
5. Instale também as dependências Javascript
   ```
   npm i
   ```
6. Inicie um dos arquivos traffic_analyzer:
    ```
    python.exe traffic_analyzer.py
    ```
7. Inicie o wrapper JavaScript equivalente:
   ```
   node node_wrapper.js 
   ```
   
OBS: Nessa verão do projeto você deve conectar ao socket JavaScript na porta 8000
    
## Copyright e Licença
Código e documentação copyright 2023 ViaSat, Inc. Código é lançado sob [licença Apache 2.0](https://github.com/Viasat/Viasat-NetworkTrafficMeter/blob/main/LICENSE).
