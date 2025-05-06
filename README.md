# Ferramenta para análise de Honeypots 

O objetivo desta ferramenta é oferecer uma forma simples de explorar os dados coletados por honeypots hospedados em servidores Apache, apresentando-os em gráficos diretamente em notebooks Python.


![image](https://github.com/user-attachments/assets/fdc25902-6a35-4672-bb23-a9236f2ecbf8)

De modo geral as funções de visualização seguem a seguinte estrutura:

**Descrição geral**

Funções responsáveis por gerar gráficos com base nos dados coletados e organizados em dataframes. O fluxo básico refere-se à execução com apenas um dataframe; já o fluxo alternativo utiliza dois conjuntos de dados distintos.

• Fluxo básico de execução
  1. O usuário indica o dataframe como parâmetro;
  2. A função filtra os dados de acordo com sua descrição (por exemplo: acesso_dia,
  acesso_fonte, top_ips, hp_dia e ip_dia);
  3. Os dados são agrupados, classificados e organizados para visualização;
  4. O gráfico é gerado e exibido ao usuário.

• Fluxo alternativo de execução
  1. O usuário indica dois dataframes como parâmetro;
  2. A função filtra e ajusta os dados com base na necessidade dos conjuntos (por
  exemplo: identificação de IPs em comum);
  3. Os dados de ambas as fontes são agrupados, classificados e organizados para
  visualização conjunta;
  4. Os gráficos são gerados de forma concorrente ou sobrepostos, e exibidos ao
  usuário.

A seguir, são apresentados os diagramas de atividade que descrevem o processo de tratamento dos arquivos e sua conversão em DataFrame.

![fluxogramas_back](https://github.com/user-attachments/assets/bce3964e-3091-4913-b3a7-23ae723157a0)
