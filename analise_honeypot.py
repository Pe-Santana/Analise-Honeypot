
import os
import gzip
import pandas as pd #2.1.0
import re
import matplotlib.pyplot as plt #3.8.0
import matplotlib.ticker as mtick 
from matplotlib.colors import Normalize
from matplotlib.patches import Patch

    


# -------- Funções de processamento de logs --------
def processar_logs(path):
    """
    Processa arquivos .gz em um diretório:
    - Cria uma subpasta 'tratados' se não existir.
    - Descompacta cada .gz, salvando o conteúdo com o mesmo nome (sem .gz) na pasta 'tratados'.
    - Renomeia o arquivo descompactado removendo os pontos e adicionando a extensão .log.

    Args:
        path (str): Caminho para o diretório contendo os arquivos .gz.
    """
    tratados_path = os.path.join(path, 'tratados')
    os.makedirs(tratados_path, exist_ok=True)

    for filename in os.listdir(path):
        if filename.endswith('.gz'):
            gz_path = os.path.join(path, filename)
            nome_base = filename[:-3]
            descompactado_path = os.path.join(tratados_path, nome_base)

            with gzip.open(gz_path, 'rb') as f_in:
                with open(descompactado_path, 'wb') as f_out:
                    f_out.write(f_in.read())

            novo_nome = filename.replace('.', '') + '.log'
            novo_path = os.path.join(tratados_path, novo_nome)
            os.rename(descompactado_path, novo_path)

def transforma_log(line):
    """
    Transforma uma linha de log no formato do Apache em uma entrada.
    """
    log = (
        r'(?P<ip>[\d\.]+) - - '
        r'\[(?P<data>[^\]]+)\] '
        r'"(?P<metodo>[A-Z]+) (?P<url>[^\s]+) [^"]+" '
        r'(?P<status>\d{3}) (?P<tamanho>\d+|-) '
        r'"[^"]*" '
        r'"(?P<user_agent>[^"]+)"'
    )
    match = re.match(log, line)
    if match:
        return match.groupdict()
    return None

def arquivo2df(arquivo):
    with open(arquivo, 'r') as file:
        lines = file.readlines()
    logs_analizados = [transforma_log(line) for line in lines if transforma_log(line) is not None]
    return pd.DataFrame(logs_analizados)

def trata_arq(path):
    """
    Percorre o path, procurando subpastas que contenham arquivos .gz,
    e chama a função processar_logs para tratar os arquivos.
    """
    for pasta in os.listdir(path):
        pasta_path = os.path.join(path, pasta)
        for subpasta in os.listdir(pasta_path):
            try:
                processar_logs(os.path.join(pasta_path, subpasta))
            except:
                continue
def cria_df(path):
    """
    Percorre o diretório base e suas subpastas, procurando arquivos .log dentro de pastas 'tratados'.
    Concatena todos os arquivos em um único DataFrame, adicionando a coluna 'source' com o nome da pasta pai.
    """
    dfs = []

    for pasta in os.listdir(path):
        pasta_path = os.path.join(path, pasta)
        if not os.path.isdir(pasta_path):
            continue

        for subpasta in os.listdir(pasta_path):
            tratados_path = os.path.join(pasta_path, subpasta, 'tratados')
            if not os.path.exists(tratados_path):
                continue

            for filename in os.listdir(tratados_path):
                if filename.endswith('.log'):
                    arquivo_path = os.path.join(tratados_path, filename)
                    df_temp = arquivo2df(arquivo_path)
                    df_temp['source'] = pasta
                    dfs.append(df_temp)

    df_final = pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()

    if 'data' in df_final.columns:
        df_final['data'] = pd.to_datetime(df_final['data'], format='%d/%b/%Y:%H:%M:%S %z', errors='coerce')

    return df_final

# -------- Funções de visualização --------
def acesso_dia(df):
    """
    Exibe gráfico de barras com a frequência de acessos por dia.
    """
    plt.figure(figsize=(25, 5))
    df_temp = df.groupby(df['data'].dt.strftime('%d/%m')).size()
    df_temp.index = pd.to_datetime(df_temp.index, format='%d/%m')
    df_temp = df_temp.sort_index()
    df_temp.index = df_temp.index.strftime('%d/%m')
    colors = plt.cm.RdYlGn((df_temp - df_temp.min()) / (df_temp.max() - df_temp.min()))
    df_temp.plot(kind='bar', title='Acessos por dia', color=colors)
    plt.xticks(rotation=45)
    plt.show()

def ip_dia(df, ip):
    """
    Exibe gráfico de linha com os acessos diários de um IP específico, separados por honeypot.
    """
    df_temp = df[df['ip'] == ip]
    all_days = pd.date_range(start=df['data'].min(), end=df['data'].max(), freq='D')
    honeypot_colors = ['royalblue', 'green', 'orange', 'red', 'purple', 'cyan', 'magenta',
                       'yellow', 'brown', 'pink', 'gray', 'lime']

    plt.figure(figsize=(25, 5))
    for i, hp in enumerate(df_temp['source'].unique()):
        df_hp = df_temp[df_temp['source'] == hp]
        df_hp = df_hp.groupby(df_hp['data'].dt.date).size().reindex(all_days.date, fill_value=0)
        plt.plot(all_days, df_hp, marker='o', label=hp.split('honeycam-')[-1],
                 color=honeypot_colors[i % len(honeypot_colors)])

    plt.xlabel('Data')
    plt.ylabel('Número de Acessos')
    plt.title(f'Acessos por dia para o IP {ip}')
    plt.xticks(all_days, [d.strftime('%d/%m') for d in all_days], rotation=45)
    plt.gca().yaxis.set_major_locator(mtick.MaxNLocator(integer=True))
    plt.legend(title="Honeypot", bbox_to_anchor=(1.05, 1), loc='upper left')
    for line in plt.gca().get_lines():
        line.set_alpha(0.5)
    plt.grid(True)
    plt.show()

def acesso_fonte(df):
    """
    Exibe gráfico de pizza com a distribuição de entradas por fonte (honeypot).
    """
    counts = df['source'].value_counts()
    plt.figure(figsize=(20, 15))
    fig, ax = plt.subplots()
    wedges, texts, autotexts = ax.pie(counts, autopct='%1.1f%%', textprops={'fontsize': 10})
    ax.legend(wedges, counts.index, title="Sources", loc="center left", bbox_to_anchor=(1, 0.5))
    plt.title('Ataques por Honeypot')
    plt.show()

def top_ips(df):
    """
    Exibe gráfico de barras com os 5 IPs que mais acessaram os honeypots.
    """
    plt.figure(figsize=(10, 5))
    df['ip'].value_counts().head(5).plot(kind='bar', title='Top 5 IPs com mais acessos', color='orange')
    plt.xlabel('IP')
    plt.ylabel('Quantidade de Acessos')
    plt.xticks(rotation=0)
    for p in plt.gca().patches:
        plt.gca().annotate(f'{int(p.get_height())}',
                           (p.get_x() + p.get_width() / 2, p.get_height() / 2),
                           ha='center', va='center', fontsize=10, fontweight='bold', color='black')
    plt.grid(axis='y', linestyle='--', alpha=0.2)
    plt.show()


#--------------testes funcoes de visualizacao----------------



def acesso_dia2(df1, df2=None):
    def agrupar_por_dia(df):
        dados = df.groupby(df['data'].dt.normalize()).size()  # Mantém datetime completo (sem hora)
        dados = dados.sort_index()
        return dados

    df1_temp = agrupar_por_dia(df1)
    num_dias = len(df1_temp)
    largura_grafico = max(10, num_dias * 0.5)

    if df2 is None:
        cores = plt.cm.RdYlGn((df1_temp - df1_temp.min()) / (df1_temp.max() - df1_temp.min()))
        labels = [data.strftime('%d/%m') for data in df1_temp.index]

        df1_temp.plot(kind='bar', title='Acessos por dia', color=cores, figsize=(largura_grafico, 5))
        plt.xticks(ticks=range(len(labels)), labels=labels, rotation=45)

    else:
        df2_temp = agrupar_por_dia(df2)
        num_dias = num_dias + len(df2_temp)
        largura_grafico = max(10, num_dias * 0.5)
        
        # Garantir união dos índices e reordenação correta
        todos_indices = sorted(set(df1_temp.index).union(df2_temp.index))
        df1_temp = df1_temp.reindex(todos_indices, fill_value=0)
        df2_temp = df2_temp.reindex(todos_indices, fill_value=0)

        norm = Normalize(vmin=min(df1_temp.min(), df2_temp.min()), vmax=max(df1_temp.max(), df2_temp.max()))
        cores_df1 = plt.cm.RdYlGn(norm(df1_temp.values))
        cores_df2 = plt.cm.RdYlGn(norm(df2_temp.values))

        fig, ax = plt.subplots(figsize=(largura_grafico, 5))
        x = range(len(todos_indices))

        for i, (valor, cor) in enumerate(zip(df1_temp.values, cores_df1)):
            ax.bar(x[i] - 0.2, valor, width=0.4, color=cor)

        for i, (valor, cor) in enumerate(zip(df2_temp.values, cores_df2)):
            ax.bar(x[i] + 0.2, valor, width=0.4, color=cor, hatch='//', edgecolor='black')

        # Formatando datas pro eixo X
        labels_formatados = [data.strftime('%d/%m/%y') for data in todos_indices]
        ax.set_xticks(x)
        ax.set_xticklabels(labels_formatados, rotation=45)

        ax.grid(True, linestyle='--', linewidth=0.5, color='gray', alpha=0.1)
        ax.set_xlabel("Data")
        ax.set_ylabel("Acessos")
        ax.set_title("Comparação de Acessos por Dia")
        ax.grid(True)

        legenda = [
            Patch(facecolor='blue', label='Dataset 1'),
            Patch(facecolor='red', hatch='//', edgecolor='black', label='Dataset 2')
        ]
        ax.legend(handles=legenda)

        plt.tight_layout()
        plt.show()

def acesso_fonte2(df1, df2=None):
    """
    Exibe gráfico de pizza com a distribuição de entradas por fonte (honeypot).
    Se dois DataFrames forem fornecidos, exibe dois gráficos lado a lado.
    """
    fig, axs = plt.subplots(1, 2 if df2 is not None else 1, figsize=(15, 7))

    def plot_pizza(ax, df, title):
        counts = df['source'].value_counts()
        wedges, texts, autotexts = ax.pie(counts, autopct='%1.1f%%', textprops={'fontsize': 10})
        ax.set_title(title)
        ax.legend(wedges, counts.index, loc="center left", bbox_to_anchor=(1, 0.5))

    if df2 is None:
        plot_pizza(axs if isinstance(axs, plt.Axes) else axs[0], df1, 'Distribuição por Honeypot')
    else:
        plot_pizza(axs[0], df1, 'DF1: Distribuição por Honeypot')
        plot_pizza(axs[1], df2, 'DF2: Distribuição por Honeypot')

    plt.tight_layout()
    plt.show()


def top_ips2(df1, df2=None):
    """
    Exibe gráfico de barras com os IPs mais ativos presentes em ambos os DataFrames (se dois forem fornecidos).
    Se apenas um for fornecido, mostra os 5 IPs com mais acessos.
    """
    if df2 is None:
        top = df1['ip'].value_counts().head(5)
        ax = top.plot(kind='bar', color='orange', figsize=(10, 5), title='Top 5 IPs com mais acessos')
        for p in ax.patches:
            ax.annotate(f'{int(p.get_height())}',
                        (p.get_x() + p.get_width() / 2, p.get_height() / 2),
                        ha='center', va='center', fontsize=10, fontweight='bold')
    else:
        # Contagem por IP
        contagem1 = df1['ip'].value_counts()
        contagem2 = df2['ip'].value_counts()

        # Interseção dos IPs
        ips_em_comum = contagem1.index.intersection(contagem2.index)

        # Seleciona os top IPs em comum com base no total combinado
        top_ips_comuns = (contagem1[ips_em_comum] + contagem2[ips_em_comum]).sort_values(ascending=False).head(5).index

        df_comparacao = pd.DataFrame({
            'DF1': contagem1[top_ips_comuns],
            'DF2': contagem2[top_ips_comuns]
        })

        ax = df_comparacao.plot(kind='bar', figsize=(10, 5), title='Top IPs em Comum - Comparação DF1 x DF2', color=['royalblue', 'darkorange'])
        for p in ax.patches:
            height = p.get_height()
            ax.annotate(f'{int(height)}', 
                        (p.get_x() + p.get_width() / 2, height + 0.5),
                        ha='center', va='bottom', fontsize=8)

    plt.xlabel('IP')
    plt.ylabel('Acessos')
    plt.xticks(rotation=0)
    plt.grid(axis='y', linestyle='--', alpha=0.2)
    plt.show()


def ip_dia2( ip,df1, df2=None):
    """
    Exibe gráfico de linha com os acessos diários de um IP específico.
    Se dois DataFrames forem fornecidos, compara os acessos entre eles.
    """
    def plot_por_df(df, label_prefix, linestyle):
        df_temp = df[df['ip'] == ip]
        all_days = pd.date_range(start=df['data'].min(), end=df['data'].max(), freq='D')
        for i, hp in enumerate(df_temp['source'].unique()):
            df_hp = df_temp[df_temp['source'] == hp]
            df_hp = df_hp.groupby(df_hp['data'].dt.date).size().reindex(all_days.date, fill_value=0)
            plt.plot(all_days, df_hp, marker='o', linestyle=linestyle,
                     label=f'{label_prefix}-{hp.split("honeycam-")[-1]}', alpha=0.6)

    plt.figure(figsize=(25, 5))
    plot_por_df(df1, "DF1", "-")

    if df2 is not None:
        plot_por_df(df2, "DF2", "--")

    plt.xlabel('Data')
    plt.ylabel('Número de Acessos')
    plt.title(f'Acessos por dia para o IP {ip}')
    plt.xticks(rotation=45)
    plt.gca().yaxis.set_major_locator(mtick.MaxNLocator(integer=True))
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.grid(True)
    plt.show()
