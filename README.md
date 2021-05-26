# apdex

## O que é APDEX?

O Apdex é um padrão aberto para medir o desempenho de aplicativos de software em computação. Sua finalidade é converter medições em insights sobre a satisfação do usuário, especificando uma maneira uniforme para analisar e relatório sobre o grau em que o desempenho medido atende as expectativas do usuário. [mais](https://en.wikipedia.org/wiki/Apdex)

## Executar

Windows
```apdex get -e 00001```

Linux e Mac
```$ pip3 install -r requirements.txt```
```$ python3 apdex.py get -e 00001```

### Arquivos de Log e Configuração

**apdex.log** - Grava o resumo de cada consulta, com os dados **data e hora**, **id**, **apdex**
**YYYYmmdd_h-m-s_apdex_exec_id.json** - Arquivo com o resumo do calculo do apdex e todos os dados coletados
**apdex_exec_id.csv** - Arquivo com o resultado da consulta no banco de dados

#### Configuração

**apdex.ini** - Arquivo de configuração

##### Chaves

[Sessão do SGBD]
**host** - Endereço do SGBD
**database** - Nome do banco de dados
**user** - Nome do usuário do banco de dados
**password** - Senha do usuário do banco de dados

[Sessão References]
**Modules** - Lista de todas as sessões de modulos

[Sessão Module]
**Process** - Nome do Processo analisado (mesmo nome da coluna _PROCNAME_)
**RecordTime** - Tempo de resposta satisfatório (quando o tempo de responta for inferior a este parametro será considerado como um tempo perfeito)
**ToleratingTime** - Tempo de resposta tolerado (quando o tempo de resposta for igual ou inferior será um tempo esperado ou tolerado, tempo de resposta superior ao **ToleratingTime** será um tempo _NÃO_ tolerado)

```ini
;exemplo do apdex.ini
[postgresql|mssql|oracle]
host=localhost
database=nome_da_base
user=postgres
password=senha_do_usuario

[References]
Modules=Modulo1,Modulo2

[Modulo1]
Process=Nome do Modulo 1
RecordTime=5
ToleratingTime=20

[Modulo2]
Process=Nome do Modulo 2
RecordTime=5
ToleratingTime=20
```

## SGBD suportados

|SGBD           | Suportado |
|---------------|-----------|
| PostgreSQL    |     ✔️     |
| MSSQL Server  |     ✔️     |
| Oracle        |     ✔️     |

✔️ - Suportado
✖️ - Em desenvolvimento

### PostgreSQL MSSQL ORACLE

❗️ Instrução de consulta ao banco de dados

```sql
SELECT EXECID
, PROCNAME
, STARTHOUR
, STARTSEC
, FINISHHOUR
, FINISHSEC
FROM BMKHISTORY
WHERE EXECID = '<id_execução>'
    AND STARTDATE <> ''
ORDER BY NTOTALTIME DESC

```

❗️ A estrutura da tabela que será consultada o resultado

```sql
CREATE TABLE public.bmkhistory (
    execid bpchar(6) NOT NULL DEFAULT '      '::bpchar,
    procname bpchar(50) NOT NULL DEFAULT '                                                  '::bpchar,
    startdate bpchar(8) NOT NULL DEFAULT '        '::bpchar,
    starthour bpchar(8) NOT NULL DEFAULT '        '::bpchar,
    startsec float8 NOT NULL DEFAULT 0.0,
    finishdate bpchar(8) NOT NULL DEFAULT '        '::bpchar,
    finishhour bpchar(8) NOT NULL DEFAULT '        '::bpchar,
    finishsec float8 NOT NULL DEFAULT 0.0,
    ntotaltime float8 NOT NULL DEFAULT 0.0,
    CONSTRAINT bmkhistory_pk PRIMARY KEY (execid)
);
```
