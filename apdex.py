import csv
import os
import json
import click
import datetime
import psycopg2
from configparser import ConfigParser


def config(filename='apdex.ini', section='postgresql'):

    if os.path.isfile(filename):
        parser = ConfigParser()
        parser.read(filename)
        # get section, default to postgresql
        result = {}
        if parser.has_section(section):
            params = parser.items(section)
            for param in params:
                result[param[0]] = param[1]
        else:
            raise Exception('Section {0} not found in the {1} file'.format(section, filename))
        return result
    else:
        createIni(filename)
        raise Exception(f'File {filename} not found!\nSample file created.')


def calc_apdex(data):
    # Variaveis base
    matrix = {}
    ref = {}
    lst_apdex = []
    count_sumSatisfied = 0
    count_sumTolerating = 0
    count_sumUntolerating = 0

    # Pega as configurações da chave References
    references = config(section='References')

    # Laço que percorre todos os modulos configurados no arquivo apdex.ini
    for r in references['modules'].split(','):
        ref[r] = config(section=r)
        matrix[ref[r]['process']] = {'recordtime': ref[r]['recordtime'], 'toleratingtime': ref[r]['toleratingtime'], 'result': []}

    # Laço que percorre todas linhas do resultado do banco de dados
    for row in data:
        # =[@HoraFim]-[@HoraIni]
        tempo = str(datetime.datetime.strptime(row[5], '%H:%M:%S') - datetime.datetime.strptime(row[3], '%H:%M:%S'))
        # =HoraAbsIni-HoraAbsFim
        tempoTotal = row[6] - row[4]

        if row[2].strip() in matrix:
            # =SE(TempoTotal<PROCV(Process;TableTimes[#Dados];3;FALSO);1;0)
            satisfied = tempoTotal < float(matrix[row[2].strip()]['recordtime'])
            # =SE(TempoTotal<=PROCVProcess2;TableTimes[#Dados];6;FALSO);1;0)*(1-[@Satisfied])
            tolerating = False if satisfied else tempoTotal <= float(matrix[row[2].strip()]['toleratingtime'])
            # =SE(TempoTotal>PROCV(Process;TableTimes[#Dados];6;FALSO);1;0)
            untolerating = tempoTotal > float(matrix[row[2].strip()]['toleratingtime'])

            rrow = {'tempo': tempo, 'tempoTotal':tempoTotal, 'satisfied':satisfied, 'tolerating':tolerating, 'untolerating':untolerating}
            matrix[row[2].strip()]['result'].append(rrow)

    for r in references['modules'].split(','):
        ref[r] = config(section=r)
        matrix[ref[r]['process']]['rowTotal'] = len(matrix[ref[r]['process']]['result'])

        if len(matrix[ref[r]['process']]['result']) > 0:
            maxTempoTotal = 0
            minTempoTotal = 1000
            avgTempoTotal = []
            sumSatisfied = 0
            sumTolerating = 0
            sumUntolerating = 0

            for i in matrix[ref[r]['process']]['result']:
                maxTempoTotal = i['tempoTotal'] if i['tempoTotal'] > maxTempoTotal else maxTempoTotal
                minTempoTotal = i['tempoTotal'] if i['tempoTotal'] < minTempoTotal else minTempoTotal
                avgTempoTotal.append(i['tempoTotal'])
                sumSatisfied = sumSatisfied + 1 if i['satisfied'] else sumSatisfied
                sumTolerating = sumTolerating + 1 if i['tolerating'] else sumTolerating
                sumUntolerating = sumUntolerating + 1 if i['untolerating'] else sumUntolerating

            matrix[ref[r]['process']]['maxTempoTotal'] = maxTempoTotal
            matrix[ref[r]['process']]['minTempoTotal'] = minTempoTotal
            matrix[ref[r]['process']]['avgTempoTotal'] = sum(avgTempoTotal) / len(avgTempoTotal)
            matrix[ref[r]['process']]['sumSatisfied'] = sumSatisfied
            matrix[ref[r]['process']]['sumTolerating'] = sumTolerating
            matrix[ref[r]['process']]['sumUntolerating'] = sumUntolerating
            # =(("Soma de Satisfied") + ("Soma de Tolerating")/2) / 
            # (("Soma de Satisfied") + ("Soma de Tolerating") + ("Soma de Untolerating"))
            matrix[ref[r]['process']]['apdex'] = (sumSatisfied + sumTolerating / 2) / (sumSatisfied + sumTolerating + sumUntolerating)

            count_sumSatisfied = count_sumSatisfied + matrix[ref[r]['process']]['sumSatisfied']
            count_sumTolerating = count_sumTolerating + matrix[ref[r]['process']]['sumTolerating']
            count_sumUntolerating = count_sumUntolerating + matrix[ref[r]['process']]['sumUntolerating']

            lst_apdex.append(matrix[ref[r]['process']]['apdex'])

    # Realiza o calculo do APDEX
    matrix['apdex'] = (count_sumSatisfied + count_sumTolerating / 2) / (count_sumSatisfied + count_sumTolerating + count_sumUntolerating)

    return matrix


def run_calc(query=None, execution=''):
    """ Connect to the PostgreSQL database server """
    conn = None

    if query is None:
        query = 'SELECT version()'

    try:
        # Le parametros de conexao
        params = config()
        dbName = params['database']
        # Conecta no banco de dados PostgreSQL
        print(f'Connecting to {dbName} database...')
        conn = psycopg2.connect(**params)
        cur = conn.cursor()  
    	# Executa a query
        cur.execute(query)
        # Guarda o resultado da query
        res = cur.fetchall()

        # Grava o resulta no arquivo .csv com o nome do numero da execução informada
        with open(f'apdex_exec_{execution}.csv', 'w', newline='') as csvfile:
            spamwriter = csv.writer(csvfile, delimiter=',', quotechar=',', quoting=csv.QUOTE_MINIMAL)
            for r in res:
                spamwriter.writerow(r)
        # Fecha a conexão com o PostgreSQL
        cur.close()
        # Calcula APDEX
        x = calc_apdex(res)
        print('Resultado do Calculo:')
        print(f'EXECUÇÃO - {execution} \nAPDEX : {x["apdex"]}')

        saveData(x, execution)

    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
    finally:
        if conn is not None:
            conn.close()
            # print('Database connection closed.')


def saveData(data, execution='00000'):

    datehour = datetime.datetime.now()
    datehour = datehour.strftime('%Y%m%d_%H-%M-%S')
    valueApdex = data["apdex"]

    with open(f'{datehour}_apdex_exec_{execution}.json', 'a') as outfile:
        json.dump(data, outfile, indent = 4)

    with open("apdex.log", "a") as outfile:
        outfile.write(f'{datehour} {execution} {valueApdex}\n')


def createIni(filename):
    model = '''[postgresql]
host=localhost
database=database_name
user=postgres
password=passwd_db

[References]
Modules=ModuleA,ModuleB

[ModuleA]
Process=Nome do Modulo A
RecordTime=5
ToleratingTime=20

[ModuleB]
Process=Nome do Modulo B
RecordTime=5
ToleratingTime=20
'''
    with open(filename, "a") as apdexfile:
        apdexfile.write(model)


@click.group()
def apdex():
    pass


@apdex.command('get', short_help='Coleta os dados para gerar o apdex, \n\n--execution <Numero da Execução> \napedx get -e 000001', help="Executa o select para coletar os dados do teste de benchmark\n\n apedx get -e 000001", epilog='', deprecated=False)
@click.option('--execution','-e', multiple=True, help='Numero da execução')
def get(execution):
    if len(execution) > 0:
        for e in execution:
            query = 'SELECT EXECID, SLAVE, PROCNAME, STARTHOUR, STARTSEC, FINISHHOUR, FINISHSEC FROM \
                BMKHISTORY WHERE EXECID = \'' + e + '\' AND STARTDATE <> \'\' ORDER BY NTOTALTIME DESC'
            run_calc(query, execution=e)

apdex.add_command(get)

if __name__ == '__main__':
    apdex()
