from flask import Flask, render_template, request
from flask import *
import requests
import pandas as pd
import os
from pandas import ExcelWriter
import concurrent.futures
from app.src import ThreadPool
from app.src import misp
import time


app = Flask(__name__)
app.config['MAX_CONTENT_LENGHT'] = 16*1000*1000*1000


@app.route('/load', methods=['POST'])
def load():
    def gen(df, filename):
        try:

            file = open("data/resultat_hash.txt", "w")
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:

                try:
                    results = {executor.submit(
                        ThreadPool.add, a, filename, file) for a in df.values}
                    yield "{\"total\": %d}\n" % (len(df.values))
                    time.sleep(1)
                    aux = []
                    for result in concurrent.futures.as_completed(results):
                        aux.append(result.result())
                        yield "{\"progress\": %d}\n" % (len(aux))
                    llista_type = [a[0] for a in aux]
                    llista_comprovacio = [a[1] for a in aux]
                    llista_value = [a[2] for a in aux]
                    llista_bool = [a[3] for a in aux]
                    llista_campanya = [a[4] for a in aux]
                except:
                    pass

            pagina = pd.DataFrame({'type': llista_type,
                                   'value': llista_value,
                                   'Added': llista_bool,
                                   'Description': llista_comprovacio,
                                   'Campaign': llista_campanya
                                   })

            # Separate Campaign - IOC
            var = pagina["Campaign"].str.split(" - ", expand=True)
            pagina["Campaign"] = var[0].str.strip()
            pagina["Campaign"].replace('', 'Cyberproof_CTI', inplace=True)
            if(var.shape[1] == 2):
                pagina["Description"] = var[1].str.strip()
            else:
                pagina["Description"] = ""

########################################################################################################
            # TODO
            # Ficar el Threat level si volem ficar de moment algun score
########################################################################################################

            pagina.to_excel("data/resultat.xlsx")

            pagina = pagina[pagina.value != '']
            # IMPLEMENTATION TO MISP
            # Delete non CrowStrike IOCs
            # pagina.drop(pagina[pagina['Added'] ==
            #            "No"].index, inplace=True)

            # Transpose & delete innecessary columns
            pagina["Description"].fillna('', inplace=True)
            pagina = pagina.groupby(['Campaign', 'type', 'Description'])[
                'value'].apply(list).reset_index(name='events')

            mispM = misp.misp_instance(
                os.getenv("misp_url"), os.getenv("misp_secret"))
            mispM.setEvents(pagina)
            mispM.push()

            file.close()
            yield "{\"finished\": \"IOCs Loaded!!\"}\n"

        except Exception as e:
            yield "{\"error\": \"%s\"}\n" % (e)

    if request.method == 'POST':
        os.chdir(app.root_path)
        if 'file' not in request.files:
            return Response("{\"error\": \"You need to provide a file!\"}\n")
        else:
            try:
                csv = request.files['file']
                if 'csv' in csv.filename:
                    df = pd.read_csv(csv, encoding='latin1')
                else:
                    df = pd.read_excel(csv)
            except Exception as e:
                return Response("{\"error\": \"Invalid file format\"}\n")
            return Response(gen(df, csv.filename))


@app.route('/delete', methods=['POST'])
def elimina():
    def gen(df):
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            results = {executor.submit(
                ThreadPool.delete_concurrent, a) for a in df.values}
            yield "{\"total\": %d}\n" % (len(df.values))
            time.sleep(1)
            aux = []
            for result in concurrent.futures.as_completed(results):
                aux.append(result.result())
                yield "{\"progress\": %d}\n" % (len(aux))
            time.sleep(1)
            yield "{\"finished\": \"IOCs Deleted!!\"}\n"

    if request.method == 'POST':
        if 'file' not in request.files:
            return Response("{\"error\": \"You need to provide a file!\"}\n")
        else:
            try:
                csv = request.files['file']
                if 'csv' in csv.filename:
                    df = pd.read_csv(csv)
                else:
                    df = pd.read_excel(csv)
                return Response(gen(df))
            except:
                return Response("{\"error\": \"Invalid file format\"}\n")


@app.route('/update', methods=['POST'])
def actualitza():
    def gen(df, filename, action):
        file = open("data/resultat_hash.txt", "w")
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            try:
                results = {executor.submit(
                    ThreadPool.update_concurrent, a, filename, file, action) for a in df.values}
                yield "{\"total\": %d}\n" % (len(df.values))
                time.sleep(1)
                aux = []
                for result in concurrent.futures.as_completed(results):
                    aux.append(result.result())
                    yield "{\"progress\": %d}\n" % (len(aux))
                llista_type = [a[0] for a in aux]
                llista_comprovacio = [a[1] for a in aux]
                llista_value = [a[2] for a in aux]
                llista_bool = [a[3] for a in aux]
            except:
                pass
        pagina = pd.DataFrame({'type': llista_type,
                               'value': llista_value,
                               'Updated': llista_bool,
                               'Description': llista_comprovacio
                               })
        pagina.to_excel("data/resultat.xlsx")
        file.close()
        yield "{\"finished\": \"IOCs Updated!!\"}\n"

    if request.method == 'POST':
        os.chdir(app.root_path)
        if 'file' not in request.files:
            return Response("{\"error\": \"You need to provide a file!\"}\n")
        else:
            try:
                csv = request.files['file']
                if 'csv' in csv.filename:
                    df = pd.read_csv(csv)
                else:
                    df = pd.read_excel(csv)
                return Response(gen(df, csv.filename, request.form['action']))
            except:
                return Response("{\"error\": \"Invalid file format\"}\n")


@app.route('/getExcel', methods=['GET', 'POST'])
def download_excel():
    path = app.root_path + "//data//resultat.xlsx"
    return send_file(path, as_attachment=True)


@app.route('/getText', methods=['GET', 'POST'])
def download_text():
    path = app.root_path + "//data//resultat_hash.txt"
    return send_file(path, as_attachment=True)


@app.route("/addIocTemplate")
def create():
    return render_template('createIoc.html')


@app.route("/deleteIocTemplate")
def delete():
    return render_template('deleteIoc.html')


@app.route("/updateIocTemplate")
def update():
    return render_template('updateIoc.html')


@app.route("/")
def main():
    os.chdir(app.root_path)
    return render_template('index.html', var=os.getenv("logo"))


if __name__ == "__main__":
    app.run()
