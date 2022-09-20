from flask import *
import pandas as pd
import os
import concurrent.futures
from app.src import ThreadPool
from app.src import misp
from app.src.mispLogger import mispLogger
import time


app = Flask(__name__)
app.config['MAX_CONTENT_LENGHT'] = 16*1000*1000*1000


def transform(a):
    a[0] = a[0].replace("-", "") if(type(a[0]) != float) else ""
    a[1] = a[1].replace("[", "") if(type(a[1]) != float) else ""
    a[1] = a[1].replace("]", "") if(type(a[1]) != float) else ""
    a[0] = a[0].lower()
    a[1] = a[1].lower()
    a[2] = a[2].replace("[", "") if(type(a[2]) != float) else ""
    a[2] = a[2].replace("]", "") if(type(a[2]) != float) else ""
    a[3] = a[3] if(type(a[3]) != float) else ""
    return a


@app.route('/load', methods=['POST'])
def load():
    def gen(df, filename, ccoo):
        try:

            file = open("data/resultat_hash.txt", "w")
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:

                try:
                    df = df.apply(transform, axis=1)
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

            pagina = pd.DataFrame({'Type': llista_type,
                                  'Value': llista_value,
                                   'Added to Crowdstrike': llista_bool,
                                   'Crowdstrike Response': llista_comprovacio,
                                   'Description': llista_comprovacio,
                                   'Campaign': llista_campanya
                                   })

            # Separate Campaign - IOC
            pagina["Campaign"].fillna("", inplace=True)
            pagina["Campaign"].replace('', 'Cyberproof_CTI', inplace=True)
            var = pagina["Campaign"].str.split(" - ", expand=True)
            pagina["Campaign"] = var[0].str.strip()
            if(var.shape[1] == 2):
                pagina["Description"] = var[1].str.strip()
            else:
                pagina["Description"] = ""

            pagina["Description"].fillna('', inplace=True)
            excel = pagina
            pagina = pagina[pagina.Value != '']
            pagina = pagina.groupby(['Campaign', 'Type', 'Description'])[
                'Value'].apply(list).reset_index(name='events')

            mispM = misp.misp_instance(
                os.getenv("misp_url"), os.getenv("misp_secret"))
            excel["MISP"] = mispM.setEvents(pagina, ccoo)
            mispM.push()
            excel.to_excel("data/resultat.xlsx")

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
            return Response(gen(df, csv.filename, request.form['ccoo'] == 'true'))


@app.route('/delete', methods=['POST'])
def elimina():
    def gen(df):
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            mispM = misp.misp_instance(
                os.getenv("misp_url"), os.getenv("misp_secret"))
            df = df.apply(transform, axis=1)
            mispM.deleteAttributes(df)
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
                df = df.apply(transform, axis=1)
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
                    df = pd.read_csv(csv, encoding='latin1')
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


@app.route("/iocLogger", methods=['GET'])
def logger():
    return render_template('iocLogger.html')


@app.route("/tableVisualizer", methods=['GET'])
def tableVisualizer():
    return render_template('tableVisualizer.html')


@app.route("/iocLogger", methods=['POST'])
def postLogger():
    if request.method == 'POST':
        os.chdir(app.root_path)
        logger = mispLogger()
        if(logger.insert(request.json)):
            return {}, 200
        else:
            return {}, 500


@app.route("/iocLogger/<succeed>", methods=['GET'])
def getLogger(succeed):
    if request.method == 'GET':
        os.chdir(app.root_path)
        logger = mispLogger()
        return jsonify(logger.getData(succeed))


@app.route("/")
def main():
    os.chdir(app.root_path)
    return render_template('index.html', var=os.getenv("logo"))


if __name__ == "__main__":
    app.run()
