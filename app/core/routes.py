from flask_jwt_extended import jwt_required, get_jwt_identity
import concurrent.futures

from sqlalchemy import null
from app.core import bp, ThreadPool, misp
import pandas as pd
import os
import time
from flask import jsonify, request, Response, send_file, current_app
from app.auth.helpers import get_user
import json
import re


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


def regex(iocs):
    match_d = {"ipv4": ["^(ip;)?(\d+\.\d+\.\d+\.\d+)$"],
               "ipv6": ["^(ip;)?([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])"],
               "domain": ["^(domain;)?((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z])"],
               "md5": ["^(hash;)?([a-f0-9]{32})$"],
               "sha1": ["^(hash;)?([a-f0-9]{40})$"],
               "sha256": ["^(hash;)?([a-f0-9]{64})$",
                          "^(filename\|sha256;).*\|([a-f0-9]{64})$"],
               "url": [".*(url;)?((http|https)://.*)$"],
               "email": ["^(email;)?([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)$"],
               }
    for k in match_d.keys():
        for r in match_d[k]:
            r = re.compile(r)
            res = list(filter(r.match, iocs))
            if res:
                iocs = [item for item in iocs if item not in res]
                for r in res:
                    yield [k, r]


@bp.route('/load', methods=['POST'])
@jwt_required()
def load():
    def gen(df, filename, clients, expiration=null):
        try:

            file = open("data/resultat_hash.txt", "w")
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:

                try:
                    if filename != 'Manual':
                        df = df.apply(transform, axis=1)
                    #[ThreadPool.add(a, filename, file) for a in df.values]
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
            pagina["Description"] = pagina["Description"] + \
                f" Uploaded by: {user['name']} {user['surname']}"
            excel = pagina
            pagina = pagina[pagina.Value != '']
            pagina = pagina.groupby(['Campaign', 'Type', 'Description'])[
                'Value'].apply(list).reset_index(name='events')

            mispM = misp.misp_instance(
                os.getenv("misp_url"), os.getenv("misp_secret"))
            excel["MISP"] = mispM.setEvents(pagina, clients, expiration)
            mispM.push()
            excel.to_excel("data/resultat.xlsx")

            file.close()
            yield "{\"finished\": \"IOCs Loaded!!\"}\n"

        except Exception as e:
            yield "{\"error\": \"%s\"}\n" % (e)

    if request.method == 'POST':
        os.chdir(current_app.root_path)
        user = get_user(get_jwt_identity())

        if 'file' in request.files:
            try:
                csv = request.files['file']
                if 'csv' in csv.filename:
                    df = pd.read_csv(csv, encoding='latin1')
                else:
                    df = pd.read_excel(csv)
            except Exception as e:
                return Response("{\"error\": \"Invalid file format\"}\n")
            return Response(gen(df, csv.filename, json.loads(request.form['clients'])))
        elif 'iocs' in request.form.keys():
            try:
                iocs = request.form['iocs'].replace(" ", "").splitlines()
                iocs = [ioc for ioc in regex(iocs)]
                if iocs == []:
                    raise Exception()
                df = pd.DataFrame(iocs, columns=['Type', 'Value'])
                df['Campaign'] = ''
            except Exception as e:
                return Response("{\"error\": \"You need to send valid IOCs\"}\n")
            return Response(gen(df, "Manual", json.loads(request.form['clients']), request.form['expiration']))

        else:
            return Response("{\"error\": \"You need to provide a file!\"}\n")


@bp.route('/delete', methods=['POST'])
@jwt_required()
def elimina():
    def gen(df, mode):
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                mispM = misp.misp_instance(
                    os.getenv("misp_url"), os.getenv("misp_secret"))
                if mode != "manual":
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
        except Exception as e:
            yield "{\"error\": \"%s\"}\n" % (e)
    if request.method == 'POST':
        if 'file' in request.files:
            try:
                csv = request.files['file']
                if 'csv' in csv.filename:
                    df = pd.read_csv(csv)
                else:
                    df = pd.read_excel(csv)
                return Response(gen(df, "file"))
            except:
                return Response("{\"error\": \"Invalid file format\"}\n")

        elif 'iocs' in request.form.keys():
            try:
                iocs = request.form['iocs'].replace(" ", "").splitlines()
                iocs = [ioc for ioc in regex(iocs)]
                if iocs == []:
                    raise Exception()
                df = pd.DataFrame(iocs, columns=['Type', 'Value'])
                df['Campaign'] = ''
            except Exception as e:
                return Response("{\"error\": \"You need to send valid IOCs\"}\n")
            return Response(gen(df, "manual"))

        else:
            return Response("{\"error\": \"You need to provide a file!\"}\n")


@bp.route('/update', methods=['POST'])
@jwt_required()
def actualitza():
    def gen(df, filename, action):
        file = open("data/resultat_hash.txt", "w")
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            try:
                if filename != "manual":
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
        os.chdir(current_app.root_path)
        if 'file' in request.files:
            try:
                csv = request.files['file']
                if 'csv' in csv.filename:
                    df = pd.read_csv(csv, encoding='latin1')
                else:
                    df = pd.read_excel(csv)
                return Response(gen(df, csv.filename, request.form['action']))
            except:
                return Response("{\"error\": \"Invalid file format\"}\n")
        elif 'iocs' in request.form.keys():
            try:
                iocs = request.form['iocs'].replace(" ", "").splitlines()
                iocs = [ioc for ioc in regex(iocs)]
                if iocs == []:
                    raise Exception()
                df = pd.DataFrame(iocs, columns=['Type', 'Value'])
                df['Campaign'] = ''
            except Exception as e:
                return Response("{\"error\": \"You need to send valid IOCs\"}\n")
            return Response(gen(df, "manual", request.form['action']))

        else:
            return Response("{\"error\": \"You need to provide a file!\"}\n")


@bp.route('/getExcel', methods=['GET', 'POST'])
def download_excel():
    path = current_app.root_path + "//data//resultat.xlsx"
    return send_file(path, as_attachment=True)


@bp.route('/getText', methods=['GET', 'POST'])
def download_text():
    path = current_app.root_path + "//data//resultat_hash.txt"
    return send_file(path, as_attachment=True)


@bp.route('/getClients', methods=['GET', 'POST'])
def get_clients():
    mispM = misp.misp_instance(
        os.getenv("misp_url"), os.getenv("misp_secret"))
    return jsonify(mispM.getClients())
