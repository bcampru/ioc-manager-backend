from flask import Flask, render_template, request
from flask import *
import requests
import pandas as pd
import os
from pandas import ExcelWriter
from app.src import VT
from app.src import crowdstrike


app = Flask(__name__)
app.config['MAX_CONTENT_LENGHT']=16*1000*1000*1000


@app.route('/form', methods=['POST'])
def form():
    if request.method == 'POST':
            
        os.chdir(app.root_path)
        
        if 'file' not in request.files:
            return render_template('createIoc.html')
        
        else:

            try:

                csv = request.files['file']
                
                if 'csv' in csv.filename:
                    df = pd.read_csv(csv)
                else:
                    df = pd.read_excel(csv)

                file = open("data/resultat_hash.txt", "w")
                llista_type = []
                llista_comprovacio = []
                llista_value = []
                llista_bool = []
                
                for a in df.values:
                    if (a[0] == 'SHA-256') or (a[0] == 'MD5'):
                        a[0] = a[0].replace("-", "")
                        llista_type.append(a[0])
                        llista_value.append(a[1])
                        diccionario = VT.virustotal(a)

                        if(diccionario["score"] != '0' and diccionario["score"] != '-1'):

                            result = crowdstrike.crowd(diccionario, "detect", csv.filename)
                        
                            if(int(result["status_code"]) >= 400):
                                llista_bool.append("No")
                                try:
                                    llista_comprovacio.append(result["body"]["resources"][0]["message"])
                                except:
                                    llista_comprovacio.append("falla " + result)
                            else:
                                file.write(a[0] + " " + a[1] + " " + diccionario["name"] + os.linesep)
                                llista_comprovacio.append("Hash correctly added")
                                llista_bool.append("Yes")
                        else:
                            llista_bool.append("No")
                            if(diccionario["score"] == '0'):
                                llista_comprovacio.append("Hash wasn't added as it isn't harmfull")
                            
                            elif(diccionario["score"] == '-1'):
                                llista_comprovacio.append("Hash wasn't added, not found in VirusTotal")

                    else:
                        a[1] = a[1].replace("[", "")
                        a[1] = a[1].replace("]", "")
                        llista_type.append(a[0])
                        llista_value.append(a[1])

                        if (a[0] == 'Domain'):
                            diccionario = VT.virustotal(a)
                            if(diccionario["score"] != '0' and diccionario["score"] != '-1'):
                                
                                result = crowdstrike.crowd(diccionario, "detect", csv.filename)
                                
                                if(int(result["status_code"]) >= 400):
                                    llista_bool.append("No")
                                    try:
                                        llista_comprovacio.append(result["body"]["resources"][0]["message"])
                                    except:
                                        llista_comprovacio.append("falla " + result)
                                else:
                                    file.write(a[0] + " " + a[1] + os.linesep)
                                    llista_comprovacio.append("correctly added")
                                    llista_bool.append("Yes")
                            else:
                                llista_bool.append("No")
                                if(diccionario["score"] == '0'):
                                    llista_comprovacio.append("Domain wasn't added as it isn't harmfull")
                            
                                elif(diccionario["score"] == '-1'):
                                    llista_comprovacio.append("Domain wasn't added, not found in VirusTotal")
                        else:
                            llista_comprovacio.append("Type is not valid")
                            llista_bool.append("No")

                pagina = pd.DataFrame({'type': llista_type,
                   'value': llista_value,
                   'Added': llista_bool,
                   'Description': llista_comprovacio 
                   })
                
                pagina.to_excel("data/resultat.xlsx")
                
                
                file.close()

            except :
                return render_template('error.html')

            return render_template('confirmar.html')
              
@app.route('/form_delete', methods=['POST'])
def elimina():
    if request.method == 'POST':
        if 'file' not in request.files:
            return render_template('deleteIoc.html')
        
        else:
            try:

                csv = request.files['file']
                if 'csv' in csv.filename:
                    df = pd.read_csv(csv)
                else:
                    df = pd.read_excel(csv)


                for a in df.values:
                    a[0] = a[0].replace("-", "")
                    a[1] = a[1].replace("[", "")
                    a[1] = a[1].replace("]", "")
                    crowdstrike.delete_crowd(a[1])
                    
            except :
                return render_template('error.html')

            return render_template('index.html')


@app.route('/update', methods=['POST'])
def actualitza():
    if request.method == 'POST':
    
        print(request.files['file'])
        os.chdir(app.root_path)
        if 'file' not in request.files:
            return render_template('updateIoc.html')
        
        else:

            try:

                csv = request.files['file']
                if 'csv' in csv.filename:
                    df = pd.read_csv(csv)
                else:
                    df = pd.read_excel(csv)

                file = open("data/resultat_hash.txt", "w")
                llista_type = []
                llista_comprovacio = []
                llista_value = []
                llista_bool = []

                for a in df.values:
                    if (a[0] == 'SHA-256') or (a[0] == 'MD5'):
                        a[0] = a[0].replace("-", "")
                        llista_type.append(a[0])
                        llista_value.append(a[1])
                        diccionario = VT.virustotal(a)

                        if(diccionario["score"] != '0' and diccionario["score"] != '-1'):

                            result = crowdstrike.updateIoc(diccionario, request.form['action'], csv.filename)
                        
                            if(int(result) == 0):
                                llista_bool.append("No")
                                llista_comprovacio.append("Not found in CrowdStrike")
                            else:
                                file.write(a[0] + " " + a[1] + " " + diccionario["name"] + os.linesep)
                                llista_comprovacio.append("Hash correctly updated")
                                llista_bool.append("Yes")
                        else:
                            llista_bool.append("No")
                            if(diccionario["score"] == '0'):
                                llista_comprovacio.append("Hash wasn't updated as it isn't harmfull")
                            
                            elif(diccionario["score"] == '-1'):
                                llista_comprovacio.append("Hash wasn't updated, not found in VirusTotal and CrowdStrike")

                    else:
                        a[1] = a[1].replace("[", "")
                        a[1] = a[1].replace("]", "")
                        llista_type.append(a[0])
                        llista_value.append(a[1])

                        if (a[0] == 'Domain'):
                            diccionario = VT.virustotal(a)
                            if(diccionario["score"] != '0' and diccionario["score"] != '-1'):
                                
                                result = crowdstrike.updateIoc(diccionario, "detect", csv.filename)
                                
                                if(int(result) == 0):
                                    llista_bool.append("No")
                                    llista_comprovacio.append("Not found in CrowdStrike")
                                else:
                                    file.write(a[0] + " " + a[1] + os.linesep)
                                    llista_comprovacio.append("correctly updated")
                                    llista_bool.append("Yes")
                            else:
                                llista_bool.append("No")
                                if(diccionario["score"] == '0'):
                                    llista_comprovacio.append("Domain wasn't updated as it isn't harmfull")
                            
                                elif(diccionario["score"] == '-1'):
                                    llista_comprovacio.append("Domain wasn't updated, not found in VirusTotal and CrowdStrike")
                        else:
                            llista_comprovacio.append("Type is not valid")
                            llista_bool.append("No")

                pagina = pd.DataFrame({'type': llista_type,
                   'value': llista_value,
                   'Updated': llista_bool,
                   'Description': llista_comprovacio 
                   })
                
                pagina.to_excel("data/resultat.xlsx")
                
                
                file.close()

            except :
                return render_template('error.html')

            return render_template('confirmar.html')
      

@app.route('/excel', methods=['GET', 'POST'])
def download_excel():   
    path = app.root_path + "//data//resultat.xlsx"
    return send_file(path, as_attachment=True)

@app.route('/text', methods=['GET', 'POST'])
def download_text():   
    path = app.root_path + "//data//resultat_hash.txt"
    return send_file(path, as_attachment=True)


@app.route("/addIoc")
def create():
    return render_template('createIoc.html')

@app.route("/deleteIoc")
def delete():
    return render_template('deleteIoc.html')

@app.route("/updateIoc")
def update():
    return render_template('updateIoc.html')

@app.route("/")
def main():
    return render_template('index.html')

if __name__ == "__main__":
    app.run()


