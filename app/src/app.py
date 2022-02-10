from flask import Flask, render_template, request
from flask import *
import requests
import pandas as pd
import os
from pandas import ExcelWriter
import concurrent.futures
from app.src import ThreadPool


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
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                     
                    try:
                        future_result={executor.submit(ThreadPool.add, a, csv, file) for a in df.values}
                        aux=concurrent.futures.wait(future_result, None)
                        llista_type=[a._result[0] for a in aux[0]]
                        llista_comprovacio=[a._result[1] for a in aux[0]]
                        llista_value=[a._result[2] for a in aux[0]]
                        llista_bool=[a._result[3] for a in aux[0]]
                    except:
                        pass
                
                

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

                with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                    try:
                        future_result={executor.submit(ThreadPool.delete_concurrent, a[1]) for a in df.values}
                        aux=concurrent.futures.wait(future_result, None)
                    except:
                        pass  
                    
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
  
                with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                     
                    try:
                        future_result={executor.submit(ThreadPool.update_concurrent, a, csv, file, request.form['action']) for a in df.values}
                        aux=concurrent.futures.wait(future_result, None)
                        llista_type=[a._result[0] for a in aux[0]]
                        llista_comprovacio=[a._result[1] for a in aux[0]]
                        llista_value=[a._result[2] for a in aux[0]]
                        llista_bool=[a._result[3] for a in aux[0]]
                    except:
                        pass
  
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


