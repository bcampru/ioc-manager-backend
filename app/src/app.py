from flask import Flask, render_template, request
import requests
import pandas as pd
import os
from pandas import ExcelWriter
from app.src.app import VT
from app.src.app import authentication
from app.src.app import create_json
from app.src.app import crowdstrike


app = Flask(__name__)
app.config['MAX_CONTENT_LENGHT']=16*1000*1000*1000


@app.route('/form', methods=['POST'])
def form():
    if request.method == 'POST':
    
        print(request.files['file'])

        if 'file' not in request.files:
            return render_template('app.html')
        
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

                for a in df.values:
                    if (a[0] == 'SHA-256') or (a[0] == 'MD5'):
                        a[0] = a[0].replace("-", "")
                        llista_type.append(a[0])
                        llista_value.append(a[1])
                        diccionario = virustotal(a)

                        if(diccionario["score"] != '0' and diccionario["score"] != '-1'):
                            result = crowd(diccionario, "prevent", csv.filename)
                            file.write(a[1] + " " + diccionario["name"] + os.linesep)

                            if(int(result["status_code"]) >= 400):
                                llista_comprovacio.append(result["body"]["resources"][0]["message"])
                            else:
                                llista_comprovacio.append("Hash correctly added")
                        else:
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
                            diccionario = virustotal(a)
                            if(diccionario["score"] != '0' and diccionario["score"] != '-1'):
                                result = crowd(diccionario, "detect", csv.filename)

                                if(int(result["status_code"]) >= 400):
                                    llista_comprovacio.append(result["body"]["resources"][0]["message"])
                                else:
                                    llista_comprovacio.append("correctly added")
                            else:
                                if(diccionario["score"] == '0'):
                                    llista_comprovacio.append("Domain wasn't added as it isn't harmfull")
                            
                                elif(diccionario["score"] == '-1'):
                                    llista_comprovacio.append("Domain wasn't added, not found in VirusTotal")
                        else:
                            llista_comprovacio.append("Type is not valid")

                pagina = pd.DataFrame({'type': llista_type,
                   'value': llista_value,
                   'Token': llista_comprovacio 
                   })
                pagina = pagina[['type','value','Token']]
                
                writer = ExcelWriter('data/resultat.xlsx')
                pagina.to_excel(writer, 'Hoja de datos', index=False)
                writer.save()
                
                file.close()

            except:
                return render_template('error.html')

            return render_template('confirmar.html')
              

        
    

@app.route("/")
def main():
    return render_template('app.html')

if __name__ == "__main__":
    app.run()


