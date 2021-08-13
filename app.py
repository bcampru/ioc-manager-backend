from flask import Flask, render_template, request
import pandas as pd
import os



app = Flask(__name__)


@app.route('/form', methods=['POST'])
def form():
    if request.method == 'POST':
    
        print(request.files['file'])

        if 'file' not in request.files:
            return render_template('app.html')
        
        else:
                
            try:

                file = open("resultat_hash.txt", "w")
                file2 = open("resultat_ip.txt", "w")
                csv = request.files['file']
                df = pd.read_csv(csv)

                for a in df.values:
                    if (a[0] == 'SHA-256') or (a[0] == 'MD5') or (a[0] == 'SHA-1'):
                        file.write(a[1] + " ")
                    
                    else:
                        a[1] = a[1].replace("[", "")
                        a[1] = a[1].replace("]", "")
                        file2.write(str(a) + os.linesep)

                file.close()
                file2.close()
                return render_template('confirmar.html')
            except:
                pass    

        return render_template('app.html')
    

@app.route("/")
def main():
    return render_template('app.html')


