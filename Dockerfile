FROM python:latest

ENV APPPATH /opt/myflaskapp
COPY . $APPPATH
WORKDIR $APPPATH/app

RUN buildDeps='python3-pip python3-dev build-essential' \
    && set -x \
    && apt-get update \
	&& apt-get install -y $buildDeps \
 	&& pip3 install --upgrade pip3 \
 	&& pip3 install -r requirements.txt \
 	&& apt-get clean \
 	&& rm -rf /var/lib/apt/lists/* \
 	&& apt-get purge -y --auto-remove $buildDeps

EXPOSE 5000

ENTRYPOINT ["python3"]
CMD ["src/app.py"]
