FROM python:3.8-slim-buster

WORKDIR /posource

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY app.py .

CMD ["gunicorn", "--workers", "10", "--log-file=/tmp/gunicorn.log", "--access-logfile=/tmp/gunicorn-access.log", "-b", "0.0.0.0:5000", "app:app"]
