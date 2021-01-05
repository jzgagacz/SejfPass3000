FROM python:3.7
WORKDIR /var/www/app
RUN useradd uwsgi
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
COPY . . 
EXPOSE 3031
CMD [ "uwsgi", "--ini", "uwsgi.ini" ]