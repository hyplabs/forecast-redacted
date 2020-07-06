# build command: docker build --tag forecast_web .
# run command: docker run -i -t forecast_web:latest

# due to an [eventlet bug](https://github.com/eventlet/eventlet/issues/526), we can't use Python 3.7+, so we're stuck on Python 3.6
FROM python:3.6-buster

# install system dependencies
RUN apt-get -y update && DEBIAN_FRONTEND=noninteractive apt-get install -y python3-pip python3-psycopg2 postgresql-client

# install app dependencies
COPY ./requirements.txt /app/backend/requirements.txt
RUN cd /app/backend && python3 -m pip install -r requirements.txt

COPY . /app/backend

# disable stdout buffering to avoid losing log messages
ENV PYTHONUNBUFFERED 1

# service is exposed on port 5000, load balancer will take care of the rest
EXPOSE 5000

# switch to a non-root user and start in the backend directory
RUN useradd -ms /bin/bash forecast
USER forecast
WORKDIR /app/backend

# gunicorn must be run in eventlet mode, and there can only be one worker since gunicorn's load balancing is too limited to stick websocket requests to the right worker when there are multiple workers
CMD [ "gunicorn", "server:app", "--worker-class", "eventlet", "-w", "1", "--bind", "0.0.0.0:5000", "--access-logfile", "-" ]
