FROM python:3.7-alpine

MAINTAINER Alex Miłowski <alex@milowski.com>

RUN pip install flask Flask-Session requests redis 'itsdangerous<1.0.0'
COPY app /app/

ENV PYTHONPATH "/"

EXPOSE 5000

ENTRYPOINT ["python", "-m", "app"]
