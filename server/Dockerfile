# depwolf CVE index API — Oracle Cloud deployment
FROM python:3.12-slim

WORKDIR /srv

COPY server/requirements.txt /srv/server/requirements.txt
RUN pip install --no-cache-dir -r /srv/server/requirements.txt

COPY depwolf /srv/depwolf
COPY server/main.py /srv/server/main.py
COPY server/__init__.py /srv/server/__init__.py

ENV AVIP_DB_PATH=/data/cpe_index.db
ENV PYTHONPATH=/srv

EXPOSE 8000

CMD ["uvicorn", "server.main:app", "--host", "0.0.0.0", "--port", "8000"]