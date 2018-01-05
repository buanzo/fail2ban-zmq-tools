# you will need to use bindmount to get fail2ban.log to be
# accesible by this container on /var/log/fail2ban.log
FROM python:3.5
COPY requirements.txt
COPY fail2ban-cluster.conf /code
COPY fail2ban-monitor.py /code
COPY daemon.py /code
COPY monitor.py /code
WORKDIR /code
RUN pip install -r requirements.txt
RUN chmod +x /code/fail2ban-monitor.py
CMD ["/code/fail2ban-monitor.py"]
