FROM python:3.9-slim-bullseye
MAINTAINER guoguopapa@gmail.com
RUN mkdir -p /opt/fail2ban/logs
ADD *.py /opt/fail2ban/
ADD requirements.txt /opt/fail2ban
RUN pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r /opt/fail2ban/requirements.txt
RUN chmod +x /opt/fail2ban/fail2ban.py
ENTRYPOINT ["python", "/opt/fail2ban/fail2ban.py"]
