FROM python:3.9-alpine
MAINTAINER guoguopapa@gmail.com
RUN pip install -i https://pypi.tuna.tsinghua.edu.cn/simple kubernetes
RUN mkdir -p /opt/fail2ban/logs
ADD *.py /opt/fail2ban/
RUN chmod +x /opt/fail2ban/fail2ban.py
ENTRYPOINT ["python", "/opt/fail2ban/fail2ban.py"]
