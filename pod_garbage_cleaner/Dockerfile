FROM python:3.9-alpine
MAINTAINER guoguopapa@gmail.com
RUN pip install -i https://pypi.tuna.tsinghua.edu.cn/simple kubernetes
ADD pod_garbage_cleaner.py /
CMD ["python", "/pod_garbage_cleaner.py"]
