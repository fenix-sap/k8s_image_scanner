# python3
FROM python:3.7
RUN mkdir /code
# python file
ADD k8s_quary.py /code/
WORKDIR /code
RUN pip install kubernetes
# entrypoint
ENTRYPOINT ["python3","k8s_quary.py"]
