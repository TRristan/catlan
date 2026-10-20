FROM python:3.12-alpine
WORKDIR /app
COPY catlan.py index.html kitty.ps1 ./
ENV CATLAN_DATA=/data CATLAN_PORT=8080
VOLUME /data
EXPOSE 8080
CMD ["python", "-u", "catlan.py"]
