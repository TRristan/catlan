FROM python:3.12-alpine
WORKDIR /app
COPY catlan.py index.html kitty.ps1 kitty.sh ./
ENV CATLAN_DATA=/data CATLAN_PORT=8080
VOLUME /data
EXPOSE 8080 514/udp
CMD ["python", "-u", "catlan.py"]
