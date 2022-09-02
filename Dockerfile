from debian:11-slim

RUN sed -i "s/deb.debian.org/mirrors.ustc.edu.cn/g" /etc/apt/sources.list
RUN sed -i "s/security.debian.org/mirrors.ustc.edu.cn/g" /etc/apt/sources.list
RUN apt-get update && \
    apt-get install python3 python3-pip -y && \
    mkdir /root/.pip && \
    echo "[global]" > /root/.pip/pip.conf && \
    echo "index-url = https://pypi.douban.com/simple" >> /root/.pip/pip.conf && \
    pip3 install requests flask prometheus_client && \
    apt-get autoremove && \
    rm -rf /var/lib/apt/lists/*

COPY app.py /app.py
COPY start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 9000
ENTRYPOINT ["/start.sh"]