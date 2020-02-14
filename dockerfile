FROM 10.72.8.172:5000/e-autumn-template:1.4
WORKDIR /root
COPY . .
RUN python3.7 -m pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
RUN apt-get install libpcap-dev -y
RUN chmod a+x /root/bin/masscan
ENV EXECUTOR_TYPE ip_extend_scan
ENV MAIN_FILE ip_extend_scan.py
ENV WORK_DIR /root
ENV OTHER_CMDS="[\"chmod a+x bin/masscan\"]"
CMD python3.7 run.py start
