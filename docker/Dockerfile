FROM ubuntu:20.04
#
# Setup redishoneypot
#
COPY ssh /opt/ssh/
COPY config.yaml /opt/ssh/
COPY root_fs.tar.gz /opt/ssh/
COPY private_key /opt/ssh/

# Start redishoneypot
WORKDIR /opt/ssh
RUN mkdir session_logs
CMD ./ssh  serve

# CMD tail -f
# docker build -t hary654321/ssh  .
