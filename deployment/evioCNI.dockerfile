FROM partlab/ubuntu-golang

WORKDIR /root/
COPY ./evioUtilities .
COPY ./evioPlugin .
COPY ./host-local .
COPY ./cmd.sh .
RUN chmod +x cmd.sh
RUN chmod +x evioUtilities
RUN chmod +x evioPlugin
RUN chmod +x host-local

CMD ["./cmd.sh"]
