FROM docker.io/metacubex/mihomo:Alpha

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

COPY config-gen /
RUN chmod +x /config-gen

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/mihomo"]