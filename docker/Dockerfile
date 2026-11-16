FROM docker.io/metacubex/mihomo:Alpha

COPY --chmod=0755 entrypoint.sh config-gen /

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/mihomo"]