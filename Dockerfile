FROM scratch
COPY bin/leasegate /leasegate
USER 65532:65532
ENTRYPOINT ["/leasegate"]
