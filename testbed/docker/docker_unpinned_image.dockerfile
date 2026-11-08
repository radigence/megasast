# rule: megasast/docker-unpinned-image
FROM alpine:3
RUN make test
