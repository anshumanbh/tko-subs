FROM golang:1.8-onbuild
MAINTAINER test
RUN apt-get update && apt-get install dnsutils -y
ENTRYPOINT ["app"]
