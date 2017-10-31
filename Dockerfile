FROM golang:1.8-onbuild
MAINTAINER Mohammed Diaa <mohammeddiaa2000@gmail.com>
RUN apt-get update && apt-get install dnsutils -y
ENTRYPOINT ["app"]
