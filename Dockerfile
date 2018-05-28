# Build Container
FROM golang:1.9.4-alpine3.7 AS build-env
RUN apk add --no-cache --upgrade git
RUN go get -u github.com/golang/dep/cmd/dep
WORKDIR /go/src/app

# Cache the dependencies early
COPY Gopkg.toml Gopkg.lock ./
RUN dep ensure -vendor-only -v

# Build
COPY *.go ./
RUN go build -o ./tkosubs *.go

# Final Container
FROM alpine:3.7
COPY --from=build-env /go/src/app/tkosubs /usr/bin/tkosubs
RUN mkdir /app
WORKDIR /app
COPY providers-data.csv .
COPY domains.txt .
ENTRYPOINT ["/usr/bin/tkosubs"]
