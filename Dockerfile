FROM golang as builder
COPY src/ /go/src/github.com/r3da/go-tcp-proxy
WORKDIR /go/src/github.com/r3da/go-tcp-proxy
RUN go get ./... && \
    CGO_ENABLED=0 GOOS=linux go build -o tcp-proxy main.go

FROM scratch
COPY --from=builder /go/src/github.com/r3da/go-tcp-proxy/tcp-proxy /tcp-proxy
WORKDIR /
CMD ./tcp-proxy
