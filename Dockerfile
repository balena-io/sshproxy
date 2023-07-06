FROM golang:1.20

WORKDIR /workspace

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .
RUN go build -v -o /workspace/sshproxy ./...

CMD ["/workspace/sshproxy"]
