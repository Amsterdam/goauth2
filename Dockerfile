FROM golang:latest
  WORKDIR /go/src/github.com/amsterdam/authz
  COPY . /go/src/github.com/amsterdam/authz
  RUN go get github.com/sparrc/gdm
  RUN gdm restore
  RUN go install
  ENTRYPOINT ["authz"]
