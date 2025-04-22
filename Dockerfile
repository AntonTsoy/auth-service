FROM golang:1.23.8-nanoserver
WORKDIR /app
COPY . .
RUN go build -o auth-service ./
CMD ["./auth-service"]
