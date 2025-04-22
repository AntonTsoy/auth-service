FROM golang:1.23.8-alpine
WORKDIR /app
COPY . .
RUN go build -o auth-service ./
CMD ["./auth-service"]
