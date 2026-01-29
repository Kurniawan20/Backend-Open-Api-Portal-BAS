.PHONY: dev build test clean swagger

# Development
dev:
	go run cmd/server/main.go

# Build
build:
	go build -o bin/server cmd/server/main.go

# Test
test:
	go test -v ./...

# Clean
clean:
	rm -rf bin/

# Generate Swagger docs
swagger:
	swag init -g cmd/server/main.go -o docs

# Install dependencies
deps:
	go mod tidy
	go mod download

# Database migrations (requires golang-migrate)
migrate-up:
	migrate -path migrations -database "postgresql://postgres:password@localhost:5432/bas_portal?sslmode=disable" up

migrate-down:
	migrate -path migrations -database "postgresql://postgres:password@localhost:5432/bas_portal?sslmode=disable" down

# Docker
docker-build:
	docker build -t bas-portal-api .

docker-run:
	docker run -p 3000:3000 --env-file .env bas-portal-api
