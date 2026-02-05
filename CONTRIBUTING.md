# Contributing to gtrace

Thank you for your interest in contributing to gtrace!

## Development Setup

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/gtrace.git
   cd gtrace
   ```

2. Ensure you have Go 1.24+ installed:
   ```bash
   go version
   ```

3. Build the project:
   ```bash
   go build -o gtrace ./cmd/gtrace
   ```

4. Run tests:
   ```bash
   go test ./...
   ```

## Running gtrace

gtrace requires root privileges for raw socket access:
```bash
sudo ./gtrace 8.8.8.8 --simple
```

## Code Style

- Run `gofmt` before committing:
  ```bash
  gofmt -w .
  ```

- Run `go vet` to catch common issues:
  ```bash
  go vet ./...
  ```

## Pull Request Guidelines

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/my-feature
   ```

2. Make your changes with clear, focused commits.

3. Ensure all tests pass:
   ```bash
   go test ./...
   ```

4. Update documentation if you're adding new features.

5. Submit a pull request with a clear description of your changes.

## Reporting Issues

When reporting bugs, please include:
- Go version (`go version`)
- Operating system and version
- Steps to reproduce the issue
- Expected vs actual behavior
- Any relevant error messages or output

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
