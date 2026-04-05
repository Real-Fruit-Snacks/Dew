# Contributing to Dew

Thank you for your interest in contributing to Dew! This document provides guidelines and instructions for contributing.

## Development Environment Setup

### Prerequisites

- **MinGW-w64:** `x86_64-w64-mingw32-gcc` for cross-compilation
- **Python 3.8+:** For the listener and build script
- **PyNaCl:** `pip install pynacl`
- **Git:** For version control

### Getting Started

```bash
# Fork and clone the repository
git clone https://github.com/<your-username>/Dew.git
cd Dew

# Build everything (generates random PSK)
./build.sh 127.0.0.1 443

# Or use make directly
make LHOST=127.0.0.1 LPORT=443

# Clean build artifacts
make clean
```

## Code Style

Dew is written in C targeting MinGW-w64. Follow these conventions:

- **Functions:** Lowercase with underscores (`encrypt_message`, `send_request`)
- **Constants:** Uppercase with underscores (`CALLBACK_HOST`, `MAX_OUTPUT`)
- **Comments:** Explain intent, not mechanics. Every function gets a header comment.
- **Indentation:** 4 spaces, no tabs
- **Line length:** 100 characters max where practical

## Testing

Test changes against a local listener before submitting:

```bash
# Build with test key
./build.sh 127.0.0.1 4444

# Start listener in one terminal
python3 listener.py --lport 4444 --key <key-from-build>

# Run dew.exe on a Windows target or VM
```

## Pull Request Process

1. **Fork** the repository and create a feature branch:
   ```bash
   git checkout -b feat/my-feature
   ```

2. **Make your changes** with clear, focused commits.

3. **Test thoroughly** against a local listener.

4. **Push** your branch and open a Pull Request against `main`.

5. **Describe your changes** in the PR using the provided template.

6. **Respond to review feedback** promptly.

## Commit Message Format

This project follows [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<optional scope>): <description>

[optional body]

[optional footer(s)]
```

### Types

| Type       | Description                          |
| ---------- | ------------------------------------ |
| `feat`     | New feature                          |
| `fix`      | Bug fix                              |
| `docs`     | Documentation changes                |
| `style`    | Formatting, no code change           |
| `refactor` | Code restructuring, no behavior change |
| `test`     | Adding or updating tests             |
| `ci`       | CI/CD changes                        |
| `chore`    | Maintenance, dependencies            |
| `perf`     | Performance improvements             |

### Examples

```
feat(crypto): add nonce counter fallback for high-frequency sends
fix(listener): handle malformed beacon payloads gracefully
docs: update build instructions for MinGW 13
```

### Important

- Do **not** include AI co-author signatures in commits.
- Keep commits focused on a single logical change.

## Questions?

If you have questions about contributing, feel free to open a discussion or issue on GitHub.
