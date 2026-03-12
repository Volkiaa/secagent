#!/bin/bash
# secagent install-hooks
# Installs git pre-commit hooks for security scanning

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || echo "$SCRIPT_DIR/..")"
HOOKS_DIR="$REPO_ROOT/.git/hooks"

echo "🔧 Installing secagent git hooks..."
echo ""

# Check if we're in a git repo
if [ ! -d "$REPO_ROOT/.git" ]; then
    echo -e "${YELLOW}Warning: Not in a git repository${NC}"
    echo "Creating .git directory..."
    mkdir -p "$REPO_ROOT/.git/hooks"
fi

# Create hooks directory if it doesn't exist
mkdir -p "$HOOKS_DIR"

# Install pre-commit hook
PRE_COMMIT_HOOK="$HOOKS_DIR/pre-commit"
cat > "$PRE_COMMIT_HOOK" << 'HOOK'
#!/bin/bash
# secagent pre-commit hook - Auto-generated

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git rev-parse --show-toplevel)"

# Try to find secagent pre-commit script
if [ -f "$REPO_ROOT/scripts/pre-commit" ]; then
    exec "$REPO_ROOT/scripts/pre-commit"
elif command -v secagent &> /dev/null; then
    # Use installed secagent if available
    exec secagent scan --scanners gitleaks,semgrep --diff HEAD
else
    echo "Warning: secagent not found. Install with:"
    echo "  go build -o secagent ./cmd/secagent"
    echo "  sudo mv secagent /usr/local/bin/"
    exit 0
fi
HOOK

chmod +x "$PRE_COMMIT_HOOK"

echo -e "${GREEN}✓ Pre-commit hook installed${NC}"
echo ""
echo "Hook location: $PRE_COMMIT_HOOK"
echo ""
echo "To test the hook:"
echo "  git commit --allow-empty -m 'test commit'"
echo ""
echo "To bypass the hook (not recommended):"
echo "  git commit --no-verify"
echo ""
echo -e "${GREEN}Done!${NC}"
