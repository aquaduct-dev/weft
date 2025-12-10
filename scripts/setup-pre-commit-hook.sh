#!/bin/bash

echo "Setting up pre-commit hook..."

HOOK_DIR=".git/hooks"
HOOK_FILE="$HOOK_DIR/pre-commit"

mkdir -p "$HOOK_DIR"

cat << 'EOF' > "$HOOK_FILE"
#!/bin/bash
set -e

echo "Running gazelle fix..."
bazel run //:gazelle
if ! git diff --quiet; then
    echo "Error: Gazelle modified files. Please stage these changes and commit again."
    exit 1
fi

echo "Running tests..."
bazel test //...
EOF

chmod +x "$HOOK_FILE"

echo "Pre-commit hook installed successfully at $HOOK_FILE"
