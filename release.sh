#!/bin/bash
# Author: wpc
# Description: Bump version, commit, tag, and push to GitHub
# Last Modified: 2026.8.17

cd "$(dirname "$0")"

# Read current version from Cargo.toml
CURRENT=$(grep '^version = ' Cargo.toml | head -1 | sed 's/^version = "\([0-9][^"]*\)"/\1/')
echo "Current version: $CURRENT"

# Get new version from argument or prompt
if [ -n "$1" ]; then
    NEW="$1"
else
    read -p "New version [$CURRENT]: " INPUT
    NEW="${INPUT:-$CURRENT}"
fi

if [ "$NEW" = "$CURRENT" ]; then
    echo "Version unchanged, exiting."
    exit 0
fi

echo "Bumping to version: $NEW"

# Update version in Cargo.toml
sed -i 's/^version = "[^"]*"/version = "'"$NEW"'"/' Cargo.toml

git add .
git commit -m "release: version $NEW"
git tag "v$NEW"
git push
git push --tags

echo "Done! Released v$NEW"
