#!/bin/bash
# Author: wpc
# Description: Bump version, commit, tag, and push to GitHub
# Last Modified: 2026.5.4

cd "$(dirname "$0")"

# Read current version from package.json
CURRENT=$(grep '"version"' package.json | head -1 | sed 's/.*"\([0-9][^"]*\)".*/\1/')
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

# Update
sed -i "s/\"version\": \"[^\"]*\"/\"version\": \"$NEW\"/" package.json
sed -i "s/\"version\": \"[^\"]*\"/\"version\": \"$NEW\"/" src-tauri/tauri.conf.json
sed -i "s/^version = \"[^\"]*\"/version = \"$NEW\"/" src-tauri/Cargo.toml

git add .
git commit -m "app release: version $NEW"
git tag "app-v$NEW"
git push
git push --tags

echo "Done! Released app-v$NEW"
