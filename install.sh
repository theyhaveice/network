#!bin/bash

if [[ "$OSTYPE" != "darwin"* ]]; then
    echo "This script only runs on macOS."
    exit 1
fi

echo "Lorem ipsum"
