#!/bin/bash
# DO NOT EVEN TRY TO DELETE THIS FILE OR ELSE

if [ -z "$1" ]; then
    echo "Usage: $0 <target_directory>"
    echo "Example: $0 parser_agent/output"
    exit 1
fi

TARGET_DIR="$1"
# Strip trailing slash if present
TARGET_DIR="${TARGET_DIR%/}"
BACKUP_DIR="${TARGET_DIR}_backup"

if [ ! -d "$TARGET_DIR" ]; then
    echo "Directory $TARGET_DIR does not exist."
    exit 1
fi

mkdir -p "$BACKUP_DIR" 2>/dev/null || sudo mkdir -p "$BACKUP_DIR"

echo "Archiving *.rml files from $TARGET_DIR to $BACKUP_DIR..."

shopt -s nullglob
for file in "$TARGET_DIR"/*.rml; do
    if [ -f "$file" ]; then
        mv "$file" "$BACKUP_DIR/" 2>/dev/null
        if [ $? -ne 0 ]; then
            echo "Permission denied moving $file, attempting with sudo..."
            sudo mv "$file" "$BACKUP_DIR/"
        fi
        echo "Moved: $file -> $BACKUP_DIR/"
    fi
done

echo "Cleanup complete. Files safely archived in $BACKUP_DIR."
