#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status

# Create the dist folder
DIST_DIR="dist"
mkdir -p "$DIST_DIR"

# Find all .c files and compile them
find . -name "*.c" -type f | while read -r file; do
    # Get the directory and filename
    dir=$(dirname "$file")
    base=$(basename "$file" .c)
    
    # Compile the .c file to .o file
    x86_64-w64-mingw32-gcc -c "$file" -o "$DIST_DIR/${base}.o"
    
    echo "Compiled $file to $DIST_DIR/${base}.o"
done
