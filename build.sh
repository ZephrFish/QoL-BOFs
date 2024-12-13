#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status

# Create the dist folder
DIST_DIR="dist"
mkdir -p "$DIST_DIR"

# Function to build using a Makefile
build_with_makefile() {
    local dir="$1"
    echo "Found Makefile in $dir. Running make..."
    make -C "$dir"
    # Copy any generated `.o` files to the dist directory
    find "$dir" -name "*.o" -type f -exec cp {} "$DIST_DIR" \;
}

# Recursively search for Makefiles and compile with them
find . -name "Makefile" -type f | while read -r makefile; do
    build_with_makefile "$(dirname "$makefile")"
done

# Find all remaining .c files without a Makefile and compile them
find . -name "*.c" -type f ! -path "*/dist/*" | while read -r file; do
    # Skip if the file is in a directory with a Makefile
    dir=$(dirname "$file")
    if [ -f "$dir/Makefile" ]; then
        continue
    fi

    # Compile the .c file to .o file
    base=$(basename "$file" .c)

    # Find include path for bofdefs.h
    INCLUDE_PATH=$(find . -name "bofdefs.h" -exec dirname {} \; | head -n 1)

    if [ -z "$INCLUDE_PATH" ]; then
        echo "Error: 'bofdefs.h' not found. Skipping $file."
        continue
    fi

    # Compile the file
    x86_64-w64-mingw32-gcc -o "$DIST_DIR/${base}.o" -I "$INCLUDE_PATH" -Os -c "$file" -DBOF
    echo "Compiled $file to $DIST_DIR/${base}.o"
done
