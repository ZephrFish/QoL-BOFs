#!/bin/bash

# List of repositories to add as submodules
repos=(
    "https://github.com/outflanknl/HelpColor"
)

# Add each repository as a submodule
for repo in "${repos[@]}"; do
    name=$(basename "$repo" .git)
    echo "Adding $repo as a submodule..."
    git submodule add "$repo" "submodules/$name"
done

# Initialize and update all submodules
git submodule update --init --recursive

echo "All repositories have been added as submodules!"