#!/bin/bash

# Set the name of your main Go file
MAIN_FILE="../main.go"
OUTPUT_DIR="bin"

# Ensure the output directory exists
mkdir -p "$OUTPUT_DIR"

# Define build targets
declare -a TARGETS=(
    "linux amd64 v1_fs_scanner_linux"
    "linux arm64 v1_fs_scanner_linux_arm"
    "windows amd64 v1_fs_scanner_windows.exe"
    "darwin amd64 v1_fs_scanner_macos"
    "darwin arm64 v1_fs_scanner_macos_arm"
)

# Build function
build() {
    local os="$1"
    local arch="$2"
    local output="$OUTPUT_DIR/$3"

    echo "Building for $os $arch..."
    GOOS="$os" GOARCH="$arch" go build -o "$output" "$MAIN_FILE"
    
    if [[ $? -ne 0 ]]; then
        echo "Error: Build failed for $os $arch."
        exit 1
    fi
}

# Run builds
for target in "${TARGETS[@]}"; do
    build $target
done

# Print success message only if all builds succeed
echo "Builds completed successfully."
