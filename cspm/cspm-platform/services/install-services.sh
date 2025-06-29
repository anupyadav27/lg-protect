for dir in /Users/apple/Desktop/cspm/cspm-platform/services/*/; do
    if [ -f "$dir/package.json" ]; then
        echo "Installing dependencies in $dir"
        (cd "$dir" && npm install)
    fi
done