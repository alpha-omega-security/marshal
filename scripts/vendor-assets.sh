#!/usr/bin/env bash
# Re-downloads the frontend assets served from internal/web/static/vendor/.
# Versions tracked alongside scrutineer's vendored set.

set -euo pipefail

vendor_dir="$(dirname "$0")/../internal/web/static/vendor"
mkdir -p "$vendor_dir"
cd "$vendor_dir"
rm -f -- *.js *.css

assets=(
  "tailwindcss-browser-4.3.0.js               https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4.3.0"
  "basecoat-0.3.11.min.css                    https://cdn.jsdelivr.net/npm/basecoat-css@0.3.11/dist/basecoat.cdn.min.css"
  "basecoat-0.3.11.min.js                     https://cdn.jsdelivr.net/npm/basecoat-css@0.3.11/dist/js/all.min.js"
  "htmx-2.0.6.min.js                          https://cdn.jsdelivr.net/npm/htmx.org@2.0.6/dist/htmx.min.js"
  "lucide-0.545.0.min.js                      https://cdn.jsdelivr.net/npm/lucide@0.545.0/dist/umd/lucide.min.js"
)

for entry in "${assets[@]}"; do
  read -r file url <<<"$entry"
  echo "  $file"
  curl -sSfLo "$file" "$url"
done

echo "Done. ${#assets[@]} assets refreshed in $(pwd)."
