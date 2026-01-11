mkdir -p out

for f in *.md; do
  base="${f%.md}"
  if python3 md2json.py < "$f" > "out/${base}.json"; then
    echo "[OK] $f -> out/${base}.json"
  else
    echo "[FAIL] $f" >&2
  fi
done

