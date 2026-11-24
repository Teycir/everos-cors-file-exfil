import json
from http.server import BaseHTTPRequestHandler, HTTPServer

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(n)
        try:
            _req=json.loads(body)
            _rf=_req.get('response_format') or {}
            _js=_rf.get('json_schema') or {}
            _nm=(_js.get('schema') or {}).get('title') or _js.get('name') or ''
            open('/tmp/everos-poc-lab/llm_calls.log','a').write(_nm+'\n')
        except Exception: pass
        if self.path.endswith('/embeddings'):
            try:
                inp = json.loads(body).get('input', '')
                cnt = len(inp) if isinstance(inp, list) else 1
            except Exception:
                cnt = 1
            vec = [0.01] * 8
            out = {"object":"list","data":[{"object":"embedding","index":i,"embedding":vec} for i in range(cnt)],"model":"stub-embed","usage":{"prompt_tokens":1,"total_tokens":1}}
        elif self.path.endswith('/rerank'):
            try:
                docs = json.loads(body).get('documents', [])
            except Exception:
                docs = []
            cnt = len(docs) if isinstance(docs, list) else 1
            out = {"results":[{"index":i,"relevance_score":0.5} for i in range(cnt)]}
        elif self.path.endswith('/chat/completions'):
            replies={
             "TopicTreeReply":'{"language":"en","summary":"stub summary","subject":"stub subject","keywords":[],"content_labels":[],"topics":[]}',
             "ContentMergeReply":'{"language":"en","summary":"stub summary","subject":"stub subject","keywords":[]}',
             "TopicMergeReply":'{"merges":[]}',
             "CategoryReply":'{"category_id":""}',
             "TopicSplitReply":'{"results":[]}',
             "UncoveredAssignReply":'{"assignments":[]}',
            }
            content=replies.get(_nm,'{}')
            out = {"id":"stub","object":"chat.completion","created":0,"model":"stub-llm","choices":[{"index":0,"message":{"role":"assistant","content":content},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}
        else:
            self.send_response(404); self.end_headers(); return
        data = json.dumps(out).encode()
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(data)))
        self.end_headers(); self.wfile.write(data)
    def log_message(self,*a): pass

HTTPServer(('127.0.0.1',18999),H).serve_forever()
