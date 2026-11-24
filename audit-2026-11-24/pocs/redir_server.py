from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header('Location','http://127.0.0.1:18099/canary2.txt')
        self.end_headers()
    def log_message(self,*a): pass
HTTPServer(('127.0.0.1',18098),H).serve_forever()
