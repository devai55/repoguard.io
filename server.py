#!/usr/bin/env python3
"""
Simple web server for RepoGuard landing page
"""

import http.server
import socketserver
import os
import webbrowser
from pathlib import Path

class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        super().end_headers()

def main():
    """Start web server and open browser"""
    port = 8080

    # Change to the directory containing index.html
    web_dir = Path(__file__).parent
    os.chdir(web_dir)

    try:
        with socketserver.TCPServer(("", port), CustomHTTPRequestHandler) as httpd:
            print(f"🚀 RepoGuard landing page server running at http://localhost:{port}")
            print("📄 Serving files from:", web_dir)
            print("🔗 Opening browser...")

            # Open browser
            webbrowser.open(f'http://localhost:{port}')

            print("💡 Press Ctrl+C to stop the server")
            httpd.serve_forever()

    except KeyboardInterrupt:
        print("\n👋 Server stopped")
    except Exception as e:
        print(f"❌ Error starting server: {e}")

if __name__ == "__main__":
    main()