import sys
import threading

from backend.app import create_app


def run_server():
    app = create_app()
    from waitress import serve
    serve(app, host="127.0.0.1", port=5111)


def main():
    # Start backend server in background
    t = threading.Thread(target=run_server, daemon=True)
    t.start()

    # Windows: launch desktop wrapper
    if sys.platform.startswith("win"):
        import webview

        class DesktopApi:
            def __init__(self, window: "webview.Window"):
                self.window = window

            def pick_memory_file(self):
                try:
                    paths = self.window.create_file_dialog(
                        webview.OPEN_DIALOG,
                        allow_multiple=False,
                        file_types=(
                            "Memory images (*.mem;*.raw;*.dmp;*.img)",
                            "*.mem;*.raw;*.dmp;*.img",
                            "All files (*.*)",
                            "*.*",
                        ),
                    )
                    if not paths:
                        return None
                    return paths[0]
                except Exception:
                    return None

        api = DesktopApi(None)
        window = webview.create_window(
            "MemoryLens",
            "http://127.0.0.1:5111",
            width=1200,
            height=800,
            js_api=api,
        )
        api.window = window

        # Prefer default GUI selection for compatibility. If you want Edge explicitly, keep gui="edgechromium".
        webview.start(debug=False, http_server=False)

    # Linux/macOS: run server-only mode (user opens browser)
    else:
        print("MemoryLens server is running at http://127.0.0.1:5111")
        print("Open it in your browser. Desktop mode is Windows-only by default.")
        t.join()


if __name__ == "__main__":
    main()
