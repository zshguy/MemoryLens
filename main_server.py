from backend.app import create_app

def main():
    app = create_app()
    # Prefer waitress on both OSes for simplicity
    from waitress import serve
    serve(app, host="127.0.0.1", port=5111)

if __name__ == "__main__":
    main()
