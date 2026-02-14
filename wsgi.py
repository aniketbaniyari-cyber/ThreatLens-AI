from app import create_app

# Production ke liye Gunicorn entrypoint (Render start: gunicorn wsgi:app)
app = create_app()
