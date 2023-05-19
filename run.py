from app import create_app, db
from app.auth.models import *
app = create_app()


@app.shell_context_processor
def make_shell_context():
    return {
        'db': db,
        'Users': Users,
    }


if __name__ == '__main__':
    app.run(debug=True)
