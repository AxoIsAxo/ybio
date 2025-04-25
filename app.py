import os
import secrets
import re
import bleach
from datetime import datetime, timezone
from flask import Flask, request, render_template, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from markdown import markdown

# Configuration
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, 'instance', 'pastes.db')
ALLOWED_EXTENSIONS = ['markdown.extensions.fenced_code', 'markdown.extensions.codehilite', 'markdown.extensions.tables']
BLEACH_ALLOWED_TAGS = set(bleach.sanitizer.ALLOWED_TAGS) | {'p', 'pre', 'code', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'strong', 'em', 'ul', 'ol', 'li', 'a', 'img', 'blockquote', 'hr', 'table', 'thead', 'tbody', 'tr', 'th', 'td'}
BLEACH_ALLOWED_ATTRIBUTES = {**bleach.sanitizer.ALLOWED_ATTRIBUTES, 'img': ['src', 'alt', 'title'], 'a': ['href', 'title'], 'code': ['class'], 'pre': []} # Allow class for syntax highlighting

# App Initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(16)) # Use env var in production!
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DATABASE_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Ensure instance folder exists
try:
    os.makedirs(app.instance_path)
except OSError:
    pass

db = SQLAlchemy(app)

# Models
class Paste(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(80), unique=True, nullable=False, index=True)
    content = db.Column(db.Text, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, nullable=True, onupdate=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f'<Paste {self.slug}>'

# Create database tables if they don't exist
with app.app_context():
    db.create_all()

# Helper Functions
def is_safe_slug(slug):
    """Check if the slug contains only allowed characters."""
    return re.match(r'^[a-zA-Z0-9_-]+$', slug) is not None

def generate_unique_slug(length=8):
    """Generate a unique random slug."""
    while True:
        slug = secrets.token_urlsafe(length)
        if not Paste.query.filter_by(slug=slug).first():
            return slug

def render_markdown(content):
    """Render markdown to safe HTML."""
    html = markdown(content, extensions=ALLOWED_EXTENSIONS)
    safe_html = bleach.clean(html, tags=BLEACH_ALLOWED_TAGS, attributes=BLEACH_ALLOWED_ATTRIBUTES)
    return safe_html

# Routes
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        content = request.form.get('content')
        password = request.form.get('password')
        custom_slug = request.form.get('custom_slug', '').strip()

        if not content or not password:
            flash('Content and password are required.', 'warning')
            return render_template('index.html')

        slug_to_use = None
        if custom_slug:
            if not is_safe_slug(custom_slug):
                flash('Custom slug contains invalid characters. Only letters, numbers, hyphens (-), and underscores (_) allowed.', 'warning')
                return render_template('index.html')
            existing_paste = Paste.query.filter_by(slug=custom_slug).first()
            if existing_paste:
                flash(f'The slug "{custom_slug}" is already taken. Please choose another or leave blank for a random one.', 'warning')
                return render_template('index.html')
            slug_to_use = custom_slug
        else:
            slug_to_use = generate_unique_slug()

        hashed_password = generate_password_hash(password)

        new_paste = Paste(
            slug=slug_to_use,
            content=content,
            password_hash=hashed_password
        )
        db.session.add(new_paste)
        db.session.commit()

        flash(f'Paste created successfully! Access it at /{slug_to_use}', 'success')
        return redirect(url_for('view_paste', slug=slug_to_use))

    return render_template('index.html')

@app.route('/<string:slug>', methods=['GET'])
def view_paste(slug):
    paste = Paste.query.filter_by(slug=slug).first()
    if not paste:
        abort(404)

    rendered_content = render_markdown(paste.content)
    return render_template('view_paste.html', paste=paste, rendered_content=rendered_content)

@app.route('/<string:slug>/edit', methods=['GET', 'POST'])
def edit_paste(slug):
    paste = Paste.query.filter_by(slug=slug).first()
    if not paste:
        abort(404)

    if request.method == 'POST':
        new_content = request.form.get('content')
        password = request.form.get('password')

        if not new_content or not password:
            flash('Content and password are required to save changes.', 'warning')
            return render_template('edit_paste.html', slug=slug, current_content=new_content or paste.content) # Show entered content if validation fails

        if check_password_hash(paste.password_hash, password):
            paste.content = new_content
            # updated_at is handled by onupdate in the model
            db.session.commit()
            flash('Paste updated successfully!', 'success')
            return redirect(url_for('view_paste', slug=slug))
        else:
            flash('Incorrect password.', 'danger')
            # Re-render edit form, keeping the attempted new content
            return render_template('edit_paste.html', slug=slug, current_content=new_content)

    # For GET request, just show the edit form with current content
    return render_template('edit_paste.html', slug=slug, current_content=paste.content)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# Run the app
if __name__ == '__main__':
    # For development:
    app.run(debug=True)
    # For production, use a proper WSGI server like Gunicorn or uWSGI:
    # gunicorn -w 4 app:app