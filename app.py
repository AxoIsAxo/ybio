import os
import secrets
import re
import bleach
from datetime import datetime, timezone
from flask import Flask, request, render_template, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from markdown import markdown
from dotenv import load_dotenv # To load .env file for local development

# Load environment variables from .env file if it exists (for local dev)
load_dotenv()

# Configuration
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
# --- Database Configuration ---
# Default to SQLite for local development if DATABASE_URL is not set
LOCAL_SQLITE_PATH = os.path.join(BASE_DIR, 'instance', 'pastes.db')
DATABASE_URL = os.environ.get('DATABASE_URL', f'sqlite:///{LOCAL_SQLITE_PATH}')

# Handle Railway's 'postgres://' prefix if using PostgreSQL
if DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

# --- Markdown/Bleach Configuration ---
ALLOWED_EXTENSIONS = ['markdown.extensions.fenced_code', 'markdown.extensions.codehilite', 'markdown.extensions.tables']
BLEACH_ALLOWED_TAGS = set(bleach.sanitizer.ALLOWED_TAGS) | {'p', 'pre', 'code', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'strong', 'em', 'ul', 'ol', 'li', 'a', 'img', 'blockquote', 'hr', 'table', 'thead', 'tbody', 'tr', 'th', 'td', 'span'} # Added span for codehilite
BLEACH_ALLOWED_ATTRIBUTES = {
    **bleach.sanitizer.ALLOWED_ATTRIBUTES,
    'img': ['src', 'alt', 'title'],
    'a': ['href', 'title'],
    'code': ['class'], # Allow class for syntax highlighting (e.g., class="language-python")
    'span': ['class'], # Allow class for syntax highlighting spans
    'pre': [],
    'div': ['class'] # Allow class on divs if codehilite wraps in divs
}

# App Initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(16)) # CRITICAL: Set SECRET_KEY env var in production!
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Ensure instance folder exists for local SQLite DB if used
if app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite:///'):
    try:
        # instance_path is relative to the app's root path if specified like this
        instance_folder = os.path.join(app.root_path, 'instance')
        os.makedirs(instance_folder, exist_ok=True)
    except OSError as e:
        app.logger.error(f"Could not create instance folder at {instance_folder}: {e}")


db = SQLAlchemy(app)

# Models
class Paste(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(80), unique=True, nullable=False, index=True)
    content = db.Column(db.Text, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False) # Increased length for potentially longer hashes
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True), nullable=True, onupdate=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f'<Paste {self.slug}>'

# Helper Functions
def is_safe_slug(slug):
    """Check if the slug contains only allowed characters."""
    return slug and re.match(r'^[a-zA-Z0-9_-]+$', slug) is not None

def generate_unique_slug(length=8):
    """Generate a unique random slug."""
    while True:
        slug = secrets.token_urlsafe(length)
        # Check uniqueness against the database
        with app.app_context(): # Need app context to query DB here
            if not Paste.query.filter_by(slug=slug).first():
                return slug

def render_markdown(content):
    """Render markdown to safe HTML."""
    # Use codehilite options for better styling control if needed
    html = markdown(content, extensions=ALLOWED_EXTENSIONS, extension_configs={
        'markdown.extensions.codehilite': {'css_class': 'codehilite'} # Add a wrapping class
    })
    safe_html = bleach.clean(html, tags=BLEACH_ALLOWED_TAGS, attributes=BLEACH_ALLOWED_ATTRIBUTES)
    return safe_html

# Database initialization command (optional, useful for local setup or first deploy)
@app.cli.command('init-db')
def init_db_command():
    """Creates the database tables."""
    try:
        db.create_all()
        print('Initialized the database.')
    except Exception as e:
        print(f'Error initializing database: {e}')


# Routes
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        content = request.form.get('content')
        password = request.form.get('password')
        custom_slug = request.form.get('custom_slug', '').strip()

        if not content:
            flash('Content cannot be empty.', 'warning')
            return render_template('index.html', content=content, custom_slug=custom_slug) # Keep form data

        if not password:
             flash('Password is required.', 'warning')
             return render_template('index.html', content=content, custom_slug=custom_slug) # Keep form data


        slug_to_use = None
        if custom_slug:
            if not is_safe_slug(custom_slug):
                flash('Custom slug contains invalid characters. Only letters, numbers, hyphens (-), and underscores (_) allowed.', 'warning')
                return render_template('index.html', content=content, custom_slug=custom_slug)
            existing_paste = Paste.query.filter_by(slug=custom_slug).first()
            if existing_paste:
                flash(f'The slug "{custom_slug}" is already taken. Please choose another or leave blank for a random one.', 'warning')
                return render_template('index.html', content=content, custom_slug=custom_slug)
            slug_to_use = custom_slug
        else:
            slug_to_use = generate_unique_slug()

        hashed_password = generate_password_hash(password)

        new_paste = Paste(
            slug=slug_to_use,
            content=content,
            password_hash=hashed_password
        )
        try:
            db.session.add(new_paste)
            db.session.commit()
            flash(f'Paste created successfully! Access it at /{slug_to_use}', 'success')
            return redirect(url_for('view_paste', slug=slug_to_use))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error creating paste: {e}")
            flash('An error occurred while creating the paste. Please try again.', 'danger')
            return render_template('index.html', content=content, custom_slug=custom_slug)


    return render_template('index.html')

@app.route('/<string:slug>', methods=['GET'])
def view_paste(slug):
    paste = Paste.query.filter_by(slug=slug).first()
    if not paste:
        abort(404) # Will trigger the 404 error handler

    rendered_content = render_markdown(paste.content)
    return render_template('view_paste.html', paste=paste, rendered_content=rendered_content)

@app.route('/<string:slug>/edit', methods=['GET', 'POST'])
def edit_paste(slug):
    # Use first_or_404 for cleaner handling of not found pastes
    paste = Paste.query.filter_by(slug=slug).first_or_404()

    if request.method == 'POST':
        new_content = request.form.get('content')
        password = request.form.get('password')

        if not new_content:
             flash('Content cannot be empty.', 'warning')
             # Pass current slug and attempted content back to template
             return render_template('edit_paste.html', slug=slug, current_content=new_content)

        if not password:
            flash('Password is required to save changes.', 'warning')
            # Pass current slug and attempted content back to template
            return render_template('edit_paste.html', slug=slug, current_content=new_content)


        if check_password_hash(paste.password_hash, password):
            paste.content = new_content
            # updated_at is handled by onupdate= in the model definition
            try:
                db.session.commit()
                flash('Paste updated successfully!', 'success')
                return redirect(url_for('view_paste', slug=slug))
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Error updating paste {slug}: {e}")
                flash('An error occurred while updating the paste. Please try again.', 'danger')
                return render_template('edit_paste.html', slug=slug, current_content=new_content)

        else:
            flash('Incorrect password.', 'danger')
            # Re-render edit form, keeping the attempted new content
            return render_template('edit_paste.html', slug=slug, current_content=new_content)

    # For GET request, just show the edit form with current content from DB
    return render_template('edit_paste.html', slug=slug, current_content=paste.content)

# Error Handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    # Log the error if possible
    app.logger.error(f"Internal Server Error: {e}")
    # You might want a dedicated 500.html template
    return "<h1>Internal Server Error</h1><p>Something went wrong.</p>", 500


# --- Template Files (No changes needed from previous versions) ---

# 4. `templates/base.html`
# 5. `templates/index.html`
# 6. `templates/view_paste.html` (Using the simplified version you requested)
# 7. `templates/edit_paste.html`
# 8. `templates/404.html`

# Keep these files exactly as they were in the previous steps.
# For clarity, here's the simplified `view_paste.html` again: