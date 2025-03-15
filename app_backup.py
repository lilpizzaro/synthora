from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import bcrypt
import traceback
from functools import wraps
import asyncio
import google.generativeai as genai

# Define allowed file extensions for uploads
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# Flask app setup
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'development-key')

# Fix database URL for PostgreSQL on Render
database_url = os.environ.get('DATABASE_URL')
is_prod = os.environ.get('RENDER', False)

# Database configuration
if database_url and database_url.startswith('postgres://'):
    # Fix the PostgreSQL URL for SQLAlchemy
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    print(f"Using PostgreSQL database at: {database_url}")
elif is_prod:
    # If on Render but no database URL, use a folder that persists
    db_path = os.path.join('/tmp', 'synthora.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    print(f"Using SQLite database at: {db_path}")
else:
    # Local development - use SQLite
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///synthora.db'
    print("Using local SQLite database")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_avatar(file, username):
    # Implementation of save_avatar
    pass

def hash_password(password):
    # Implementation of hash_password
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(plain_password, hashed_password):
    try:
        # Log debugging information
        print(f"Verifying password: Type of hashed_password = {type(hashed_password)}")
        
        # Ensure hashed_password is bytes
        if isinstance(hashed_password, str):
            hashed_password = hashed_password.encode('utf-8')
        
        # Ensure plain_password is properly encoded
        if isinstance(plain_password, str):
            plain_password = plain_password.encode('utf-8')
            
        # Check if the hash appears to be valid
        if not hashed_password.startswith(b'$2a$') and not hashed_password.startswith(b'$2b$'):
            print(f"Invalid hash format, doesn't start with $2a$ or $2b$: {hashed_password[:20]}")
            return False
            
        # Verify the password
        return bcrypt.checkpw(plain_password, hashed_password)
    except ValueError as e:
        print(f"Password verification error: {str(e)}")
        print(f"Hash value (first 20 chars): {str(hashed_password)[:20] if hashed_password else 'None'}")
        # If there's an error with the hash, authentication fails
        return False
    except Exception as e:
        print(f"Unexpected error during password verification: {str(e)}")
        return False

# User model
class User(db.Model):
    __tablename__ = 'users'  # Explicitly set table name to avoid SQLite/PostgreSQL naming issues
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    avatar_url = db.Column(db.String(200))
    avatar_data = db.Column(db.LargeBinary)
    avatar_content_type = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    email = db.Column(db.String(120), unique=True)
    reset_token = db.Column(db.String(100), unique=True)
    reset_token_expiry = db.Column(db.DateTime)
    memories = db.relationship('Memory', backref='user', lazy=True)
    
    def generate_reset_token(self):
        # Implementation of generate_reset_token
        pass
        
    def verify_reset_token(self, token):
        # Implementation of verify_reset_token
        pass
        
    def clear_reset_token(self):
        # Implementation of clear_reset_token
        pass

# Memory model
class Memory(db.Model):
    __tablename__ = 'memories'  # Explicitly set table name
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user_message = db.Column(db.Text, nullable=False)
    synthora_response = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Initialize database on startup (ensures tables exist)
with app.app_context():
    try:
        # Drop existing tables in development if needed
        # db.drop_all()  # Uncomment if you need to reset the database structure
        
        # Create all tables
        db.create_all()
        print("Database tables created successfully")
        
        # Check if any users exist, if not create a default one
        if User.query.count() == 0:
            print("No users found, creating default user")
            default_password_hash = hash_password("SynthoraAdmin2024")
            default_user = User(
                username="admin",
                password_hash=default_password_hash
            )
            db.session.add(default_user)
            db.session.commit()
            print("Default user 'admin' created successfully")
    except Exception as e:
        print(f"Error creating database tables: {str(e)}")
        traceback.print_exc()

# Setup Gemini AI
try:
    # First try to get the API key from Render secrets
    with open('/etc/secrets/GOOGLE_API_KEY', 'r') as secret_file:
        GOOGLE_API_KEY = secret_file.read().strip()
except (FileNotFoundError, IOError):
    # Fall back to environment variable if not on Render
    GOOGLE_API_KEY = os.environ.get('GOOGLE_API_KEY')
    
    # TEMPORARY: Hard-coded API key as fallback for local development only
    # WARNING: REMOVE BEFORE COMMITTING TO PRODUCTION
    if not GOOGLE_API_KEY:
        GOOGLE_API_KEY = 'AIzaSyB0MmJjgLLRDCSs89VkUTGRLLCeoP0djEc'
        print("WARNING: Using temporary hard-coded API key. DO NOT USE IN PRODUCTION.")

if not GOOGLE_API_KEY:
    print("WARNING: No Google API key found. AI functionality will not work.")

genai.configure(api_key=GOOGLE_API_KEY)
model = genai.GenerativeModel('gemini-2.0-flash')

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

# AI response generation
async def get_ai_response(message, conversation_history=None, settings=None):
    try:
        # Default settings
        temperature = 0.7
        max_tokens = 500
        personality = 'helpful'
        
        # Apply provided settings if any
        if settings:
            temperature = float(settings.get('temperature', temperature))
            max_tokens = int(settings.get('max_tokens', max_tokens))
            personality = settings.get('personality', personality)
        
        # Initialize context
        context = ""
        
        # Process conversation history
        if conversation_history:
            # If it's a list of messages, format them properly
            if isinstance(conversation_history, list):
                for msg in conversation_history:
                    # If it's a dictionary, extract user_message and synthora_response
                    if isinstance(msg, dict):
                        context += f"User: {msg.get('user_message', '')}\nSynthora: {msg.get('synthora_response', '')}\n\n"
            else:
                # If it's a string (conversation_id), just use it as reference
                print(f"Using conversation ID: {conversation_history}")
        
        # Select personality prompt based on setting
        personality_prompts = {
            'helpful': "You are Synthora, a friendly and helpful AI companion. You have a playful personality and love to help people with their problems. You speak in a cheerful manner. You're knowledgeable and always try to provide accurate and helpful information.",
            'formal': "You are Synthora, a professional and formal AI assistant. You provide clear, accurate information in a business-like manner. You avoid using casual language, focusing instead on delivering precise, well-structured responses.",
            'enthusiastic': "You are Synthora, an EXTREMELY enthusiastic and playful AI! You LOVE to use exclamation marks! You're super friendly and energetic in all your responses! You use lots of emojis and speak with great enthusiasm!",
            'concise': "You are Synthora, a direct and concise AI assistant. Keep all responses brief and to the point. Avoid unnecessary details. Provide just the essential information in as few words as possible. MAINTAIN CONTEXT from previous messages."
        }
        
        # Get the appropriate system context
        system_context = personality_prompts.get(personality, personality_prompts['helpful'])
        
        # Prepare the full prompt
        full_prompt = f"{system_context}\n\nConversation history:\n{context}\n\nUser: {message}\nSynthora:"
        
        # Configure generation parameters
        generation_config = {
            'temperature': temperature,
            'max_output_tokens': max_tokens,
        }
        
        # Get response from Gemini with settings
        response = await asyncio.to_thread(
            model.generate_content,
            full_prompt,
            generation_config=generation_config
        )
        
        # Clean and return the response
        return response.text.strip()
    except Exception as e:
        print(f"Error getting AI response: {str(e)}")
        return "Quack! Sorry, I'm having trouble thinking right now. Could you try again?"

# Main routes
@app.route('/')
def index():
    # Implementation of index route
    return render_template('index.html')

# Login page route
@app.route('/auth/login-page')
def login_page():
    return render_template('login.html')

# Signup page route
@app.route('/auth/signup-page')
def signup_page():
    return render_template('signup.html')

# Auth routes with fixed indentation
@app.route('/auth/signup', methods=['POST'])
def signup():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
    
        # Validate input
        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400
    
        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({'error': 'Username already exists'}), 400
    
        # Hash password and create user
        password_hash = hash_password(password)
