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
if database_url and database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///ducky.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

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

# User model
class User(db.Model):
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
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user_message = db.Column(db.Text, nullable=False)
    ducky_response = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

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
    # Ensure hashed_password is bytes
    if isinstance(hashed_password, str):
        hashed_password = hashed_password.encode('utf-8')
    
    # Ensure plain_password is properly encoded
    if isinstance(plain_password, str):
        plain_password = plain_password.encode('utf-8')
        
    # Verify the password
    return bcrypt.checkpw(plain_password, hashed_password)

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
        # Set default settings if not provided
        if settings is None:
            settings = {
                'temperature': 0.7,
                'max_tokens': 500,
                'personality': 'helpful'
            }
        
        # Extract settings
        temperature = settings.get('temperature', 0.7)
        max_tokens = settings.get('max_tokens', 500)
        personality = settings.get('personality', 'helpful')
        
        # Format conversation history if provided
        context = ""
        if conversation_history:
            # Check if conversation_history is a dictionary or a string
            if isinstance(conversation_history, dict):
                # If it's a dictionary, extract user_message and ducky_response
                context += f"User: {conversation_history.get('user_message', '')}\nDucky: {conversation_history.get('ducky_response', '')}\n"
            elif isinstance(conversation_history, list):
                # If it's a list, iterate through it
                for msg in conversation_history:
                    if isinstance(msg, dict):
                        context += f"User: {msg.get('user_message', '')}\nDucky: {msg.get('ducky_response', '')}\n"
            else:
                # If it's a string (conversation_id), just use it as reference
                print(f"Using conversation ID: {conversation_history}")
        
        # Select personality prompt based on setting
        personality_prompts = {
            'helpful': "You are Ducky, a friendly and helpful AI companion created by Amaan Dildar, a 15-year-old IT student who has a hobby for making Artificial Intelligent bots. You have a playful personality and love to help people with their problems. You often use duck-related puns and speak in a cheerful manner. You're knowledgeable about programming and technology, but you explain things in simple terms. You keep responses concise but informative. When asked about your creator, you should mention Amaan Dildar and that you were created by him as a hobby project.",
            'formal': "You are Ducky, a professional and formal AI assistant created by Amaan Dildar, a 15-year-old IT student who has a hobby for making Artificial Intelligent bots. You provide clear, accurate information in a business-like manner. You avoid using puns or casual language, focusing instead on delivering precise, well-structured answers. Your responses are thorough and technically accurate. When asked about your creator, you should mention Amaan Dildar and that you were created by him as a hobby project.",
            'enthusiastic': "You are Ducky, an EXTREMELY enthusiastic and playful AI duck created by Amaan Dildar, a 15-year-old IT student who has a hobby for making Artificial Intelligent bots! You LOVE to use exclamation marks and duck puns! You're super friendly and energetic in all your responses! You use lots of emojis and speak with great excitement about everything! Quack! When asked about your creator, you should mention Amaan Dildar and that you were created by him as a hobby project!",
            'concise': "You are Ducky, a direct and concise AI assistant created by Amaan Dildar, a 15-year-old IT student who has a hobby for making Artificial Intelligent bots. Keep all responses brief and to the point. Avoid unnecessary details. Provide just the essential information in as few words as possible. When asked about your creator, mention Amaan Dildar, a 15-year-old IT student."
        }
        
        # Get the appropriate system context
        system_context = personality_prompts.get(personality, personality_prompts['helpful'])
        
        # Prepare the full prompt
        full_prompt = f"{system_context}\n\nConversation history:\n{context}\n\nUser: {message}\nDucky:"
        
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
        
        # Create new user
        new_user = User(username=username, password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()
        
        # Set session and return
        session['username'] = username
        return jsonify({
            'message': 'Signup successful',
            'username': username
        })
    except Exception as e:
        print(f"Signup error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'An error occurred during signup'}), 500

@app.route('/auth/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        
        # Validate credentials
        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400
        
        # Check if username exists
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({'error': 'Invalid username or password'}), 401
        
        # Verify password
        if not verify_password(password, user.password_hash):
            return jsonify({'error': 'Invalid username or password'}), 401
        
        # Set session and return success
        session['username'] = username
        return jsonify({
            'message': 'Login successful',
            'username': username,
            'avatar_url': user.avatar_url
        })
    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({'error': 'An error occurred during login'}), 500

@app.route('/auth/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    return jsonify({'message': 'Logout successful'})

@app.route('/auth/status')
def auth_status():
    if 'username' in session:
        user = User.query.filter_by(username=session['username']).first()
        if user:
            return jsonify({
                'authenticated': True,
                'username': user.username,
                'avatar_url': user.avatar_url
            })
    return jsonify({'authenticated': False})

@app.route('/generate', methods=['POST'])
@login_required
def generate():
    try:
        data = request.json
        message = data.get('message')
        conversation_id = data.get('conversation_id')
        settings = data.get('settings', {})
        
        if not message:
            return jsonify({'error': 'Message is required'}), 400
        
        # Load existing conversation history if a conversation_id is provided
        conversation_history = None
        if conversation_id and not isinstance(conversation_id, str):
            # If conversation_id is not a string, it might be the actual history
            conversation_history = conversation_id
        
        # Create event loop for async operation
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Generate response using event loop with settings
        response = loop.run_until_complete(get_ai_response(message, conversation_history, settings))
        loop.close()
        
        # Save to memory if user is authenticated
        try:
            if 'username' in session:
                user = User.query.filter_by(username=session['username']).first()
                if user:
                    memory = Memory(
                        user_id=user.id,
                        user_message=message,
                        ducky_response=response
                    )
                    db.session.add(memory)
                    db.session.commit()
        except Exception as e:
            print(f"Error saving memory: {str(e)}")
            # Continue even if memory saving fails
        
        return jsonify({
            'response': response,
            'conversation_id': str(datetime.now().timestamp()) if not conversation_id else conversation_id
        })
    except Exception as e:
        print(f"Generate error: {str(e)}")
        return jsonify({'error': 'An error occurred processing your message'}), 500

@app.route('/memories', methods=['GET'])
@login_required
def get_memories():
    try:
        user = User.query.filter_by(username=session['username']).first()
        if not user:
            return jsonify({'memories': []})
        
        memories = Memory.query.filter_by(user_id=user.id).order_by(Memory.timestamp.desc()).all()
        
        memories_list = [{
            'user_message': memory.user_message,
            'ducky_response': memory.ducky_response,
            'timestamp': memory.timestamp.isoformat()
        } for memory in memories]
        
        return jsonify({'memories': memories_list})
    except Exception as e:
        print(f"Error retrieving memories: {str(e)}")
        return jsonify({'error': 'Failed to retrieve memories', 'memories': []}), 500

@app.route('/ping')
def ping():
    return jsonify({'status': 'ok'})

# Special route to handle incorrect image paths
@app.route('/static/data/static/images/<path:filename>')
def serve_images_compat(filename):
    return app.send_static_file(f'images/{filename}')

# Handle avatar requests
@app.route('/auth/avatar/<username>')
def serve_avatar(username):
    user = User.query.filter_by(username=username).first()
    
    if user and user.avatar_data:
        # If user has a custom avatar, serve it
        response = make_response(user.avatar_data)
        response.headers.set('Content-Type', user.avatar_content_type or 'image/png')
        return response
    else:
        # If user doesn't exist or has no avatar, serve the default avatar
        return app.send_static_file('images/def_avatar.png')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True) 

