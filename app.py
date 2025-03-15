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
    """Save the uploaded avatar file for the user."""
    try:
    if file and allowed_file(file.filename):
            # Create avatars directory if it doesn't exist
            avatar_dir = os.path.join('static', 'avatars')
            os.makedirs(avatar_dir, exist_ok=True)
            
            # Generate a unique filename
            filename = f"{username}_{datetime.now().strftime('%Y%m%d%H%M%S')}.png"
            filepath = os.path.join(avatar_dir, filename)
            
            # Save the file
            file.save(filepath)
            
            # Return the URL path to the avatar
            return os.path.join('avatars', filename)
        return None
        except Exception as e:
            print(f"Error saving avatar: {str(e)}")
    return None

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
    
        print(f"Attempting login for username: {username}")
        
        # Validate credentials
    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    
        # Check if username exists
        user = User.query.filter_by(username=username).first()
        if not user:
            print(f"Login failed: User {username} not found")
        return jsonify({'error': 'Invalid username or password'}), 401
    
        # Check if password hash is valid
        if user.password_hash is None or (isinstance(user.password_hash, bytes) and len(user.password_hash) < 10):
            print(f"Invalid password hash for user {username}, attempting to reset it")
            
            # Special case: if this is the admin user, allow a recovery
            if username == "LilPizzaRo":  # Replace with your admin username
                # Reset admin password to a default
                print(f"Resetting admin password for {username}")
                admin_default_password = "SynthoraAI@2024"  # Set to your default admin password
                user.password_hash = hash_password(admin_default_password)
                db.session.commit()
                
                # Try verification again with the new hash
                if verify_password(password, user.password_hash):
    session['username'] = username
                    print(f"Admin recovery successful for {username}")
                    return jsonify({
                        'message': 'Login successful (password reset)',
                        'username': username,
                        'avatar_url': user.avatar_url,
                        'password_reset': True
                    })
                else:
                    return jsonify({'error': 'Please use the default admin password to login'}), 401
            else:
                return jsonify({'error': 'Your password needs to be reset. Please contact an administrator.'}), 401
        
        # Regular verification for accounts with valid hashes
        if not verify_password(password, user.password_hash):
            print(f"Login failed: Invalid password for {username}")
            return jsonify({'error': 'Invalid username or password'}), 401
        
        # Set session and return success
        session['username'] = username
        print(f"Login successful for {username}")
        return jsonify({
            'message': 'Login successful',
            'username': username,
            'avatar_url': user.avatar_url
        })
    except Exception as e:
        print(f"Login error: {str(e)}")
        traceback.print_exc()  # Add detailed stack trace
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
                'avatar_url': url_for('serve_avatar', username=user.username) if user.avatar_data else None
        })
    return jsonify({'authenticated': False})

@app.route('/auth/update', methods=['POST'])
@login_required
def update_account():
    user = User.query.filter_by(username=session['username']).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    try:
        # Update username if provided
        if 'username' in request.form and request.form['username'] != user.username:
            new_username = request.form['username']
            # Check if username is already taken
            existing_user = User.query.filter_by(username=new_username).first()
            if existing_user and existing_user.id != user.id:
                return jsonify({'error': 'Username already taken'}), 400
            user.username = new_username
        
        # Update password if provided
        if 'current_password' in request.form and 'new_password' in request.form:
            current_password = request.form['current_password']
            new_password = request.form['new_password']
            
            # Verify current password
            if not verify_password(current_password, user.password_hash):
                return jsonify({'error': 'Current password is incorrect'}), 400
            
            # Update password
            user.password_hash = hash_password(new_password)
        
        # Update avatar if provided
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file and file.filename and allowed_file(file.filename):
                # Save avatar
                avatar_url = save_avatar(file, user.username)
                if avatar_url:
                    user.avatar_url = avatar_url
                else:
                    return jsonify({'error': 'Failed to save avatar'}), 500
        
        # Save changes to database
        db.session.commit()
        
        return jsonify({
            'success': True,
            'username': user.username,
            'avatar_url': url_for('serve_avatar', username=user.username) if user.avatar_data else None
        })
    except Exception as e:
        db.session.rollback()
        print(f"Error updating account: {str(e)}")
        return jsonify({'error': f'Failed to update account: {str(e)}'}), 500

@app.route('/generate', methods=['POST'])
@login_required
def generate():
    try:
        data = request.json
        message = data.get('message')
        conversation_id = data.get('conversation_id')
        conversation_history = data.get('conversation_history')
        settings = data.get('settings', {})
        
        if not message:
            return jsonify({'error': 'Message is required'}), 400
        
        # Check what type of conversation history we have
        if not conversation_history:
            # If no conversation history is provided, check if we have a conversation_id
            if conversation_id and not isinstance(conversation_id, str):
                # If conversation_id is not a string, it might be the actual history (for backward compatibility)
                conversation_history = conversation_id
        
        # Ensure conversation_history is well-formatted
        if conversation_history and isinstance(conversation_history, list):
            # Filter out any invalid messages
            conversation_history = [
                msg for msg in conversation_history 
                if isinstance(msg, dict) and 'user_message' in msg and 'synthora_response' in msg
            ]
            
            # Log conversation history for debugging
            print(f"Using conversation history with {len(conversation_history)} messages")
        
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
                        synthora_response=response
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
            'synthora_response': memory.synthora_response,
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

@app.route('/auth/reset-password', methods=['POST'])
@login_required
def reset_user_password():
    """Admin endpoint to reset a user's password"""
    try:
        # Check if current user is an admin
        admin_username = session.get('username')
        if admin_username != 'LilPizzaRo':  # Replace with your admin username
            return jsonify({'error': 'Unauthorized. Admin access required.'}), 403
        
        # Get data from request
        data = request.json
        target_username = data.get('username')
        new_password = data.get('new_password')
        
        if not target_username or not new_password:
            return jsonify({'error': 'Username and new password are required'}), 400
        
        # Find the user
        user = User.query.filter_by(username=target_username).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Reset the password
        user.password_hash = hash_password(new_password)
        db.session.commit()
        
        print(f"Password reset for user {target_username} by admin {admin_username}")
        return jsonify({'message': f'Password for {target_username} has been reset successfully'})
    except Exception as e:
        print(f"Password reset error: {str(e)}")
        traceback.print_exc()
        return jsonify({'error': 'An error occurred during password reset'}), 500

@app.route('/auth/check-password-hashes', methods=['GET'])
@login_required
def check_password_hashes():
    """Admin endpoint to check the health of password hashes"""
    try:
        # Check if current user is an admin
        admin_username = session.get('username')
        if admin_username != 'LilPizzaRo':  # Replace with your admin username
            return jsonify({'error': 'Unauthorized. Admin access required.'}), 403
        
        # Get all users
        users = User.query.all()
        
        # Check each user's password hash
        results = []
        for user in users:
            hash_status = 'valid'
            hash_info = {}
            
            if user.password_hash is None:
                hash_status = 'missing'
            elif isinstance(user.password_hash, str):
                hash_info['type'] = 'string'
                hash_info['length'] = len(user.password_hash)
                if not (user.password_hash.startswith('$2a$') or user.password_hash.startswith('$2b$')):
                    hash_status = 'invalid_format'
            elif isinstance(user.password_hash, bytes):
                hash_info['type'] = 'bytes'
                hash_info['length'] = len(user.password_hash)
                try:
                    prefix = user.password_hash[:4].decode('utf-8', 'ignore')
                    hash_info['prefix'] = prefix
                    if not (prefix.startswith('$2a$') or prefix.startswith('$2b$')):
                        hash_status = 'invalid_format'
                except:
                    hash_status = 'decode_error'
            else:
                hash_info['type'] = str(type(user.password_hash))
                hash_status = 'unknown_type'
            
            results.append({
                'username': user.username,
                'hash_status': hash_status,
                'hash_info': hash_info
            })
        
        return jsonify({
            'message': 'Password hash check completed',
            'total_users': len(users),
            'results': results
        })
    except Exception as e:
        print(f"Password hash check error: {str(e)}")
        traceback.print_exc()
        return jsonify({'error': 'An error occurred during password hash check'}), 500

# Ensure app restarts properly
if __name__ == '__main__':
    print("Starting application in development mode...")
    with app.app_context():
        db.create_all()
        print("Database tables verified at startup")
        # Print number of users in database
        try:
            user_count = User.query.count()
            print(f"Found {user_count} users in database")
        except Exception as e:
            print(f"Error checking users: {e}")
    app.run(debug=True, host='0.0.0.0', port=5000) 

