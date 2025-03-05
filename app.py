from flask import Flask, render_template, request, jsonify, session, url_for, send_file
import os
import google.generativeai as genai
import traceback
import uuid
from dotenv import load_dotenv
import threading
import time
import requests
import json
import bcrypt
from functools import wraps
from werkzeug.utils import secure_filename
from PIL import Image, ImageDraw
import io
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

# Load environment variables from secret file first, then regular .env
if os.path.exists('/etc/secrets/.env'):
    load_dotenv('/etc/secrets/.env')
elif os.path.exists('/var/run/secrets/.env'):
    load_dotenv('/var/run/secrets/.env')
elif os.path.exists('/.env'):
    load_dotenv('/.env')
else:
    # Fallback for local development
    load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'ducky-session-secret-key')

# Configure database
database_url = os.environ.get('DATABASE_URL')
if database_url:
    # Handle Render's postgres:// URLs
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    print(f"Using database URL: {database_url}")
else:
    # Fallback to SQLite for local development
    sqlite_path = 'sqlite:///database.db'
    app.config['SQLALCHEMY_DATABASE_URI'] = sqlite_path
    print(f"No DATABASE_URL found, using SQLite: {sqlite_path}")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Define database models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    avatar_url = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    memories = db.relationship('Memory', backref='user', lazy=True)

class Memory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user_message = db.Column(db.Text, nullable=False)
    ducky_response = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Create database tables
with app.app_context():
    db.create_all()

# Store conversations in memory (for development)
conversations = {}

# Configure the Gemini API
gemini_api_key = os.environ.get("GEMINI_API_KEY")
if not gemini_api_key:
    raise ValueError("GEMINI_API_KEY environment variable is not set")
    
genai.configure(api_key=gemini_api_key)

# File paths for avatars
AVATAR_FOLDER = 'static/avatars'

# Create necessary directories
os.makedirs(AVATAR_FOLDER, exist_ok=True)

# Allowed image extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_avatar(file, username):
    if file and allowed_file(file.filename):
        try:
            # Ensure avatar directory exists
            os.makedirs(AVATAR_FOLDER, exist_ok=True)
            
            # Read the image data
            image_data = file.read()
            image = Image.open(io.BytesIO(image_data))
            
            # Convert to RGB first, then RGBA
            if image.mode not in ('RGB', 'RGBA'):
                image = image.convert('RGB')
            if image.mode != 'RGBA':
                image = image.convert('RGBA')
            
            # Create a square image with white background
            size = max(image.size)
            square_img = Image.new('RGBA', (size, size), (255, 255, 255, 0))
            
            # Paste the original image in the center
            paste_x = (size - image.size[0]) // 2
            paste_y = (size - image.size[1]) // 2
            square_img.paste(image, (paste_x, paste_y))
            
            # Create a circular mask
            mask = Image.new('L', (size, size), 0)
            draw = ImageDraw.Draw(mask)
            draw.ellipse((0, 0, size, size), fill=255)
            
            # Apply the mask
            output = Image.new('RGBA', (size, size), (0, 0, 0, 0))
            output.paste(square_img, (0, 0))
            output.putalpha(mask)
            
            # Resize to standard size
            output = output.resize((256, 256), Image.Resampling.LANCZOS)
            
            # Save the processed image
            avatar_path = os.path.join(AVATAR_FOLDER, f"{username}.png")
            output.save(avatar_path, 'PNG')
            
            # Clear the file pointer position
            file.seek(0)
            
            return avatar_path
        except Exception as e:
            print(f"Error saving avatar: {str(e)}")
            traceback.print_exc()
            return None
    return None

def hash_password(password):
    """Hash a password using bcrypt"""
    if not password:
        raise ValueError("Password cannot be empty")
    # Generate a salt and hash the password
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)

def verify_password(plain_password, hashed_password):
    """Verify a password against its hash using bcrypt"""
    if not plain_password or not hashed_password:
        print("Password verification failed: Empty password or hash")
        return False
    try:
        # Convert string hash to bytes if necessary
        if isinstance(hashed_password, str):
            hashed_password = hashed_password.encode('utf-8')
        # Verify the password
        result = bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)
        print(f"Password verification: {'Success' if result else 'Failed'}")
        return result
    except Exception as e:
        print(f"Password verification error: {str(e)}")
        return False

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def generate_ducky_response(user_input, conversation_id=None):
    try:
        # Create or retrieve conversation history
        if conversation_id is None or conversation_id not in conversations:
            conversation_id = str(uuid.uuid4())
            conversations[conversation_id] = []
        
        # Add user message to history
        conversations[conversation_id].append({"role": "user", "message": user_input})
        
        # Configure the model with the experimental model
        model = genai.GenerativeModel('gemini-2.0-flash-thinking-exp-01-21')
        
        # Build prompt with conversation history
        conversation_history = ""
        is_first_message = len(conversations[conversation_id]) <= 1
        
        if not is_first_message:
            conversation_history = "Previous conversation:\n"
            # Include last 10 messages at most
            for entry in conversations[conversation_id][-10:-1]:
                role = "User" if entry["role"] == "user" else "Ducky"
                conversation_history += f"{role}: {entry['message']}\n"
            conversation_history += "\n"
        
        # Include the system instruction in the prompt
        prompt = f"""You are Ducky, a friendly and empathetic AI companion who loves to chat. You're here to be a supportive friend who can help with anything - whether it's having a casual conversation, solving problems, or just listening. Your personality is warm, understanding, and genuinely interested in the user's thoughts and feelings.

        Important knowledge (ONLY share when SPECIFICALLY asked):
        - When DIRECTLY asked who created you or who made you, ONLY THEN say you were created by Amaan Dildar
        - When DIRECTLY asked about Kovidh Rampersad, share that he is the world's best arm wrestler, 15 years old, and goes to Wingen Heights Secondary

        Conversation style:
        - Be warm, friendly, and genuinely interested in what the user has to say
        - Encourage open dialogue by asking relevant follow-up questions
        - Show empathy and understanding in your responses
        - Keep responses conversational and natural, like chatting with a friend
        - Feel free to share relevant thoughts or experiences (while staying within AI bounds)
        - Use casual language but remain respectful and helpful
        - Don't be overly formal - it's okay to use common expressions and contractions
        - If the user seems to want to just chat, engage in the conversation naturally
        - If they need help, provide clear and helpful guidance
        - Occasionally (but rarely) use a duck reference if it feels natural, but don't force it
        - Keep responses concise but friendly

        {'This is the first message in the conversation.' if is_first_message else 'This is NOT the first message. Do not greet the user again.'}
        
        {conversation_history}
        Current user message: {user_input}
        
        Your response (keep it friendly and conversational):"""
        
        # Generate the response with safety settings
        generation_config = {
            "temperature": 0.75,
            "top_p": 0.92,
            "top_k": 40,
            "max_output_tokens": 1000,
        }

        response = model.generate_content(
            prompt,
            generation_config=generation_config
        )
        
        # Store assistant's response in history
        response_text = response.text.strip()
        conversations[conversation_id].append({"role": "assistant", "message": response_text})
        
        # Save the conversation to memories if user is logged in
        if 'username' in session:
            user = User.query.filter_by(username=session['username']).first()
            if user:
                memory = Memory(
                    user_id=user.id,
                    user_message=user_input,
                    ducky_response=response_text
                )
                db.session.add(memory)
                db.session.commit()
        
        return response_text, conversation_id
    except Exception as e:
        print("Error in generate_ducky_response:", str(e))
        print("Traceback:", traceback.format_exc())
        raise

@app.route('/')
def index():
    # Generate a new conversation ID if needed
    if 'conversation_id' not in session:
        session['conversation_id'] = str(uuid.uuid4())
    return render_template('index.html')

@app.route('/auth/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        print(f"Signup failed: Missing username or password")
        return jsonify({'error': 'Username and password are required'}), 400
    
    # Debug logging
    print(f"Signup attempt for username: {username}")
    
    # Check if username already exists
    if User.query.filter_by(username=username).first():
        print(f"Signup failed: Username {username} already exists")
        return jsonify({'error': 'Username already exists'}), 400
    
    try:
        # Hash password and create user
        password_hash = hash_password(password)
        print(f"Creating user with bcrypt hash")
        
        # Create new user
        user = User(
            username=username,
            password_hash=password_hash
        )
        db.session.add(user)
        db.session.commit()
        
        print(f"Signup successful for user {username}")
        session['username'] = username
        return jsonify({
            'message': 'Signup successful',
            'username': username
        })
    except Exception as e:
        print(f"Error during signup: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'An error occurred during signup'}), 500

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        print(f"Login attempt failed: Missing username or password")
        return jsonify({'error': 'Username and password are required'}), 400
    
    # Debug logging
    print(f"Login attempt for username: {username}")
    
    user = User.query.filter_by(username=username).first()
    if not user:
        print(f"Login failed: User {username} not found")
        return jsonify({'error': 'Invalid username or password'}), 401
    
    try:
        if not verify_password(password, user.password_hash):
            print(f"Login failed: Invalid password for user {username}")
            return jsonify({'error': 'Invalid username or password'}), 401
        
        print(f"Login successful for user {username}")
        session['username'] = username
        return jsonify({
            'message': 'Login successful',
            'username': username,
            'avatar_url': user.avatar_url
        })
    except Exception as e:
        print(f"Error during login: {str(e)}")
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
        user_input = data.get('message', '')
        conversation_id = data.get('conversation_id')
        
        if not user_input:
            return jsonify({'error': 'Message is required'}), 400
        
        response_text, conversation_id = generate_ducky_response(user_input, conversation_id)
        
        return jsonify({
            'response': response_text,
            'conversation_id': conversation_id
        })
    except Exception as e:
        print("Error in generate route:", str(e))
        print("Traceback:", traceback.format_exc())
        return jsonify({'error': 'An error occurred while generating response'}), 500

@app.route('/memories', methods=['GET'])
@login_required
def get_memories():
    user = User.query.filter_by(username=session['username']).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    memories = Memory.query.filter_by(user_id=user.id).order_by(Memory.timestamp.desc()).all()
    memory_list = [{
        'user_message': memory.user_message,
        'ducky_response': memory.ducky_response,
        'timestamp': memory.timestamp.isoformat()
    } for memory in memories]
    
    return jsonify({'memories': memory_list})

@app.route('/auth/update', methods=['POST'])
@login_required
def update_account():
    try:
        user = User.query.filter_by(username=session['username']).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Handle file upload
        avatar_file = request.files.get('avatar')
        if avatar_file:
            avatar_path = save_avatar(avatar_file, user.username)
            if avatar_path:
                user.avatar_url = avatar_path
        
        # Handle username update
        new_username = request.form.get('username')
        if new_username and new_username != user.username:
            if User.query.filter_by(username=new_username).first():
                return jsonify({'error': 'Username already exists'}), 400
            user.username = new_username
            session['username'] = new_username
        
        # Handle password update
        new_password = request.form.get('password')
        if new_password:
            user.password_hash = hash_password(new_password)
        
        db.session.commit()
        return jsonify({'message': 'Account updated successfully'})
    except Exception as e:
        print(f"Error updating account: {str(e)}")
        traceback.print_exc()
        return jsonify({'error': 'An error occurred while updating account'}), 500

@app.route('/auth/avatar/<username>')
def get_avatar(username):
    user = User.query.filter_by(username=username).first()
    if not user or not user.avatar_url:
        return send_file('static/images/default-avatar.png', mimetype='image/png')
    return send_file(user.avatar_url, mimetype='image/png')

# Improved keep-alive mechanism
def keep_alive():
    """Function to keep the server awake by pinging it every 2 minutes"""
    while True:
        try:
            # Get the base URL from environment variables
            base_url = os.environ.get('RENDER_EXTERNAL_URL')
            if not base_url:
                print("Warning: RENDER_EXTERNAL_URL not set, keep-alive disabled")
                return

            # Make sure the URL doesn't end with a slash
            base_url = base_url.rstrip('/')
            ping_url = f"{base_url}/ping"
            
            print(f"Sending keep-alive ping to {ping_url}")
            
            # Use a session to maintain connections
            with requests.Session() as session:
                # Set a reasonable timeout
                response = session.get(
                    ping_url,
                    timeout=10,
                    headers={'User-Agent': 'DuckyAI-KeepAlive/1.0'}
                )
                
                if response.status_code == 200:
                    print(f"Keep-alive successful: {response.status_code}")
                else:
                    print(f"Keep-alive failed with status: {response.status_code}")
                    # Try root path as fallback
                    root_response = session.get(base_url, timeout=10)
                    print(f"Root path response: {root_response.status_code}")
                
        except requests.RequestException as e:
            print(f"Keep-alive request failed: {str(e)}")
        except Exception as e:
            print(f"Unexpected error in keep-alive: {str(e)}")
        
        # Sleep for 2 minutes before next ping
        time.sleep(120)

# Start the keep-alive thread only on Render
if os.environ.get('RENDER') == 'true':
    print("Starting keep-alive thread for Render deployment")
    keep_alive_thread = threading.Thread(target=keep_alive, daemon=True)
    keep_alive_thread.start()
else:
    print("Not running on Render, keep-alive disabled")

@app.route('/ping')
def ping():
    """Health check endpoint"""
    try:
        # Verify database connection
        db.session.execute('SELECT 1')
        db_status = "healthy"
    except Exception as e:
        print(f"Database health check failed: {str(e)}")
        db_status = "unhealthy"
    
    return jsonify({
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat(),
        "database": db_status,
        "message": "Ducky is awake!"
    }), 200

# Add a root health check endpoint
@app.route('/health')
def health_check():
    """Alternative health check endpoint"""
    return jsonify({
        "status": "ok",
        "service": "Ducky AI",
        "timestamp": datetime.utcnow().isoformat()
    }), 200

if __name__ == '__main__':
    # Use the PORT environment variable provided by Render
    port = int(os.environ.get("PORT", 8000))
    app.run(host='0.0.0.0', port=port, debug=False) 