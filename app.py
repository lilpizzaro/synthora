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
import hashlib
from functools import wraps
from werkzeug.utils import secure_filename
from PIL import Image, ImageDraw
import io

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

# Store conversations in memory (for development)
conversations = {}

# Configure the Gemini API
gemini_api_key = os.environ.get("GEMINI_API_KEY")
if not gemini_api_key:
    raise ValueError("GEMINI_API_KEY environment variable is not set")
    
genai.configure(api_key=gemini_api_key)

# File paths for user data and avatars
USERS_FILE = 'data/users.json'
MEMORIES_FILE = 'data/memories.json'
AVATAR_FOLDER = 'static/avatars'

# Create necessary directories
os.makedirs('data', exist_ok=True)
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
            
            # Open and resize image
            image = Image.open(file)
            
            # Convert to RGBA if necessary
            if image.mode != 'RGBA':
                image = image.convert('RGBA')
            
            # Create a circular mask
            mask = Image.new('L', image.size, 0)
            draw = ImageDraw.Draw(mask)
            draw.ellipse((0, 0) + image.size, fill=255)
            
            # Apply the mask
            output = Image.new('RGBA', image.size, (0, 0, 0, 0))
            output.paste(image, (0, 0))
            output.putalpha(mask)
            
            # Resize to standard size (e.g., 256x256)
            output = output.resize((256, 256), Image.Resampling.LANCZOS)
            
            # Save the processed image
            avatar_path = os.path.join(AVATAR_FOLDER, f"{username}.png")
            output.save(avatar_path, 'PNG')
            
            return avatar_path
        except Exception as e:
            print(f"Error saving avatar: {str(e)}")
            traceback.print_exc()
            return None
    return None

def load_users():
    try:
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f)

def load_memories():
    try:
        with open(MEMORIES_FILE, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_memories(memories):
    with open(MEMORIES_FILE, 'w') as f:
        json.dump(memories, f)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

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
        
        # Log the response for debugging        print("Generated response:", response_text)
        
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
        return jsonify({'error': 'Username and password are required'}), 400
    
    users = load_users()
    if username in users:
        return jsonify({'error': 'Username already exists'}), 400
    
    # Create new user
    users[username] = {
        'password': hash_password(password),
        'created_at': time.time()
    }
    save_users(users)
    
    # Initialize empty memories for user
    memories = load_memories()
    memories[username] = []
    save_memories(memories)
    
    session['username'] = username
    return jsonify({'success': True, 'username': username})

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    
    users = load_users()
    if username not in users or users[username]['password'] != hash_password(password):
        return jsonify({'error': 'Invalid username or password'}), 401
    
    session['username'] = username
    return jsonify({'success': True, 'username': username})

@app.route('/auth/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    return jsonify({'success': True})

@app.route('/auth/status')
def auth_status():
    if 'username' in session:
        username = session['username']
        avatar_url = url_for('get_avatar', username=username, _external=True) if os.path.exists(os.path.join(AVATAR_FOLDER, f"{username}.png")) else None
        return jsonify({
            'authenticated': True,
            'username': username,
            'avatar_url': avatar_url
        })
    return jsonify({'authenticated': False})

@app.route('/generate', methods=['POST'])
@login_required
def generate():
    try:
        if not request.is_json:
            return jsonify({'error': 'Request must be JSON'}), 400
        
        user_message = request.json.get('message')
        if not user_message:
            return jsonify({'error': 'Message is required'}), 400
        
        username = session['username']
        conversation_id = session.get('conversation_id') or str(uuid.uuid4())
        
        # Generate response
        ducky_response, conversation_id = generate_ducky_response(user_message, conversation_id)
        
        # Save to memories
        memories = load_memories()
        if username not in memories:
            memories[username] = []
        
        memories[username].append({
            'timestamp': time.time(),
            'user_message': user_message,
            'ducky_response': ducky_response,
            'conversation_id': conversation_id
        })
        save_memories(memories)
        
        # Store conversation ID in session
        session['conversation_id'] = conversation_id
        
        return jsonify({
            'response': ducky_response,
            'conversation_id': conversation_id
        })
    except Exception as e:
        error_msg = str(e)
        traceback_msg = traceback.format_exc()
        print("Error in generate endpoint:", error_msg)
        print("Traceback:", traceback_msg)
        return jsonify({
            'error': 'Failed to generate response',
            'details': error_msg,
            'traceback': traceback_msg
        }), 500

@app.route('/memories', methods=['GET'])
@login_required
def get_memories():
    username = session['username']
    memories = load_memories()
    user_memories = memories.get(username, [])
    
    # Sort memories by timestamp in descending order
    user_memories.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return jsonify(user_memories)

def generate_stream(user_input):
    # Using genai that was already imported and configured
    model = genai.GenerativeModel('gemini-2.0-flash-thinking-exp-01-21')
    
    system_instruction = """Your name is just ducky. You have to be friendly and human like. 
    The user should feel like their talking to a human. Cut out on the duck jokes."""
    
    generation_config = {
        "temperature": 0.7,
        "top_p": 0.95,
        "top_k": 64,
        "max_output_tokens": 65536,
    }
    
    response = model.generate_content(
        user_input,
        generation_config=generation_config,
        system_instruction=system_instruction,
        stream=True
    )
    
    for chunk in response:
        if hasattr(chunk, 'text'):
            print(chunk.text, end="")

# Improved keep-alive mechanism
def keep_alive():
    """Function to keep the server awake by pinging it every 2 minutes"""
    app_url = os.environ.get("APP_URL")
    
    # If APP_URL isn't set, try to construct it using RENDER_EXTERNAL_URL (provided by Render)
    if not app_url:
        render_external_url = os.environ.get("RENDER_EXTERNAL_URL")
        if render_external_url:
            app_url = render_external_url
            print(f"Using RENDER_EXTERNAL_URL for keep-alive: {app_url}")
        else:
            print("Warning: APP_URL not set and RENDER_EXTERNAL_URL not available, keep-alive disabled")
            return
    
    ping_interval = int(os.environ.get("PING_INTERVAL_SECONDS", "120"))  # Default to 2 minutes
    print(f"Starting keep-alive service with ping interval of {ping_interval} seconds to {app_url}")
    
    while True:
        try:
            print(f"Sending keep-alive ping to {app_url}/ping")
            response = requests.get(f"{app_url}/ping")
            print(f"Keep-alive response: {response.status_code}")
            
            # If we can't access our own ping endpoint, try the root path
            if response.status_code != 200:
                print(f"Ping endpoint failed, trying root path...")
                root_response = requests.get(app_url)
                print(f"Root path response: {root_response.status_code}")
        except Exception as e:
            print(f"Keep-alive ping failed: {str(e)}")
        
        # Sleep for the specified interval (default 2 minutes)
        time.sleep(ping_interval)

# Start the keep-alive thread - enable by default on Render
is_on_render = os.environ.get("RENDER", "false").lower() == "true" or os.environ.get("IS_RENDER", "false").lower() == "true"
should_enable_keep_alive = os.environ.get("ENABLE_KEEP_ALIVE", "true" if is_on_render else "false").lower() == "true"

if should_enable_keep_alive:
    keep_alive_thread = threading.Thread(target=keep_alive, daemon=True)
    keep_alive_thread.start()
    print("Keep-alive thread started")
else:
    print("Keep-alive disabled by configuration")

@app.route('/ping')
def ping():
    """Simple endpoint for keep-alive pings"""
    return jsonify({"status": "ok", "message": "Ducky is awake!"}), 200

@app.route('/auth/update', methods=['POST'])
def update_account():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    current_username = session['username']
    
    try:
        # Load existing users
        with open(USERS_FILE, 'r') as f:
            users = json.load(f)
        
        if current_username not in users:
            return jsonify({'error': 'User not found'}), 404
        
        # Get form data
        username = request.form.get('username', current_username)
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        avatar = request.files.get('avatar')
        
        # Verify current password if changing password or username
        if (new_password or username != current_username) and not verify_password(current_password, users[current_username]['password']):
            return jsonify({'error': 'Current password is incorrect'}), 400
        
        # Check if new username is available
        if username != current_username and username in users:
            return jsonify({'error': 'Username already taken'}), 400
        
        # Handle avatar upload
        avatar_url = None
        if avatar and allowed_file(avatar.filename):
            # Save the avatar
            avatar_path = save_avatar(avatar, username)
            if avatar_path:
                avatar_url = url_for('get_avatar', username=username, _external=True)
        
        # Update user data
        user_data = users[current_username].copy()
        if new_password:
            user_data['password'] = hash_password(new_password)
        
        # If username is changing, update the user entry
        if username != current_username:
            users[username] = user_data
            del users[current_username]
            
            # Update memories with new username
            update_memories_username(current_username, username)
            
            # Update session
            session['username'] = username
        else:
            users[current_username] = user_data
        
        # Save updated users
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=4)
        
        return jsonify({
            'message': 'Account updated successfully',
            'username': username,
            'avatar_url': avatar_url
        })
        
    except Exception as e:
        print(f"Error updating account: {str(e)}")
        traceback.print_exc()
        return jsonify({'error': 'Failed to update account'}), 500

@app.route('/auth/avatar/<username>')
def get_avatar(username):
    avatar_path = os.path.join(AVATAR_FOLDER, f"{username}.png")
    if os.path.exists(avatar_path):
        return send_file(avatar_path, mimetype='image/png')
    return send_file('static/images/default-avatar.png', mimetype='image/png')

if __name__ == '__main__':
    # Use the PORT environment variable provided by Render
    port = int(os.environ.get("PORT", 8000))
    app.run(host='0.0.0.0', port=port, debug=False) 