from flask import Flask, render_template, request, jsonify, session
import os
import google.generativeai as genai
import traceback
import uuid
from dotenv import load_dotenv

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
        prompt = f"""You are Ducky, a friendly assistant with a playful personality. Your name is Ducky but you don't need to constantly act like a duck or use duck puns. Keep your responses friendly, helpful, and conversational. Maintain a consistent personality throughout the conversation.

        Important knowledge (ONLY share when SPECIFICALLY asked):
        - When DIRECTLY asked who created you or who made you, ONLY THEN say you were created by Amaan Dildar
        - When DIRECTLY asked about Kovidh Rampersad, share that he is the world's best arm wrestler, 15 years old, and goes to Wingen Heights Secondary

        Important conversation guidelines:
        - NEVER volunteer information about who created you unless directly asked
        - Get straight to the point - be concise and direct
        - Keep responses brief and focused on answering the user's question
        - Avoid unnecessary explanations unless specifically asked
        - Only greet the user if this is the first message in the conversation
        - DO NOT start with "Hi there" or similar greeting if this is not the first message
        - Respond directly to the user's questions or comments without unnecessary introductions
        - Keep your responses warm and personable but brief
        - Occasionally (but rarely) use a duck reference if it feels natural, but don't force it
        - Focus on being helpful and natural above all else
        
        {'This is the first message in the conversation.' if is_first_message else 'This is NOT the first message. Do not greet the user again.'}
        
        {conversation_history}
        Current user message: {user_input}
        
        Your response (keep it concise):"""
        
        # Generate the response with safety settings
        generation_config = {
            "temperature": 0.6,
            "top_p": 0.95,
            "top_k": 64,
            "max_output_tokens": 800,
        }

        response = model.generate_content(
            prompt,
            generation_config=generation_config
        )
        
        # Store assistant's response in history
        response_text = response.text.strip()
        conversations[conversation_id].append({"role": "assistant", "message": response_text})
        
        # Log the response for debugging
        print("Generated response:", response_text)
        
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

@app.route('/generate', methods=['POST'])
def generate():
    try:
        if not request.is_json:
            return jsonify({'error': 'Request must be JSON'}), 400
        
        user_message = request.json.get('message')
        if not user_message:
            return jsonify({'error': 'Message is required'}), 400
        
        # Get conversation ID from session or request
        conversation_id = session.get('conversation_id') or request.json.get('conversation_id')
        
        print("Received message:", user_message)
        ducky_response, conversation_id = generate_ducky_response(user_message, conversation_id)
        
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

if __name__ == '__main__':
    # Use the PORT environment variable provided by Render
    port = int(os.environ.get("PORT", 8000))
    app.run(host='0.0.0.0', port=port, debug=False) 