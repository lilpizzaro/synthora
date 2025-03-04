import json
import os
from app import app, db, User, Memory
from datetime import datetime

def migrate_data():
    # Create database tables
    with app.app_context():
        db.create_all()
        
        # Load existing users
        try:
            with open('data/users.json', 'r') as f:
                users_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            users_data = {}
            
        # Load existing memories
        try:
            with open('data/memories.json', 'r') as f:
                memories_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            memories_data = {}
            
        # Migrate users
        username_to_id = {}  # Map usernames to new user IDs
        for username, user_data in users_data.items():
            # Check if user already exists
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                username_to_id[username] = existing_user.id
                continue
                
            # Create new user
            avatar_path = os.path.join('static/avatars', f"{username}.png")
            user = User(
                username=username,
                password_hash=user_data.get('password'),
                avatar_url=avatar_path if os.path.exists(avatar_path) else None,
                created_at=datetime.fromtimestamp(user_data.get('created_at', datetime.utcnow().timestamp()))
            )
            db.session.add(user)
            db.session.flush()  # Get the user ID
            username_to_id[username] = user.id
            
        # Migrate memories
        for username, user_memories in memories_data.items():
            user_id = username_to_id.get(username)
            if not user_id:
                continue
                
            for memory_data in user_memories:
                memory = Memory(
                    user_id=user_id,
                    user_message=memory_data.get('user_message', ''),
                    ducky_response=memory_data.get('ducky_response', ''),
                    timestamp=datetime.fromtimestamp(memory_data.get('timestamp', datetime.utcnow().timestamp()))
                )
                db.session.add(memory)
                
        # Commit all changes
        db.session.commit()
        print("Data migration completed successfully!")

if __name__ == '__main__':
    migrate_data() 