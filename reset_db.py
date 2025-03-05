from app import app, db

def reset_database():
    with app.app_context():
        print("Dropping all tables...")
        db.drop_all()
        print("Creating new tables...")
        db.create_all()
        print("Database reset complete!")

if __name__ == "__main__":
    reset_database() 