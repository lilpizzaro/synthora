from app import app, db
from sqlalchemy import text

def run_migrations():
    with app.app_context():
        try:
            # Add new columns using SQLAlchemy text
            db.session.execute(text('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS avatar_data BYTEA'))
            db.session.execute(text('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS avatar_content_type VARCHAR(50)'))
            
            # Commit the changes
            db.session.commit()
            print("Database migration completed successfully!")
        except Exception as e:
            print(f"Error during migration: {str(e)}")
            db.session.rollback()
            raise
 