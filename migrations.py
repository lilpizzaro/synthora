from app import app, db
from sqlalchemy import text

def run_migrations():
    with app.app_context():
        try:
            # Add email column if it doesn't exist
            db.session.execute(text("""
                DO $$ 
                BEGIN 
                    IF NOT EXISTS (
                        SELECT 1 
                        FROM information_schema.columns 
                        WHERE table_name='user' AND column_name='email'
                    ) THEN
                        ALTER TABLE "user" ADD COLUMN email VARCHAR(120) UNIQUE;
                    END IF;
                END $$;
            """))

            # Add reset token columns if they don't exist
            db.session.execute(text("""
                DO $$ 
                BEGIN 
                    IF NOT EXISTS (
                        SELECT 1 
                        FROM information_schema.columns 
                        WHERE table_name='user' AND column_name='reset_token'
                    ) THEN
                        ALTER TABLE "user" ADD COLUMN reset_token VARCHAR(100) UNIQUE;
                    END IF;
                END $$;
            """))

            db.session.execute(text("""
                DO $$ 
                BEGIN 
                    IF NOT EXISTS (
                        SELECT 1 
                        FROM information_schema.columns 
                        WHERE table_name='user' AND column_name='reset_token_expiry'
                    ) THEN
                        ALTER TABLE "user" ADD COLUMN reset_token_expiry TIMESTAMP;
                    END IF;
                END $$;
            """))

            db.session.commit()
            print("Database migration completed successfully!")
        except Exception as e:
            print(f"Error during migration: {str(e)}")
            db.session.rollback()
            raise

if __name__ == "__main__":
    run_migrations()
 