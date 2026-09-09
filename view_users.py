import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from database import SessionLocal, User

print("\n" + "="*70)
print("  SENTINEL-MCP USER DATABASE")
print("="*70)

db = SessionLocal()
users = db.query(User).all()

if len(users) == 0:
    print("\n📭 No users found in database.")
else:
    print(f"\n📊 Total Users: {len(users)}\n")
    print("-"*70)
    print(f"{'ID':<5} {'Username':<20} {'Email':<30} {'Created'}")
    print("-"*70)
    
    for user in users:
        created = user.created_at.strftime('%Y-%m-%d %H:%M') if user.created_at else 'N/A'
        print(f"{user.id:<5} {user.username:<20} {user.email:<30} {created}")

db.close()
print("\n" + "="*70)