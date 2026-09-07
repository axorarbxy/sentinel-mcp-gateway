print("Testing imports...")

try:
    print("1. Importing fastapi...")
    from fastapi import FastAPI
    print("✅ fastapi imported")
except Exception as e:
    print(f"❌ fastapi failed: {e}")

try:
    print("2. Importing uvicorn...")
    import uvicorn
    print("✅ uvicorn imported")
except Exception as e:
    print(f"❌ uvicorn failed: {e}")

try:
    print("3. Importing policies...")
    from policies import PolicyEngine
    print("✅ policies imported")
except Exception as e:
    print(f"❌ policies failed: {e}")

try:
    print("4. Importing monitor...")
    from monitor import BehavioralMonitor
    print("✅ monitor imported")
except Exception as e:
    print(f"❌ monitor failed: {e}")

print("All imports checked!")