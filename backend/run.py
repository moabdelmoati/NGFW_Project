"""
سكريبت بسيط لتشغيل Backend
"""
import os
import sys

# تعيين متغيرات البيئة
os.environ.setdefault("DB_HOST", "127.0.0.1")
os.environ.setdefault("DB_PORT", "5432")
os.environ.setdefault("DB_NAME", "ngfw_db")
os.environ.setdefault("DB_USER", "postgres")
os.environ.setdefault("DB_PASS", "1234")

# استيراد وتشغيل app
if __name__ == "__main__":
    from app import app, load_model_and_preproc, ensure_tables
    
    print("\n" + "="*60)
    print("🚀 Starting NGFW Backend...")
    print("="*60 + "\n")
    
    try:
        load_model_and_preproc()
        ensure_tables()
        print("\n" + "="*60)
        print("✅ Backend ready!")
        print("📍 Access at: http://localhost:5000")
        print("="*60 + "\n")
        app.run(host="0.0.0.0", port=5000, debug=True)
    except KeyboardInterrupt:
        print("\n\n👋 Shutting down...")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)








