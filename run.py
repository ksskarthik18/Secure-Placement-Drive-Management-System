from app import create_app

app = create_app()

if __name__ == '__main__':
    print("Starting Secure Placement Drive Management System...")
    print("Remember: This is a demonstration environment.")
    app.run(debug=True)
