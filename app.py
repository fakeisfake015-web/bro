#!/usr/bin/env python3
"""
Challenge 14: Insecure Deserialization (Pickle RCE)
Points: 800
Flag: JCOECTF{d3s3r14l1z4t10n_pwn3d_2024}
"""

from flask import Flask, request, jsonify, session
import pickle
import base64
import os

app = Flask(__name__)
app.secret_key = 'weak_secret_key_12345'  # Intentionally weak

# Create flag
FLAG = "JCOECTF{d3s3r14l1z4t10n_pwn3d_2024}"
with open('flag.txt', 'w') as f:
    f.write(FLAG)

class User:
    def __init__(self, username, is_admin=False):
        self.username = username
        self.is_admin = is_admin

@app.route('/')
def index():
    return '''
    <html><body style="font-family: monospace; padding: 40px;">
    <h1>🍪 Session Manager Pro</h1>
    <p>Advanced session management with serialization</p>
    
    <h2>Create Session</h2>
    <form action="/login" method="POST">
        <input type="text" name="username" placeholder="Username"><br><br>
        <button type="submit">Login</button>
    </form>
    
    <h2>Load Custom Session</h2>
    <form action="/load_session" method="POST">
        <textarea name="session_data" rows="5" cols="60" placeholder="Base64 encoded session data"></textarea><br><br>
        <button type="submit">Load Session</button>
    </form>
    
    <h2>Current Session</h2>
    <a href="/profile">View Profile</a>
    
    <p><i>Hint: Pickle is powerful but dangerous...</i></p>
    </body></html>
    '''

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', 'guest')
    
    # Create user object
    user = User(username, is_admin=False)
    
    # Serialize user (DANGEROUS!)
    serialized = pickle.dumps(user)
    session['user_data'] = base64.b64encode(serialized).decode()
    
    return jsonify({
        'success': True,
        'username': username,
        'session_data': session['user_data']
    })

@app.route('/load_session', methods=['POST'])
def load_session():
    session_data = request.form.get('session_data', '')
    
    try:
        # Vulnerable deserialization!
        decoded = base64.b64decode(session_data)
        user = pickle.loads(decoded)  # RCE vulnerability!
        
        session['user_data'] = session_data
        
        return jsonify({
            'success': True,
            'username': getattr(user, 'username', 'unknown'),
            'is_admin': getattr(user, 'is_admin', False)
        })
    except Exception as e:
        return jsonify({'error': f'Invalid session data: {str(e)}'}), 400

@app.route('/profile')
def profile():
    if 'user_data' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        decoded = base64.b64decode(session['user_data'])
        user = pickle.loads(decoded)
        
        response = {
            'username': user.username,
            'is_admin': user.is_admin
        }
        
        # Admin can see flag
        if user.is_admin:
            response['flag'] = FLAG
        
        return jsonify(response)
    except:
        return jsonify({'error': 'Invalid session'}), 400

if __name__ == '__main__':
    print("[*] Deserialization Challenge running on port 9014")
    print("[*] Hint: Craft a malicious pickle payload")
    app.run(host='0.0.0.0', port=9014, debug=False)
