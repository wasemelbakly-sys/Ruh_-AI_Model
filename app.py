from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import sqlite3
import os
from datetime import datetime

GEOAPIFY_API_KEY = "83e37fb78b2d4da79d8c57ca6934b679"

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'my_very_strong_secret_key_for_ruh_app_2025')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Database Setup ---
def get_db_connection():
    conn = sqlite3.connect('data.db')
    conn.row_factory = sqlite3.Row
    return conn

def setup_database():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # 1. users
        cursor.execute('''CREATE TABLE IF NOT EXISTS Users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL, username TEXT UNIQUE NOT NULL,     
            first_name TEXT, last_name TEXT, password_hash TEXT NOT NULL,     
            gender TEXT, age INTEGER, profile_image TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        );''')
        
        try:
            cursor.execute('ALTER TABLE Users ADD COLUMN profile_image TEXT')
        except:
            pass 

        # 2. History
        cursor.execute('''CREATE TABLE IF NOT EXISTS User_History (
            history_id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL,
            place_name TEXT, query_text TEXT, action TEXT NOT NULL, url TEXT,
            address TEXT, latitude REAL, longitude REAL,
            visited_at TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now', 'localtime')),
            FOREIGN KEY (user_id) REFERENCES Users(user_id)
        );''')

        # 3. Favorites 
        cursor.execute('''CREATE TABLE IF NOT EXISTS Favorites (
            fav_id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL,
            place_name TEXT NOT NULL, custom_name TEXT, custom_image TEXT,
            category TEXT, address TEXT, latitude REAL, longitude REAL,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES Users(user_id)
        );''')
        
        try:
            cursor.execute('ALTER TABLE Favorites ADD COLUMN custom_image TEXT')
        except:
            pass

        # 4. AI Preferences
        cursor.execute('''CREATE TABLE IF NOT EXISTS User_Preferences (
            pref_id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL,
            category TEXT NOT NULL, weight REAL DEFAULT 1.0,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES Users(user_id),
            UNIQUE(user_id, category)
        );''')
        
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"DB Error: {e}")

setup_database()

# --- Decorator ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', message='Please log in first.', category='error'))
        return f(*args, **kwargs)
    return decorated_function

# Auth Helpers
def hash_password(password): return generate_password_hash(password)
def check_password(hash, password): return check_password_hash(hash, password)

# --- Routes ---
@app.route('/')
@app.route('/index')
def index():
    if 'user_id' in session:
        return redirect(url_for('go'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    message = None
    category = 'error'
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM Users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password(user['password_hash'], password):
            session['user_id'] = user['user_id']
            conn = get_db_connection()
            conn.execute('UPDATE Users SET last_login = ? WHERE user_id = ?', 
                         (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user['user_id']))
            conn.commit()
            conn.close()
            return redirect(url_for('go'))
        else:
            message = 'Incorrect credentials.'
            
    if 'message' in request.args:
        message = request.args.get('message')
        category = request.args.get('category', 'error')
        
    return render_template('login.html', message=(message, category))

@app.route('/create_account', methods=['GET', 'POST'])
def create_account():
    message = ''
    category = 'error'
    if request.method == 'POST':
        password = request.form['password']
        email = request.form['email']
        username = request.form['username']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        gender = request.form['gender']
        age = request.form.get('age')

        if len(password) < 8:
            return render_template('create_account.html', message=('Password must be at least 8 characters.', 'error'))
        
        special = "!@#$%^&*()-+"
        if not any(c.isdigit() for c in password) and not any(c in special for c in password):
             return render_template('create_account.html', message=('Password must contain numbers or symbols.', 'error'))

        try:
            hashed = hash_password(password)
            conn = get_db_connection()
            conn.execute("INSERT INTO Users (email, username, first_name, last_name, password_hash, gender, age) VALUES (?, ?, ?, ?, ?, ?, ?)",
                         (email, username, first_name, last_name, hashed, gender, age))
            conn.commit()
            conn.close()
            return redirect(url_for('login', message='Account created successfully!', category='success'))
        except sqlite3.IntegrityError:
            message = 'Username or Email already exists.'
        except Exception as e:
            message = f'Error: {e}'
            
    return render_template('create_account.html', message=(message, category))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login', message='Logged out.', category='success'))

# --- Feature Routes ---

@app.route('/add_history', methods=['POST'])
@login_required
def add_history():
    data = request.get_json()
    try:
        conn = get_db_connection()
        conn.execute('''INSERT INTO User_History (user_id, place_name, query_text, action, url, address, latitude, longitude, visited_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
                        (session['user_id'], data.get('place_name'), data.get('query_text'), data.get('action'), 
                         data.get('url'), data.get('address'), data.get('latitude'), data.get('longitude'), datetime.now().strftime("%Y-%m-%d %H:%M")))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/toggle_favorite', methods=['POST'])
@login_required
def toggle_favorite():
    data = request.get_json()
    uid = session['user_id']
    action = data.get('action')
    try:
        conn = get_db_connection()
        if action == 'add':
            exists = conn.execute('SELECT 1 FROM Favorites WHERE user_id=? AND place_name=?', (uid, data.get('place_name'))).fetchone()
            if not exists:
                conn.execute('INSERT INTO Favorites (user_id, place_name, category, address, latitude, longitude) VALUES (?,?,?,?,?,?)',
                             (uid, data.get('place_name'), data.get('category'), data.get('address'), data.get('latitude'), data.get('longitude')))
        elif action == 'remove':
            conn.execute('DELETE FROM Favorites WHERE user_id=? AND place_name=?', (uid, data.get('place_name')))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/update_favorite_details', methods=['POST'])
@login_required
def update_favorite_details():
    fav_id = request.form.get('fav_id')
    custom_name = request.form.get('custom_name')
    file = request.files.get('custom_image')
    conn = get_db_connection()
    
    if custom_name:
        conn.execute('UPDATE Favorites SET custom_name = ? WHERE fav_id = ? AND user_id = ?', 
                     (custom_name, fav_id, session['user_id']))
    if file and allowed_file(file.filename):
        filename = secure_filename(f"user_{session['user_id']}_fav_{fav_id}_{file.filename}")
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        conn.execute('UPDATE Favorites SET custom_image = ? WHERE fav_id = ? AND user_id = ?', 
                     (filename, fav_id, session['user_id']))
        
    conn.commit()
    conn.close()
    return redirect(url_for('favorites'))

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    file = request.files.get('profile_image')
    if file and allowed_file(file.filename):
        filename = secure_filename(f"profile_{session['user_id']}_{file.filename}")
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        conn = get_db_connection()
        conn.execute('UPDATE Users SET profile_image = ? WHERE user_id = ?', 
                     (filename, session['user_id']))
        conn.commit()
        conn.close()
    return redirect(url_for('profile'))

# --- AI Logic ---

@app.route('/train_model', methods=['POST'])
@login_required
def train_model():
    data = request.get_json()
    category = data.get('category')
    action = data.get('action')
    user_id = session['user_id']
    reward = 0.2 
    if action == 'favorite': reward = 1.0 
    conn = get_db_connection()
    current = conn.execute('SELECT weight FROM User_Preferences WHERE user_id=? AND category=?', (user_id, category)).fetchone()
    if current:
        new_weight = current['weight'] + reward
        conn.execute('UPDATE User_Preferences SET weight = ? WHERE user_id=? AND category=?', (new_weight, user_id, category))
    else:
        conn.execute('INSERT INTO User_Preferences (user_id, category, weight) VALUES (?, ?, ?)', (user_id, category, 1.0 + reward))
    conn.execute('UPDATE User_Preferences SET weight = weight * 0.95 WHERE user_id=? AND category != ?', (user_id, category))
    conn.commit()
    conn.close()
    return jsonify({'status': 'learned'})

@app.route('/get_user_preferences')
@login_required
def get_user_preferences():
    conn = get_db_connection()
    prefs = conn.execute('SELECT category, weight FROM User_Preferences WHERE user_id=?', (session['user_id'],)).fetchall()
    conn.close()
    return jsonify({row['category']: row['weight'] for row in prefs})

# --- Pages ---

@app.route('/go')
@login_required 
def go():
    return render_template('go.html', active_page='home', api_key=GEOAPIFY_API_KEY)

@app.route('/mood')
@login_required 
def mood():
    return render_template('mood.html', active_page='mood', api_key=GEOAPIFY_API_KEY)

@app.route('/history')
@login_required 
def history():
    user_id = session.get('user_id')
    conn = get_db_connection()
    logs = conn.execute('SELECT * FROM User_History WHERE user_id = ? ORDER BY visited_at DESC LIMIT 50', (user_id,)).fetchall()
    conn.close()
    return render_template('History.html', active_page='history', history_logs=logs)

@app.route('/near')
@login_required 
def near():
    return render_template('Near.html', active_page='near', api_key=GEOAPIFY_API_KEY)

@app.route('/trend')
@login_required 
def trend():
    return render_template('Trend.html', active_page='trend')

@app.route('/favorites')
@login_required 
def favorites():
    user_id = session.get('user_id')
    conn = get_db_connection()
    favs = conn.execute('SELECT * FROM Favorites WHERE user_id = ? ORDER BY added_at DESC', (user_id,)).fetchall()
    conn.close()
    return render_template('Favorites.html', active_page='favorites', favorites_list=favs)

@app.route('/profile')
@login_required 
def profile():
    user_id = session.get('user_id')
    conn = get_db_connection()
    user_info = conn.execute('SELECT * FROM Users WHERE user_id = ?', (user_id,)).fetchone()
    conn.close()
    return render_template('Profile.html', active_page='profile', user_info=user_info)

@app.route('/about')
def about():
    return render_template('about.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0')