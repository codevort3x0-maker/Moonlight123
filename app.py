from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_socketio import SocketIO, emit
import sqlite3
import hashlib
import os
import secrets
import requests
from datetime import datetime, timedelta
from functools import wraps
import json

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
socketio = SocketIO(app, cors_allowed_origins="*")

# Discord OAuth2
DISCORD_CLIENT_ID = os.environ.get('DISCORD_CLIENT_ID', '')
DISCORD_CLIENT_SECRET = os.environ.get('DISCORD_CLIENT_SECRET', '')
DISCORD_REDIRECT_URI = os.environ.get('DISCORD_REDIRECT_URI', 'http://localhost:5000/auth/discord/callback')
DISCORD_BOT_TOKEN = os.environ.get('DISCORD_TOKEN', '')
DISCORD_GUILD_ID = os.environ.get('GUILD_ID', '1062306150365794364')

DB_PATH = 'database/moonlight.db'


@app.context_processor
def inject_pending_count():
    if 'user_id' in session and session.get('role') in ('admin', 'owner'):
        try:
            conn = get_db()
            count = conn.execute('SELECT COUNT(*) FROM users WHERE approved=0').fetchone()[0]
            conn.close()
            return {'pending_count': count}
        except:
            pass
    return {'pending_count': 0}

# ─── DATABASE ────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs('database', exist_ok=True)
    conn = get_db()
    c = conn.cursor()

    c.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT,
            discord_id TEXT UNIQUE,
            discord_username TEXT,
            discord_avatar TEXT,
            role TEXT DEFAULT 'newbie',
            approved INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            reset_token TEXT,
            reset_token_expires TEXT
        );

        CREATE TABLE IF NOT EXISTS meetings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            scheduled_at TEXT NOT NULL,
            created_by INTEGER,
            status TEXT DEFAULT 'upcoming',
            discord_message_id TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(created_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS meeting_responses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            meeting_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            discord_username TEXT,
            response TEXT NOT NULL,
            absence_reason TEXT,
            reason_status TEXT DEFAULT 'pending',
            reason_reviewed_by INTEGER,
            reason_reviewed_at TEXT,
            dm_sent INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(meeting_id) REFERENCES meetings(id),
            FOREIGN KEY(user_id) REFERENCES users(id),
            UNIQUE(meeting_id, user_id)
        );

        CREATE TABLE IF NOT EXISTS transfers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user_id INTEGER,
            to_user_id INTEGER,
            organization TEXT NOT NULL,
            reason TEXT,
            status TEXT DEFAULT 'pending',
            created_by INTEGER,
            reviewed_by INTEGER,
            reviewed_at TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(from_user_id) REFERENCES users(id),
            FOREIGN KEY(to_user_id) REFERENCES users(id),
            FOREIGN KEY(created_by) REFERENCES users(id),
            FOREIGN KEY(reviewed_by) REFERENCES users(id)
        );
    ''')

    # Create default admin if not exists
    admin_pass = hashlib.sha256('admin123'.encode()).hexdigest()
    c.execute('''INSERT OR IGNORE INTO users (username, password_hash, role, approved)
                 VALUES ('admin', ?, 'admin', 1)''', (admin_pass,))

    conn.commit()
    conn.close()

# ─── HELPERS ─────────────────────────────────────────────────────────────────

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            if session.get('role') not in roles:
                return render_template('403.html'), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

def get_current_user():
    if 'user_id' not in session:
        return None
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    return user

def send_discord_dm(discord_id, message):
    """Send a DM to a Discord user via bot"""
    if not DISCORD_BOT_TOKEN:
        return False
    try:
        # Create DM channel
        r = requests.post(
            f'https://discord.com/api/v10/users/@me/channels',
            headers={'Authorization': f'Bot {DISCORD_BOT_TOKEN}', 'Content-Type': 'application/json'},
            json={'recipient_id': discord_id}
        )
        if r.status_code == 200:
            channel_id = r.json()['id']
            # Send message
            requests.post(
                f'https://discord.com/api/v10/channels/{channel_id}/messages',
                headers={'Authorization': f'Bot {DISCORD_BOT_TOKEN}', 'Content-Type': 'application/json'},
                json={'content': message}
            )
            return True
    except Exception as e:
        print(f"Discord DM error: {e}")
    return False

def send_discord_channel_message(channel_id, embed):
    """Send embed to Discord channel"""
    if not DISCORD_BOT_TOKEN:
        return None
    try:
        r = requests.post(
            f'https://discord.com/api/v10/channels/{channel_id}/messages',
            headers={'Authorization': f'Bot {DISCORD_BOT_TOKEN}', 'Content-Type': 'application/json'},
            json={'embeds': [embed]}
        )
        if r.status_code == 200:
            return r.json()['id']
    except Exception as e:
        print(f"Discord channel error: {e}")
    return None

def verify_discord_member(discord_username):
    """Check if a Discord username exists in the guild"""
    if not DISCORD_BOT_TOKEN:
        return True  # Skip check if no token
    try:
        r = requests.get(
            f'https://discord.com/api/v10/guilds/{DISCORD_GUILD_ID}/members/search?query={discord_username}&limit=5',
            headers={'Authorization': f'Bot {DISCORD_BOT_TOKEN}'}
        )
        if r.status_code == 200:
            members = r.json()
            for m in members:
                if m.get('user', {}).get('username', '').lower() == discord_username.lower():
                    return True
            return False
    except:
        return True  # Fail open
    return False

# ─── AUTH ROUTES ─────────────────────────────────────────────────────────────

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        conn = get_db()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ? AND password_hash = ?',
            (username, hash_password(password))
        ).fetchone()
        conn.close()

        if user:
            if not user['approved']:
                flash('Ваш аккаунт ожидает подтверждения.', 'warning')
                return redirect(url_for('login'))
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            return redirect(url_for('dashboard'))
        else:
            flash('Неверный логин или пароль.', 'error')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if not username or not password:
            flash('Заполните все поля.', 'error')
            return redirect(url_for('register'))

        if password != confirm:
            flash('Пароли не совпадают.', 'error')
            return redirect(url_for('register'))

        if len(password) < 6:
            flash('Пароль минимум 6 символов.', 'error')
            return redirect(url_for('register'))

        conn = get_db()
        try:
            conn.execute(
                'INSERT INTO users (username, password_hash, role, approved) VALUES (?, ?, ?, ?)',
                (username, hash_password(password), 'newbie', 0)
            )
            conn.commit()
            flash('Регистрация успешна! Ожидайте подтверждения.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Имя пользователя занято.', 'error')
        finally:
            conn.close()

    return render_template('register.html')

@app.route('/auth/discord')
def discord_auth():
    scope = 'identify'
    url = (f'https://discord.com/api/oauth2/authorize'
           f'?client_id={DISCORD_CLIENT_ID}'
           f'&redirect_uri={DISCORD_REDIRECT_URI}'
           f'&response_type=code&scope={scope}')
    return redirect(url)

@app.route('/auth/discord/callback')
def discord_callback():
    code = request.args.get('code')
    if not code:
        flash('Ошибка авторизации Discord.', 'error')
        return redirect(url_for('login'))

    # Exchange code for token
    r = requests.post('https://discord.com/api/oauth2/token', data={
        'client_id': DISCORD_CLIENT_ID,
        'client_secret': DISCORD_CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': DISCORD_REDIRECT_URI
    })

    if r.status_code != 200:
        flash('Ошибка получения токена Discord.', 'error')
        return redirect(url_for('login'))

    token_data = r.json()
    access_token = token_data.get('access_token')

    # Get user info
    user_r = requests.get('https://discord.com/api/users/@me',
                          headers={'Authorization': f'Bearer {access_token}'})
    if user_r.status_code != 200:
        flash('Ошибка получения данных Discord.', 'error')
        return redirect(url_for('login'))

    discord_user = user_r.json()
    discord_id = discord_user['id']
    discord_username = discord_user['username']
    discord_avatar = discord_user.get('avatar', '')

    conn = get_db()
    # Check if discord account already linked
    existing = conn.execute('SELECT * FROM users WHERE discord_id = ?', (discord_id,)).fetchone()

    if existing:
        if not existing['approved']:
            conn.close()
            flash('Ваш аккаунт ожидает подтверждения.', 'warning')
            return redirect(url_for('login'))
        session['user_id'] = existing['id']
        session['username'] = existing['username'] or existing['discord_username']
        session['role'] = existing['role']
        conn.close()
        return redirect(url_for('dashboard'))

    # If logged in, link account
    if 'user_id' in session:
        conn.execute(
            'UPDATE users SET discord_id=?, discord_username=?, discord_avatar=? WHERE id=?',
            (discord_id, discord_username, discord_avatar, session['user_id'])
        )
        conn.commit()
        conn.close()
        flash('Discord аккаунт привязан!', 'success')
        return redirect(url_for('dashboard'))

    # Create new account via Discord
    try:
        conn.execute(
            'INSERT INTO users (username, discord_id, discord_username, discord_avatar, role, approved) VALUES (?, ?, ?, ?, ?, ?)',
            (discord_username, discord_id, discord_username, discord_avatar, 'newbie', 0)
        )
        conn.commit()
        flash('Аккаунт создан через Discord! Ожидайте подтверждения.', 'success')
    except sqlite3.IntegrityError:
        flash('Аккаунт с таким Discord уже существует.', 'error')
    finally:
        conn.close()

    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ─── DASHBOARD ───────────────────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    user = get_current_user()
    if not user:
        return redirect(url_for('logout'))

    conn = get_db()
    stats = {}

    if user['role'] in ('admin', 'owner'):
        stats['users_total'] = conn.execute('SELECT COUNT(*) FROM users WHERE approved=1').fetchone()[0]
        stats['pending_users'] = conn.execute('SELECT COUNT(*) FROM users WHERE approved=0').fetchone()[0]
        stats['meetings_total'] = conn.execute('SELECT COUNT(*) FROM meetings').fetchone()[0]
        stats['transfers_pending'] = conn.execute("SELECT COUNT(*) FROM transfers WHERE status='pending'").fetchone()[0]
        recent_meetings = conn.execute(
            'SELECT m.*, u.username as creator FROM meetings m LEFT JOIN users u ON m.created_by=u.id ORDER BY m.scheduled_at DESC LIMIT 5'
        ).fetchall()
        recent_transfers = conn.execute(
            '''SELECT t.*, u1.username as from_name, u2.username as to_name, u3.username as creator_name
               FROM transfers t
               LEFT JOIN users u1 ON t.from_user_id=u1.id
               LEFT JOIN users u2 ON t.to_user_id=u2.id
               LEFT JOIN users u3 ON t.created_by=u3.id
               ORDER BY t.created_at DESC LIMIT 5'''
        ).fetchall()
    else:
        recent_meetings = conn.execute(
            "SELECT * FROM meetings WHERE status='upcoming' ORDER BY scheduled_at ASC LIMIT 5"
        ).fetchall()
        recent_transfers = []

    conn.close()
    return render_template('dashboard.html', user=user, stats=stats,
                           recent_meetings=recent_meetings, recent_transfers=recent_transfers)

# ─── USERS (Admin only) ───────────────────────────────────────────────────────

@app.route('/users')
@role_required('admin', 'owner')
def users_list():
    user = get_current_user()
    conn = get_db()
    all_users = conn.execute('SELECT * FROM users ORDER BY created_at DESC').fetchall()
    pending = conn.execute('SELECT * FROM users WHERE approved=0 ORDER BY created_at DESC').fetchall()
    conn.close()
    return render_template('users.html', user=user, all_users=all_users, pending=pending)

@app.route('/users/<int:uid>/approve', methods=['POST'])
@role_required('admin', 'owner')
def approve_user(uid):
    conn = get_db()
    conn.execute('UPDATE users SET approved=1 WHERE id=?', (uid,))
    conn.commit()
    target = conn.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
    conn.close()

    # Notify via Discord DM
    if target and target['discord_id']:
        send_discord_dm(target['discord_id'],
                        f'✅ Ваш аккаунт на сайте **MoonLight** подтверждён! Добро пожаловать.')

    socketio.emit('user_approved', {'uid': uid})
    return jsonify({'ok': True})

@app.route('/users/<int:uid>/reject', methods=['POST'])
@role_required('admin', 'owner')
def reject_user(uid):
    conn = get_db()
    conn.execute('DELETE FROM users WHERE id=? AND role="newbie"', (uid,))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

@app.route('/users/<int:uid>/reset-password', methods=['POST'])
@role_required('admin')
def reset_password(uid):
    new_pass = secrets.token_urlsafe(8)
    conn = get_db()
    conn.execute('UPDATE users SET password_hash=? WHERE id=?', (hash_password(new_pass), uid))
    conn.commit()
    target = conn.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
    conn.close()

    if target and target['discord_id']:
        send_discord_dm(target['discord_id'],
                        f'🔑 Ваш пароль на сайте **MoonLight** был сброшен администратором.\n'
                        f'Новый пароль: `{new_pass}`\nПожалуйста, смените его после входа.')

    return jsonify({'ok': True, 'new_password': new_pass})

@app.route('/users/<int:uid>/change-role', methods=['POST'])
@role_required('admin')
def change_role(uid):
    new_role = request.json.get('role')
    if new_role not in ('admin', 'owner', 'newbie'):
        return jsonify({'ok': False, 'error': 'Invalid role'})
    conn = get_db()
    conn.execute('UPDATE users SET role=? WHERE id=?', (new_role, uid))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

# ─── MEETINGS ─────────────────────────────────────────────────────────────────

@app.route('/meetings')
@login_required
def meetings():
    user = get_current_user()
    conn = get_db()

    if user['role'] in ('admin', 'owner'):
        all_meetings = conn.execute(
            'SELECT m.*, u.username as creator FROM meetings m LEFT JOIN users u ON m.created_by=u.id ORDER BY m.scheduled_at DESC'
        ).fetchall()
    else:
        all_meetings = conn.execute(
            "SELECT * FROM meetings WHERE status='upcoming' ORDER BY scheduled_at ASC"
        ).fetchall()

    conn.close()
    return render_template('meetings.html', user=user, meetings=all_meetings)

@app.route('/meetings/create', methods=['GET', 'POST'])
@role_required('admin', 'owner')
def create_meeting():
    user = get_current_user()
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        scheduled_at = request.form.get('scheduled_at', '')
        notify_channel = request.form.get('notify_channel', '').strip()

        if not title or not scheduled_at:
            flash('Заполните название и время.', 'error')
            return redirect(url_for('create_meeting'))

        conn = get_db()
        c = conn.execute(
            'INSERT INTO meetings (title, description, scheduled_at, created_by) VALUES (?, ?, ?, ?)',
            (title, description, scheduled_at, session['user_id'])
        )
        meeting_id = c.lastrowid
        conn.commit()

        # Send Discord notification
        msg_id = None
        if notify_channel and DISCORD_BOT_TOKEN:
            dt = datetime.fromisoformat(scheduled_at)
            site_url = request.host_url.rstrip('/')
            meeting_url = f"{site_url}/meeting/{meeting_id}"
            
            embed = {
                "title": f"📅 Новое собрание: {title}",
                "description": description or "Собрание назначено.",
                "color": 0x5865F2,
                "fields": [
                    {"name": "🕐 Время", "value": dt.strftime('%d.%m.%Y %H:%M'), "inline": True},
                    {"name": "👤 Создал", "value": session['username'], "inline": True},
                    {"name": "🔗 Ссылка", "value": f"[Перейти к собранию]({meeting_url})", "inline": False}
                ],
                "footer": {"text": "MoonLight • Подтвердите участие на сайте"}
            }
            msg_id = send_discord_channel_message(notify_channel, embed)

        if msg_id:
            conn.execute('UPDATE meetings SET discord_message_id=? WHERE id=?', (msg_id, meeting_id))
            conn.commit()

        conn.close()
        flash('Собрание создано!', 'success')
        return redirect(url_for('meetings'))

    return render_template('create_meeting.html', user=user)
@app.route('/meetings/<int:mid>')
@login_required
def meeting_detail(mid):
    user = get_current_user()
    conn = get_db()
    meeting = conn.execute(
        'SELECT m.*, u.username as creator FROM meetings m LEFT JOIN users u ON m.created_by=u.id WHERE m.id=?',
        (mid,)
    ).fetchone()

    if not meeting:
        conn.close()
        return render_template('404.html'), 404

    my_response = conn.execute(
        'SELECT * FROM meeting_responses WHERE meeting_id=? AND user_id=?',
        (mid, session['user_id'])
    ).fetchone()

    attendees = []
    absent = []
    no_response = []

    if user['role'] in ('admin', 'owner'):
        attendees = conn.execute(
            '''SELECT mr.*, u.username, u.discord_username FROM meeting_responses mr
               JOIN users u ON mr.user_id=u.id
               WHERE mr.meeting_id=? AND mr.response='attending' ORDER BY mr.created_at''',
            (mid,)
        ).fetchall()
        absent = conn.execute(
            '''SELECT mr.*, u.username, u.discord_username FROM meeting_responses mr
               JOIN users u ON mr.user_id=u.id
               WHERE mr.meeting_id=? AND mr.response='absent' ORDER BY mr.created_at''',
            (mid,)
        ).fetchall()
        # Users who haven't responded (approved, newbie role is the base approved user role)
        all_approved = conn.execute(
            'SELECT * FROM users WHERE approved=1 AND role IN ("newbie","owner","admin")'
        ).fetchall()
        responded_ids = set(r['user_id'] for r in list(attendees) + list(absent))
        no_response = [u for u in all_approved if u['id'] not in responded_ids]

    conn.close()
    return render_template('meeting_detail.html', user=user, meeting=meeting,
                           my_response=my_response, attendees=attendees,
                           absent=absent, no_response=no_response)

@app.route('/meetings/<int:mid>/respond', methods=['POST'])
@login_required
def meeting_respond(mid):
    data = request.json
    response = data.get('response')  # 'attending' or 'absent'
    discord_username = data.get('discord_username', '').strip().lstrip('@')
    absence_reason = data.get('absence_reason', '').strip()

    if not discord_username:
        return jsonify({'ok': False, 'error': 'Укажите Discord username'})

    # Verify Discord member
    if not verify_discord_member(discord_username):
        return jsonify({'ok': False, 'error': 'Пользователь не найден на Discord сервере'})

    conn = get_db()
    meeting = conn.execute('SELECT * FROM meetings WHERE id=?', (mid,)).fetchone()
    if not meeting:
        conn.close()
        return jsonify({'ok': False, 'error': 'Собрание не найдено'})

    conn.execute('''
        INSERT INTO meeting_responses (meeting_id, user_id, discord_username, response, absence_reason, reason_status)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(meeting_id, user_id) DO UPDATE SET
            discord_username=excluded.discord_username,
            response=excluded.response,
            absence_reason=excluded.absence_reason,
            reason_status=CASE WHEN excluded.response='absent' THEN 'pending' ELSE 'n/a' END
    ''', (mid, session['user_id'], discord_username, response, absence_reason,
          'pending' if response == 'absent' else 'n/a'))
    conn.commit()
    conn.close()

    socketio.emit('meeting_updated', {'meeting_id': mid})
    return jsonify({'ok': True})

@app.route('/meetings/<int:mid>/absence/<int:resp_id>/review', methods=['POST'])
@role_required('admin', 'owner')
def review_absence(mid, resp_id):
    data = request.json
    decision = data.get('decision')  # 'approved' or 'rejected'

    if decision not in ('approved', 'rejected'):
        return jsonify({'ok': False, 'error': 'Invalid decision'})

    conn = get_db()
    resp = conn.execute(
        'SELECT mr.*, u.discord_id, u.username FROM meeting_responses mr JOIN users u ON mr.user_id=u.id WHERE mr.id=?',
        (resp_id,)
    ).fetchone()

    if not resp:
        conn.close()
        return jsonify({'ok': False, 'error': 'Не найдено'})

    conn.execute('''
        UPDATE meeting_responses SET reason_status=?, reason_reviewed_by=?, reason_reviewed_at=datetime('now')
        WHERE id=?
    ''', (decision, session['user_id'], resp_id))
    conn.commit()

    meeting = conn.execute('SELECT * FROM meetings WHERE id=?', (mid,)).fetchone()
    conn.close()

    # Send Discord DM
    if resp['discord_id']:
        if decision == 'approved':
            msg = (f'✅ Ваша причина отсутствия на собрании **"{meeting["title"]}"** одобрена.\n'
                   f'Причина: _{resp["absence_reason"]}_')
        else:
            msg = (f'❌ Ваша причина отсутствия на собрании **"{meeting["title"]}"** отклонена.\n'
                   f'Причина: _{resp["absence_reason"]}_\n'
                   f'Вы отмечены как **Бездарь** в статистике.')
        send_discord_dm(resp['discord_id'], msg)

    socketio.emit('absence_reviewed', {'resp_id': resp_id, 'decision': decision})
    return jsonify({'ok': True})

@app.route('/meetings/<int:mid>/stats')
@role_required('admin', 'owner')
def meeting_stats(mid):
    user = get_current_user()
    conn = get_db()
    meeting = conn.execute('SELECT * FROM meetings WHERE id=?', (mid,)).fetchone()

    total_users = conn.execute('SELECT COUNT(*) FROM users WHERE approved=1').fetchone()[0]
    attending = conn.execute(
        "SELECT COUNT(*) FROM meeting_responses WHERE meeting_id=? AND response='attending'", (mid,)
    ).fetchone()[0]
    absent_approved = conn.execute(
        "SELECT COUNT(*) FROM meeting_responses WHERE meeting_id=? AND response='absent' AND reason_status='approved'", (mid,)
    ).fetchone()[0]
    absent_rejected = conn.execute(
        "SELECT COUNT(*) FROM meeting_responses WHERE meeting_id=? AND response='absent' AND reason_status='rejected'", (mid,)
    ).fetchone()[0]
    no_response = total_users - attending - absent_approved - absent_rejected

    conn.close()
    return jsonify({
        'total': total_users,
        'attending': attending,
        'absent_approved': absent_approved,
        'absent_rejected': absent_rejected,
        'no_response': no_response
    })

# ─── TRANSFERS ────────────────────────────────────────────────────────────────

@app.route('/transfers')
@role_required('admin', 'owner')
def transfers():
    user = get_current_user()
    conn = get_db()
    all_transfers = conn.execute('''
        SELECT t.*, u1.username as from_name, u2.username as to_name,
               u3.username as creator_name, u4.username as reviewer_name
        FROM transfers t
        LEFT JOIN users u1 ON t.from_user_id=u1.id
        LEFT JOIN users u2 ON t.to_user_id=u2.id
        LEFT JOIN users u3 ON t.created_by=u3.id
        LEFT JOIN users u4 ON t.reviewed_by=u4.id
        ORDER BY t.created_at DESC
    ''').fetchall()
    all_users = conn.execute('SELECT id, username FROM users WHERE approved=1').fetchall()
    conn.close()
    return render_template('transfers.html', user=user, transfers=all_transfers, all_users=all_users)

@app.route('/transfers/create', methods=['POST'])
@role_required('admin', 'owner')
def create_transfer():
    data = request.json
    conn = get_db()
    conn.execute(
        'INSERT INTO transfers (from_user_id, to_user_id, organization, reason, created_by) VALUES (?, ?, ?, ?, ?)',
        (data.get('from_user_id'), data.get('to_user_id'), data.get('organization'), data.get('reason'), session['user_id'])
    )
    conn.commit()
    conn.close()
    socketio.emit('transfer_created', {})
    return jsonify({'ok': True})

@app.route('/transfers/<int:tid>/review', methods=['POST'])
@role_required('admin', 'owner')
def review_transfer(tid):
    data = request.json
    decision = data.get('decision')
    if decision not in ('approved', 'rejected'):
        return jsonify({'ok': False})

    conn = get_db()
    conn.execute(
        "UPDATE transfers SET status=?, reviewed_by=?, reviewed_at=datetime('now') WHERE id=?",
        (decision, session['user_id'], tid)
    )
    conn.commit()
    conn.close()
    socketio.emit('transfer_updated', {'tid': tid, 'decision': decision})
    return jsonify({'ok': True})

# ─── API ──────────────────────────────────────────────────────────────────────

@app.route('/api/verify-discord', methods=['POST'])
@login_required
def api_verify_discord():
    username = request.json.get('username', '').strip().lstrip('@')
    if not username:
        return jsonify({'valid': False, 'error': 'Пустое имя'})
    valid = verify_discord_member(username)
    return jsonify({'valid': valid})

# ─── PROFILE ─────────────────────────────────────────────────────────────────

@app.route('/profile')
@login_required
def profile():
    user = get_current_user()
    return render_template('profile.html', user=user)

@app.route('/profile/change-password', methods=['POST'])
@login_required
def change_password():
    current = request.form.get('current_password', '')
    new_pass = request.form.get('new_password', '')
    confirm = request.form.get('confirm_password', '')

    if new_pass != confirm:
        flash('Новые пароли не совпадают.', 'error')
        return redirect(url_for('profile'))

    if len(new_pass) < 6:
        flash('Пароль минимум 6 символов.', 'error')
        return redirect(url_for('profile'))

    conn = get_db()
    user = conn.execute(
        'SELECT * FROM users WHERE id=? AND password_hash=?',
        (session['user_id'], hash_password(current))
    ).fetchone()

    if not user:
        conn.close()
        flash('Неверный текущий пароль.', 'error')
        return redirect(url_for('profile'))

    conn.execute('UPDATE users SET password_hash=? WHERE id=?',
                 (hash_password(new_pass), session['user_id']))
    conn.commit()
    conn.close()
    flash('Пароль успешно изменён!', 'success')
    return redirect(url_for('profile'))

@app.route('/profile/unlink-discord', methods=['POST'])
@login_required
def unlink_discord():
    conn = get_db()
    conn.execute('UPDATE users SET discord_id=NULL, discord_username=NULL, discord_avatar=NULL WHERE id=?',
                 (session['user_id'],))
    conn.commit()
    conn.close()
    flash('Discord аккаунт отвязан.', 'success')
    return redirect(url_for('profile'))

# ─── ERROR PAGES ─────────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

# ─── MAIN ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    init_db()
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
