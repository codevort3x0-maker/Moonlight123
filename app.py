import os
import sqlite3
import secrets
import hashlib
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_socketio import SocketIO, emit
import requests
import asyncio
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
socketio = SocketIO(app, cors_allowed_origins="*")

# Discord config
DISCORD_TOKEN = os.getenv('DISCORD_TOKEN')
DISCORD_CLIENT_ID = os.getenv('DISCORD_CLIENT_ID')
DISCORD_CLIENT_SECRET = os.getenv('DISCORD_CLIENT_SECRET')
DISCORD_REDIRECT_URI = os.getenv('DISCORD_REDIRECT_URI')
GUILD_ID = os.getenv('GUILD_ID')

# Каналы для логирования
ATTENDANCE_CHANNEL = "1439711992264003786"  # Пришедшие
ABSENCE_CHANNEL = "1405865354479009912"      # Отписи

def get_db():
    conn = sqlite3.connect('database/moonlight.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT,
            discord_id TEXT UNIQUE,
            role TEXT DEFAULT 'newbie',
            approved INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Добавляем новые колонки если их нет
    try:
        conn.execute('ALTER TABLE meetings ADD COLUMN role_id TEXT')
    except:
        pass
    try:
        conn.execute('ALTER TABLE meetings ADD COLUMN reminder_sent INTEGER DEFAULT 0')
    except:
        pass
    try:
        conn.execute('ALTER TABLE meetings ADD COLUMN notify_channel TEXT')
    except:
        pass
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS meetings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            scheduled_at TIMESTAMP NOT NULL,
            created_by INTEGER,
            status TEXT DEFAULT 'upcoming',
            discord_message_id TEXT,
            role_id TEXT,
            reminder_sent INTEGER DEFAULT 0,
            notify_channel TEXT,
            FOREIGN KEY (created_by) REFERENCES users (id)
        )
    ''')
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS meeting_responses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            meeting_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            discord_username TEXT NOT NULL,
            response TEXT NOT NULL,
            absence_reason TEXT,
            reason_status TEXT DEFAULT 'n/a',
            responded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(meeting_id, user_id),
            FOREIGN KEY (meeting_id) REFERENCES meetings (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Создаем админа по умолчанию
    admin = conn.execute('SELECT * FROM users WHERE username="CodeV0rtex"').fetchone()
    if not admin:
        hashed = hashlib.sha256('21emanoN74859474()'.encode()).hexdigest()
        conn.execute('INSERT INTO users (username, password, role, approved) VALUES (?, ?, ?, ?)',
                    ('admin', hashed, 'admin', 1))
    
    conn.commit()
    conn.close()

init_db()

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
            conn = get_db()
            user = conn.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()
            conn.close()
            if not user or user['role'] not in roles:
                flash('Недостаточно прав', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated
    return decorator

def get_current_user():
    if 'user_id' not in session:
        return None
    conn = get_db()
    user = conn.execute('SELECT id, username, role, approved FROM users WHERE id=?', (session['user_id'],)).fetchone()
    conn.close()
    return user

def send_discord_channel_message(channel_id, embed=None, content=None):
    """Отправка сообщения в канал Discord"""
    if not DISCORD_TOKEN:
        return None
    
    url = f"https://discord.com/api/v10/channels/{channel_id}/messages"
    headers = {
        "Authorization": f"Bot {DISCORD_TOKEN}",
        "Content-Type": "application/json"
    }
    
    data = {}
    if content:
        data["content"] = content
    if embed:
        data["embeds"] = [embed]
    
    try:
        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 200:
            return response.json().get('id')
        print(f"Discord API error: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Error sending Discord message: {e}")
    return None

def verify_discord_member(username):
    """Проверка что пользователь есть на сервере"""
    if not DISCORD_TOKEN or not GUILD_ID:
        return False
    
    url = f"https://discord.com/api/v10/guilds/{GUILD_ID}/members/search?query={username}"
    headers = {"Authorization": f"Bot {DISCORD_TOKEN}"}
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            members = response.json()
            return len(members) > 0
    except:
        pass
    return False

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = get_db()
        hashed = hashlib.sha256(password.encode()).hexdigest()
        user = conn.execute('SELECT * FROM users WHERE username=? AND password=?', (username, hashed)).fetchone()
        
        if user:
            if not user['approved']:
                flash('Аккаунт ожидает подтверждения', 'error')
            else:
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                return redirect(url_for('dashboard'))
        else:
            flash('Неверный логин или пароль', 'error')
        conn.close()
    
    return render_template('login.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not username or not password:
        return jsonify({'ok': False, 'error': 'Заполните все поля'})
    
    conn = get_db()
    existing = conn.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
    if existing:
        conn.close()
        return jsonify({'ok': False, 'error': 'Логин уже занят'})
    
    hashed = hashlib.sha256(password.encode()).hexdigest()
    conn.execute('INSERT INTO users (username, password, role, approved) VALUES (?, ?, ?, ?)',
                (username, hashed, 'newbie', 0))
    conn.commit()
    conn.close()
    
    return jsonify({'ok': True, 'message': 'Регистрация успешна, ожидайте подтверждения'})

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = get_current_user()
    conn = get_db()
    
    # Статистика для дашборда
    upcoming = conn.execute('SELECT COUNT(*) as cnt FROM meetings WHERE status="upcoming"').fetchone()['cnt']
    my_responses = conn.execute('''
        SELECT COUNT(*) as cnt FROM meeting_responses 
        WHERE user_id=? AND response="attending"
    ''', (session['user_id'],)).fetchone()['cnt']
    
    conn.close()
    
    return render_template('dashboard.html', user=user, upcoming=upcoming, my_responses=my_responses)

@app.route('/meetings')
@login_required
def meetings():
    user = get_current_user()
    conn = get_db()
    
    meetings = conn.execute('''
        SELECT m.*, u.username as creator,
        (SELECT COUNT(*) FROM meeting_responses WHERE meeting_id=m.id AND response="attending") as attending,
        (SELECT COUNT(*) FROM meeting_responses WHERE meeting_id=m.id AND response="absent" AND reason_status="approved") as absent_approved
        FROM meetings m
        JOIN users u ON m.created_by = u.id
        ORDER BY m.scheduled_at DESC
    ''').fetchall()
    
    conn.close()
    return render_template('meetings.html', user=user, meetings=meetings)

@app.route('/meetings/create', methods=['GET', 'POST'])
@role_required('admin', 'owner')
def create_meeting():
    user = get_current_user()
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        scheduled_at = request.form.get('scheduled_at', '')
        notify_channel = request.form.get('notify_channel', '').strip()
        role_id = request.form.get('role_id', '').strip()

        if not title or not scheduled_at:
            flash('Заполните название и время.', 'error')
            return redirect(url_for('create_meeting'))

        conn = get_db()
        c = conn.execute(
            'INSERT INTO meetings (title, description, scheduled_at, created_by, role_id, notify_channel) VALUES (?, ?, ?, ?, ?, ?)',
            (title, description, scheduled_at, session['user_id'], role_id if role_id else None, notify_channel)
        )
        meeting_id = c.lastrowid
        conn.commit()

        # Discord уведомление
        if notify_channel and DISCORD_TOKEN:
            dt = datetime.fromisoformat(scheduled_at)
            site_url = request.host_url.rstrip('/')
            meeting_url = f"{site_url}/meeting/{meeting_id}"
            
            content = None
            if role_id:
                content = f"<@&{role_id}>"
            
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
            msg_id = send_discord_channel_message(notify_channel, embed, content)

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
    
    meeting = conn.execute('''
        SELECT m.*, u.username as creator 
        FROM meetings m
        JOIN users u ON m.created_by = u.id
        WHERE m.id=?
    ''', (mid,)).fetchone()
    
    if not meeting:
        conn.close()
        return render_template('404.html'), 404
    
    # Ответы пользователей
    responses = conn.execute('''
        SELECT mr.*, u.username
        FROM meeting_responses mr
        JOIN users u ON mr.user_id = u.id
        WHERE mr.meeting_id=?
    ''', (mid,)).fetchall()
    
    # Мой ответ
    my_response = conn.execute('''
        SELECT * FROM meeting_responses 
        WHERE meeting_id=? AND user_id=?
    ''', (mid, session['user_id'])).fetchone()
    
    # Разбиваем по категориям для админов
    attendees = []
    absent = []
    if user['role'] in ('admin', 'owner'):
        for r in responses:
            if r['response'] == 'attending':
                attendees.append(r)
            elif r['response'] == 'absent':
                absent.append(r)
    
    # Пользователи без ответа
    no_response = []
    if user['role'] in ('admin', 'owner'):
        all_users = conn.execute('SELECT id, username FROM users WHERE approved=1').fetchall()
        responded_users = set(r['user_id'] for r in responses)
        no_response = [u for u in all_users if u['id'] not in responded_users and u['id'] != meeting['created_by']]
    
    conn.close()
    
    return render_template('meeting_detail.html', 
                         user=user,
                         meeting=meeting,
                         my_response=my_response,
                         attendees=attendees,
                         absent=absent,
                         no_response=no_response)

@app.route('/meetings/<int:mid>/respond', methods=['POST'])
@login_required
def meeting_respond(mid):
    data = request.json
    response = data.get('response')
    discord_username = data.get('discord_username', '').strip().lstrip('@')
    absence_reason = data.get('absence_reason', '').strip()

    if not discord_username:
        return jsonify({'ok': False, 'error': 'Укажите Discord username'})

    if not verify_discord_member(discord_username):
        return jsonify({'ok': False, 'error': 'Пользователь не найден на Discord сервере'})

    conn = get_db()
    meeting = conn.execute('SELECT * FROM meetings WHERE id=?', (mid,)).fetchone()
    if not meeting:
        conn.close()
        return jsonify({'ok': False, 'error': 'Собрание не найдено'})

    existing = conn.execute(
        'SELECT response FROM meeting_responses WHERE meeting_id=? AND user_id=?',
        (mid, session['user_id'])
    ).fetchone()

    if existing and existing['response'] == 'attending':
        conn.close()
        return jsonify({'ok': False, 'error': 'Вы уже подтвердили участие. Изменить ответ нельзя.'})

    conn.execute('''
        INSERT INTO meeting_responses (meeting_id, user_id, discord_username, response, absence_reason, reason_status)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(meeting_id, user_id) DO UPDATE SET
            discord_username=excluded.discord_username,
            response=excluded.response,
            absence_reason=excluded.absence_reason,
            reason_status=CASE 
                WHEN excluded.response='absent' THEN 'pending'
                WHEN excluded.response='attending' THEN 'n/a'
                ELSE reason_status 
            END
    ''', (mid, session['user_id'], discord_username, response, absence_reason,
          'pending' if response == 'absent' else 'n/a'))
    
    conn.commit()

    # Логируем в Discord
    if DISCORD_TOKEN:
        user_data = conn.execute('SELECT username FROM users WHERE id=?', (session['user_id'],)).fetchone()
        
        if response == 'attending':
            embed = {
                "title": "✅ Подтверждение участия",
                "color": 0x57F287,
                "fields": [
                    {"name": "Пользователь", "value": user_data['username'], "inline": True},
                    {"name": "Собрание", "value": meeting['title'], "inline": True},
                    {"name": "Время", "value": meeting['scheduled_at'][:16].replace('T',' '), "inline": True},
                    {"name": "Discord", "value": f"@{discord_username}", "inline": True}
                ],
                "footer": {"text": "Придет на собрание"}
            }
            send_discord_channel_message(ATTENDANCE_CHANNEL, embed)
        
        elif response == 'absent' and absence_reason:
            embed = {
                "title": "❌ Отсутствие с причиной",
                "color": 0xED4245,
                "fields": [
                    {"name": "Пользователь", "value": user_data['username'], "inline": True},
                    {"name": "Собрание", "value": meeting['title'], "inline": True},
                    {"name": "Время", "value": meeting['scheduled_at'][:16].replace('T',' '), "inline": True},
                    {"name": "Discord", "value": f"@{discord_username}", "inline": True},
                    {"name": "Причина", "value": absence_reason, "inline": False}
                ],
                "footer": {"text": "Ждет одобрения"}
            }
            send_discord_channel_message(ABSENCE_CHANNEL, embed)

    conn.close()
    socketio.emit('meeting_updated', {'meeting_id': mid})
    return jsonify({'ok': True})

@app.route('/meetings/<int:mid>/absence/<int:resp_id>/review', methods=['POST'])
@role_required('admin', 'owner')
def review_absence(mid, resp_id):
    data = request.json
    decision = data.get('decision')
    
    conn = get_db()
    
    # Получаем информацию об отсутствии
    absence = conn.execute('''
        SELECT mr.*, u.username, u.discord_id, m.title as meeting_title
        FROM meeting_responses mr
        JOIN users u ON mr.user_id = u.id
        JOIN meetings m ON mr.meeting_id = m.id
        WHERE mr.id=? AND mr.meeting_id=?
    ''', (resp_id, mid)).fetchone()
    
    if not absence:
        conn.close()
        return jsonify({'ok': False, 'error': 'Не найдено'})
    
    new_status = 'approved' if decision == 'approved' else 'rejected'
    conn.execute('UPDATE meeting_responses SET reason_status=? WHERE id=?', (new_status, resp_id))
    conn.commit()
    
    # Отправляем личное сообщение в Discord если есть discord_id
    if absence['discord_id'] and DISCORD_TOKEN:
        dm_channel = create_dm_channel(absence['discord_id'])
        if dm_channel:
            if decision == 'approved':
                text = f"Ваша причина отсутствия на собрании «{absence['meeting_title']}» одобрена."
            else:
                text = f"Ваша причина отсутствия на собрании «{absence['meeting_title']}» отклонена. Вы помечены как «Бездарь»."
            
            send_discord_channel_message(dm_channel, content=text)
    
    conn.close()
    socketio.emit('absence_reviewed', {'meeting_id': mid})
    return jsonify({'ok': True})

def create_dm_channel(user_id):
    """Создает DM канал с пользователем"""
    url = "https://discord.com/api/v10/users/@me/channels"
    headers = {"Authorization": f"Bot {DISCORD_TOKEN}"}
    data = {"recipient_id": user_id}
    
    try:
        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 200:
            return response.json().get('id')
    except:
        pass
    return None

@app.route('/api/verify-discord', methods=['POST'])
def api_verify_discord():
    data = request.json
    username = data.get('username', '').lstrip('@')
    valid = verify_discord_member(username)
    return jsonify({'valid': valid})

@app.route('/meetings/<int:mid>/stats')
@login_required
def meeting_stats(mid):
    user = get_current_user()
    if user['role'] not in ('admin', 'owner'):
        return jsonify({'error': 'Forbidden'}), 403
    
    conn = get_db()
    attending = conn.execute('''
        SELECT COUNT(*) as cnt FROM meeting_responses 
        WHERE meeting_id=? AND response="attending"
    ''', (mid,)).fetchone()['cnt']
    
    absent_approved = conn.execute('''
        SELECT COUNT(*) as cnt FROM meeting_responses 
        WHERE meeting_id=? AND response="absent" AND reason_status="approved"
    ''', (mid,)).fetchone()['cnt']
    
    absent_rejected = conn.execute('''
        SELECT COUNT(*) as cnt FROM meeting_responses 
        WHERE meeting_id=? AND response="absent" AND reason_status="rejected"
    ''', (mid,)).fetchone()['cnt']
    
    total_users = conn.execute('SELECT COUNT(*) as cnt FROM users WHERE approved=1').fetchone()['cnt']
    no_response = total_users - attending - absent_approved - absent_rejected
    
    conn.close()
    
    return jsonify({
        'attending': attending,
        'absent_approved': absent_approved,
        'absent_rejected': absent_rejected,
        'no_response': no_response
    })

# Фоновая задача для напоминаний
async def check_upcoming_meetings():
    """Проверка собраний и отправка напоминаний за 5 минут"""
    while True:
        try:
            conn = get_db()
            now = datetime.now()
            soon = now + timedelta(minutes=5)
            
            meetings = conn.execute('''
                SELECT m.*, u.username as creator_name 
                FROM meetings m
                JOIN users u ON m.created_by = u.id
                WHERE m.status = 'upcoming' 
                AND datetime(m.scheduled_at) BETWEEN ? AND ?
                AND m.reminder_sent = 0
                AND m.notify_channel IS NOT NULL
            ''', (now.strftime('%Y-%m-%d %H:%M:%S'), 
                  (soon + timedelta(seconds=30)).strftime('%Y-%m-%d %H:%M:%S'))).fetchall()
            
            for meeting in meetings:
                if DISCORD_TOKEN and meeting['notify_channel']:
                    site_url = request.host_url.rstrip('/') if request else "https://moonlight.app"
                    meeting_url = f"{site_url}/meeting/{meeting['id']}"
                    
                    content = None
                    if meeting['role_id']:
                        content = f"<@&{meeting['role_id']}> Напоминание! Собрание через 5 минут"
                    
                    embed = {
                        "title": f"⏰ Напоминание: {meeting['title']}",
                        "description": "Собрание начнется через 5 минут!",
                        "color": 0xFEE75C,
                        "fields": [
                            {"name": "🕐 Время", "value": meeting['scheduled_at'][:16].replace('T',' '), "inline": True},
                            {"name": "🔗 Ссылка", "value": f"[Перейти к собранию]({meeting_url})", "inline": False}
                        ]
                    }
                    send_discord_channel_message(meeting['notify_channel'], embed, content)
                    
                    conn.execute('UPDATE meetings SET reminder_sent=1 WHERE id=?', (meeting['id'],))
                    conn.commit()
            
            conn.close()
        except Exception as e:
            print(f"Ошибка в напоминалке: {e}")
        
        await asyncio.sleep(30)

@app.route('/admin/users')
@role_required('admin')
def admin_users():
    user = get_current_user()
    conn = get_db()
    users = conn.execute('SELECT id, username, role, approved, created_at FROM users ORDER BY created_at DESC').fetchall()
    conn.close()
    return render_template('users.html', user=user, users=users)

@app.route('/admin/users/<int:uid>/approve', methods=['POST'])
@role_required('admin')
def approve_user(uid):
    conn = get_db()
    conn.execute('UPDATE users SET approved=1 WHERE id=?', (uid,))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

@app.route('/admin/users/<int:uid>/role', methods=['POST'])
@role_required('admin')
def change_role(uid):
    data = request.json
    role = data.get('role')
    conn = get_db()
    conn.execute('UPDATE users SET role=? WHERE id=?', (role, uid))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

@app.route('/admin/users/<int:uid>/reset-password', methods=['POST'])
@role_required('admin')
def reset_password(uid):
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
    if user and user['discord_id'] and DISCORD_TOKEN:
        new_pass = secrets.token_urlsafe(8)
        hashed = hashlib.sha256(new_pass.encode()).hexdigest()
        conn.execute('UPDATE users SET password=? WHERE id=?', (hashed, uid))
        conn.commit()
        
        # Отправляем в DM
        dm = create_dm_channel(user['discord_id'])
        if dm:
            send_discord_channel_message(dm, content=f"Ваш новый пароль: `{new_pass}`")
    
    conn.close()
    return jsonify({'ok': True})

if __name__ == "__main__":
    # Запускаем фоновую задачу
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.create_task(check_upcoming_meetings())
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)
