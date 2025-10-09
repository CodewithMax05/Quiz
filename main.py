from gevent import monkey, spawn, sleep
monkey.patch_all()

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort, make_response
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import SQLAlchemyError, OperationalError
from sqlalchemy import func, or_
import os
import random
import csv
import time
from collections import defaultdict
from flask_session import Session
from datetime import datetime, timezone, timedelta
from flask_socketio import SocketIO, emit, join_room, leave_room
import uuid
from threading import Timer, Lock
from werkzeug.middleware.proxy_fix import ProxyFix
from functools import wraps
from flask_wtf.csrf import CSRFProtect, generate_csrf, validate_csrf
from wtforms import ValidationError
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
csrf = CSRFProtect(app)  # CSRF-Schutz aktivieren

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# WebSocket-Konfiguration für Render
socketio = SocketIO(app, 
                   async_mode='gevent',
                   cors_allowed_origins="*", 
                   manage_session=False,
                   logger=True,  # Für Debugging aktivieren
                   engineio_logger=True,  # Für Debugging aktivieren
                   ping_timeout=60,
                   ping_interval=25,
                   max_http_buffer_size=1e8,
                   allow_upgrades=True,  # WebSocket-Upgrades erlauben
                   transports=['websocket', 'polling'])  # Beide Transportmethoden

database_url = os.environ.get('DATABASE_URL', 'sqlite:///quiz.db')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

is_production = os.environ.get('FLASK_ENV') == 'production'

app.config.update(
    SESSION_COOKIE_SECURE=is_production,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_REFRESH_EACH_REQUEST=True,  # Session-Cookie wird bei jeder Anfrage erneuert
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
    SESSION_USE_SIGNER=True,
    SECRET_KEY=os.environ.get('SECRET_KEY', os.urandom(24).hex()),
    SESSION_COOKIE_DOMAIN=None,
    SESSION_COOKIE_PATH='/'
)

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(150), nullable=False)
    highscore = db.Column(db.Integer, default=0)
    highscore_time = db.Column(db.DateTime)
    correct_high = db.Column(db.Integer, default=0)
    first_played = db.Column(db.DateTime)  
    is_admin = db.Column(db.Boolean, default=False)
    avatar = db.Column(db.String(200), default="avatar0.png")  # <-- Avatar-Bild
    number_of_games = db.Column(db.Integer, default=0)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(150), nullable=False)
    question = db.Column(db.String(500), unique=True, nullable=False)
    true = db.Column(db.String(150), nullable=False)
    wrong1 = db.Column(db.String(150), nullable=False)
    wrong2 = db.Column(db.String(150), nullable=False)
    wrong3 = db.Column(db.String(150), nullable=False)

class SupportRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(50))
    email = db.Column(db.String(150))
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    def to_dict(self):
        return {
            'id': self.id,
            'category': self.category,
            'username': self.username,
            'phone': self.phone,
            'email': self.email,
            'message': self.message,
            'created_at': self.created_at
        }

class QuizTimer:
    def __init__(self, socketio, room_id, duration=30):
        self.socketio = socketio
        self.room_id = room_id
        self.duration = duration
        self.time_left = duration
        self.is_running = False
        self.lock = Lock()
        self.start_time = None
        self.greenlet = None

    def start(self):
        with self.lock:
            if self.is_running:
                return
            self.is_running = True
            self.start_time = time.time()
            self.time_left = self.duration
            # Starte den Timer in einem Greenlet
            self.greenlet = spawn(self._run_timer)

    def _run_timer(self):
        """Läuft in einem eigenen Greenlet und sendet Timer-Updates"""
        start_time = time.time()
        while self.is_running:
            with self.lock:
                if not self.is_running:
                    break
                    
                # Berechne verbleibende Zeit genau
                elapsed = time.time() - start_time
                self.time_left = max(0, self.duration - int(elapsed))
                
                # Sende Update an den Raum
                try:
                    self.socketio.emit('time_update', 
                                    {'time_left': self.time_left}, 
                                    room=self.room_id)
                except Exception as e:
                    print(f"Fehler beim Senden des Timer-Updates: {e}")
                
                # Zeit abgelaufen?
                if self.time_left <= 0:
                    try:
                        self.socketio.emit('time_out', room=self.room_id)
                    except Exception as e:
                        print(f"Fehler beim Timeout: {e}")
                    self.is_running = False
                    break
            
            # Exakt 1 Sekunde warten
            next_update = start_time + (30 - self.time_left + 1)
            sleep_time = max(0, next_update - time.time())
            sleep(sleep_time)

    def stop(self):
        with self.lock:
            self.is_running = False
            if self.greenlet:
                try:
                    self.greenlet.kill()
                except:
                    pass
                self.greenlet = None

    def get_time_left(self):
        with self.lock:
            if not self.is_running or not self.start_time:
                return 0
            elapsed = time.time() - self.start_time
            return max(0, self.duration - int(elapsed))

# Thread-safe Timer Management
active_timers = {}
timer_lock = Lock()
# Speichere Socket-Sessions zu Räumen
socket_rooms = {}

# Serverseitige Session-Konfiguration
app.config['SESSION_TYPE'] = 'sqlalchemy'
app.config['SESSION_SQLALCHEMY'] = db
app.config['SESSION_PERMANENT'] = False

server_session = Session(app)

bcrypt = Bcrypt(app)

def stop_timer(room_id):
    """Stoppt und entfernt Timer sicher"""
    with timer_lock:
        if room_id in active_timers:
            active_timers[room_id].stop()
            del active_timers[room_id]
            print(f"Timer für Raum {room_id} gestoppt")

def get_or_create_timer(room_id):
    """Erstellt oder gibt existierenden Timer zurück"""
    with timer_lock:
        if room_id not in active_timers:
            timer = QuizTimer(socketio, room_id, duration=30)
            active_timers[room_id] = timer
            timer.start()
            print(f"Neuer Timer für Raum {room_id} gestartet")
        else:
            # Timer existiert bereits - prüfe ob er läuft
            timer = active_timers[room_id]
            if not timer.is_running:
                timer.start()
                print(f"Timer für Raum {room_id} neu gestartet")
        return active_timers[room_id]

# Template-Filter für lokale Zeit
@app.template_filter('to_local_time')
def to_local_time(utc_time):
    if utc_time is None:
        return "Noch nicht gespielt"
    local_time = utc_time + timedelta(hours=2)
    return local_time.strftime('%d.%m.%Y %H:%M')

# Automatische Datenbankinitialisierung beim App-Start
def initialize_database():
    """Erstellt Tabellen und importiert neue Fragen bei jedem Start"""
    # Verhindere doppelte Ausführung im Reloader
    if os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        print("⏩ Überspringe Datenbankinitialisierung im Reloader")
        return

    with app.app_context():
        try:
            # Tabellen erstellen
            db.create_all()

            # Environment-Variable für erzwungenen Import prüfen
            force_init = os.environ.get('FORCE_DB_INIT', 'false').lower() == 'true'
            
            if force_init:
                print("Erzwinge Datenbank-Reset...")
                Question.query.delete()
                db.session.commit()
            
            print("Prüfe auf neue Fragen...")
            categories = [
                'wirtschaft', 'technologie', 'sprache', 'promis', 
                'sport', 'natur', 'musik', 'glauben', 'kunst', 
                'geschichte', 'geographie', 'essen', 'filme', 
                'automobil', 'astrologie', 'gaming'
            ]
            
            # Pfad zum CSV-Ordner
            csv_folder = os.path.join(os.path.dirname(__file__), 'csv')
            total_imported = 0
            
            for category in categories:
                # Pfad zur CSV-Datei im Unterordner
                csv_file = os.path.join(csv_folder, f'fragen_{category}.csv')
                
                if not os.path.exists(csv_file):
                    print(f"⚠️ Datei nicht gefunden: {csv_file}")
                    continue
                    
                imported = 0
                try:
                    # UTF-8-SIG für BOM-Behandlung verwenden
                    with open(csv_file, 'r', encoding='utf-8-sig') as file:
                        reader = csv.DictReader(file, delimiter=';')
                        required_keys = ['subject', 'question', 'true', 'wrong1', 'wrong2', 'wrong3']
                        
                        for row in reader:
                            # Sicherstellen, dass alle Spalten vorhanden und nicht leer sind
                            if not all(key in row for key in required_keys):
                                continue
                                
                            if any(not row[key].strip() for key in required_keys):
                                continue
                                
                            # Daten bereinigen
                            subject_lower = row['subject'].strip().lower()
                            question_text = row['question'].strip()
                            true_answer = row['true'].strip()
                            wrong1 = row['wrong1'].strip()
                            wrong2 = row['wrong2'].strip()
                            wrong3 = row['wrong3'].strip()
                            
                            # Prüfen ob Frage bereits existiert
                            existing = Question.query.filter_by(question=question_text).first()
                            if not existing:
                                new_question = Question(
                                    subject=subject_lower,
                                    question=question_text,
                                    true=true_answer,
                                    wrong1=wrong1,
                                    wrong2=wrong2,
                                    wrong3=wrong3
                                )
                                db.session.add(new_question)
                                imported += 1
                    
                    if imported > 0:
                        db.session.commit()
                        print(f"✅ {category}: {imported} neue Fragen importiert")
                        total_imported += imported
                    else:
                        print(f"ℹ️ {category}: Keine neuen Fragen gefunden")
                        
                except Exception as e:
                    print(f"❌ Fehler beim Import von {csv_file}: {str(e)}")
                    db.session.rollback()
            
            print(f"Importierte Fragen: {total_imported}")
            
            # Testbenutzer immer hinzufügen, wenn nicht vorhanden
            print("Prüfe Testbenutzer...")
            test_users = [
                {'username': 'Michael', 'password': 'test', 'highscore': 900, 'highscore_time': datetime(2025, 1, 15, tzinfo=timezone.utc), 'correct_high': 28},
                {'username': 'Laura', 'password': 'test', 'highscore': 839, 'highscore_time': datetime(2025, 1, 16, tzinfo=timezone.utc), 'correct_high': 28},
                {'username': 'Tobi', 'password': 'test', 'highscore': 818, 'highscore_time': datetime(2025, 1, 17, tzinfo=timezone.utc), 'correct_high': 28},
                {'username': 'Sofia', 'password': 'test', 'highscore': 239, 'highscore_time': datetime(2025, 1, 18, tzinfo=timezone.utc), 'correct_high': 28},
                {'username': 'Ben', 'password': 'test', 'highscore': 714, 'highscore_time': datetime(2025, 1, 19, tzinfo=timezone.utc), 'correct_high': 28},
                {'username': 'Anna', 'password': 'test', 'highscore': 677, 'highscore_time': datetime(2025, 1, 20, tzinfo=timezone.utc), 'correct_high': 28},
                {'username': 'Felix', 'password': 'test', 'highscore': 630, 'highscore_time': datetime(2025, 1, 21, tzinfo=timezone.utc), 'correct_high': 28},
                {'username': 'Nina', 'password': 'test', 'highscore': 435, 'highscore_time': datetime(2025, 1, 23, tzinfo=timezone.utc), 'correct_high': 28},
                {'username': 'Nino', 'password': 'test', 'highscore': 435, 'highscore_time': datetime(2025, 1, 24, tzinfo=timezone.utc), 'correct_high': 28},
                {'username': 'Nils', 'password': 'test', 'highscore': 435, 'highscore_time': datetime(2025, 1, 24, tzinfo=timezone.utc), 'correct_high': 28},
                {'username': 'Tim', 'password': 'test', 'highscore': 331, 'highscore_time': datetime(2025, 1, 25, tzinfo=timezone.utc), 'correct_high': 28},
                {'username': 'Emily', 'password': 'test', 'highscore': 322, 'highscore_time': datetime(2025, 1, 26, tzinfo=timezone.utc), 'correct_high': 28},
                {'username': 'Chris', 'password': 'test', 'highscore': 230, 'highscore_time': datetime(2025, 1, 27, tzinfo=timezone.utc), 'correct_high': 28},
                {'username': 'Lena', 'password': 'test', 'highscore': 121, 'highscore_time': datetime(2025, 1, 28, tzinfo=timezone.utc), 'correct_high': 28},
                {'username': 'Max', 'password': 'test', 'highscore': 736, 'highscore_time': datetime(2025, 1, 29, tzinfo=timezone.utc), 'correct_high': 28}
            ]

            added_users = 0
            for user_data in test_users:
                user = User.query.filter_by(username=user_data['username']).first()
                if not user:
                    new_user = User(
                        username=user_data['username'],
                        highscore=user_data['highscore'],
                        highscore_time=user_data['highscore_time'],
                        correct_high=user_data.get('correct_high', 0),
                        first_played=user_data.get('first_played', datetime.now(timezone.utc))  # Erstes Spiel setzen
                    )
                    new_user.set_password(user_data['password'])
                    db.session.add(new_user)
                    added_users += 1
                # Existierenden Benutzer aktualisieren, falls notwendig
                elif user.highscore != user_data['highscore']:
                    user.highscore = user_data['highscore']
                    user.highscore_time = user_data['highscore_time']
                    if not user.first_played:
                        user.first_played = user_data['highscore_time']
            
            if added_users > 0:
                db.session.commit()
                print(f"✅ {added_users} Testbenutzer hinzugefügt/aktualisiert")
            else:
                print("ℹ️ Keine neuen Testbenutzer benötigt")
            
            admin_username = os.environ.get('ADMIN_USERNAME', 'AdminZugang')
            admin_password = os.environ.get('ADMIN_PASSWORD', 'adminzugang')

            admin_user = User.query.filter_by(username=admin_username).first()
            if not admin_user:
                admin_user = User(
                    username=admin_username,
                    is_admin=True,
                    first_played=datetime.now(timezone.utc)
                )
                admin_user.set_password(admin_password)
                db.session.add(admin_user)
                db.session.commit()
                print("✅ Admin-Benutzer erstellt")

            print("Datenbankinitialisierung abgeschlossen")
            
        except Exception as e:
            print(f"❌❌ KRITISCHER FEHLER: {str(e)}")

# Initialisierung nur im Hauptprozess durchführen
if not app.debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
    initialize_database()

# Error Handler für 405 Method Not Allowed
@app.errorhandler(405)
def method_not_allowed(error):
    # Session beenden bei ungültiger Zugriffsmethode
    if 'quiz_data' in session:
        room_id = session['quiz_data'].get('room_id')
        if room_id:
            stop_timer(room_id)
    
    session.clear()
    flash('Ungültige Zugriffsmethode für diese Seite.', 'error')
    return render_template('index.html'), 405
    
def quiz_required(f):
    """Prüft ob ein Quiz aktiv ist"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'quiz_data' not in session:
            # Prüfe ob das Quiz ordnungsgemäß beendet wurde
            if session.get('quiz_properly_ended'):
                # Flag zurücksetzen und ohne Fehler zur Homepage weiterleiten
                session.pop('quiz_properly_ended', None)
                return redirect(url_for('homepage'))
            
            flash('Kein aktives Quiz gefunden. Bitte starte ein neues Quiz.', 'error')
            return redirect(url_for('homepage'))
        
        if session['quiz_data'].get('completed', False):
            # Wenn Quiz abgeschlossen ist, erlaube nur Zugriff auf evaluate_quiz
            if f.__name__ != 'evaluate_quiz':
                flash('Dieses Quiz wurde bereits abgeschlossen.', 'error')
                return redirect(url_for('evaluate_quiz'))
        
        return f(*args, **kwargs)
    return decorated_function

# Admin Panel
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('index'))
        user = User.query.filter_by(username=session['username']).first()
        if not user or not user.is_admin:
            flash('Zugriff verweigert: Admin-Bereich', 'error')
            return redirect(url_for('homepage'))
        return f(*args, **kwargs)
    return decorated_function

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Bitte melde dich zuerst an', 'error')
            return redirect(url_for('index'))
        # Prüfe, ob der Benutzer existiert
        user = User.query.filter_by(username=session['username']).first()
        if not user:
            session.clear()
            flash('Ihre Sitzung ist ungültig. Bitte melden Sie sich erneut an.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def logout_required(f):
    """Prüft ob Benutzer NICHT angemeldet ist - nur dann Zugriff erlaubt"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' in session:
            # Benutzer ist angemeldet - Zugriff verweigern
            route_name = request.endpoint
            if route_name == 'imprint':
                flash('Impressum nur über Startseite erreichbar.', 'error')
            elif route_name == 'settings':
                flash('Einstellungen nur über Startseite erreichbar.', 'error')
            else:
                flash('Diese Seite ist nur über die Startseite erreichbar.', 'error')
            
            # Zurück zur Homepage
            return redirect(url_for('homepage'))
        
        return f(*args, **kwargs)
    return decorated_function

def prevent_quiz_exit(f):
    """Verhindert das Verlassen eines aktiven Quiz ohne Bestätigung"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Prüfe ob Quiz gerade abgebrochen wurde
        if session.pop('quiz_cancelled', False):
            # Quiz wurde absichtlich abgebrochen, erlaube Zugriff
            return f(*args, **kwargs)
        
        # Prüfe ob ein aktives Quiz läuft und ob es nicht abgeschlossen ist
        if 'quiz_data' in session and not session['quiz_data'].get('completed', False):
            # Speichere das gewünschte Ziel in der Session
            target_route = request.endpoint
            session['pending_navigation'] = target_route
            # Redirect zurück zur Quiz-Seite mit Modal-Trigger
            return redirect(url_for('show_question', show_exit_modal='true'))
        return f(*args, **kwargs)
    return decorated_function

# CSRF-Token global verfügbar machen
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)

# führt die eigentliche Sicherheitsprüfung durch
@app.before_request
def check_csrf():
    # CSRF für API-Routes deaktivieren, die JSON verwenden
    if request.path.startswith('/api/'):
        return  # Keine CSRF-Validierung für API-Endpoints
    
    if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
        try:
            # Für Form-Daten
            if request.content_type and 'application/x-www-form-urlencoded' in request.content_type:
                validate_csrf(request.form.get('csrf_token'))
            # Für JSON-Daten
            elif request.content_type and 'application/json' in request.content_type:
                if request.json:
                    validate_csrf(request.json.get('csrf_token'))
        except ValidationError:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'CSRF-Validierung fehlgeschlagen'}), 400
            else:
                flash('CSRF-Validierung fehlgeschlagen. Bitte versuche es erneut.', 'error')
                if 'username' in session:
                    return redirect(url_for('homepage'))
                else:
                    return redirect(url_for('index'))
                
@app.after_request
def add_cache_headers(response):
    try:
        content_type = response.headers.get('Content-Type', '') or ''
        if 'text/html' in content_type:
            # Strenge Cache-Header für HTML-Antworten
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
    except Exception:
        pass
    return response
 
@app.context_processor
def inject_user():
    user = None
    is_admin = False
    if 'username' in session:
        user = User.query.filter_by(username=session['username']).first()
        if user and user.is_admin:
            is_admin = True
    return dict(
        is_logged_in='username' in session,
        is_admin=is_admin
    )

# Ab hier alle Routes 
@app.route('/')
@prevent_quiz_exit 
def index():
    # Wenn Benutzer angemeldet ist: serverseitig ausloggen
    if 'username' in session:
        # Falls ein Quiz läuft: Timer stoppen
        if 'quiz_data' in session:
            room_id = session['quiz_data'].get('room_id')
            if room_id:
                stop_timer(room_id)
        # Session komplett löschen
        session.clear()

    # Gespeicherte Login-Daten (falls vorhanden und Consent gegeben wurde)
    saved_username = request.cookies.get('saved_username', '')
    saved_password = request.cookies.get('saved_password', '')

    return render_template(
        'index.html',
        saved_username=saved_username,
        saved_password=saved_password
    )

@app.route('/login', methods=['POST'])
def login():
    try:
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        if not username or not password:
            flash('Bitte fülle alle Felder aus', 'error')
            return redirect(url_for('index'))

        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            flash('Ungültige Anmeldedaten', 'error')
            return redirect(url_for('index'))

        # Authentifiziert
        session['username'] = username

        # Session permanent nur wenn Consent gesetzt
        if request.cookies.get('cookie_consent') == 'true':
            session.permanent = True
        else:
            session.permanent = False

        # Weiterleitung
        target_endpoint = 'admin_panel' if user.is_admin else 'playermenu'
        resp = redirect(url_for(target_endpoint))

        # Gespeicherte Login-Cookies nur wenn Consent vorhanden
        if request.cookies.get('cookie_consent') == 'true':
            max_age = 60 * 60 * 24 * 30  # 30 Tage
            resp.set_cookie('saved_username', username, max_age=max_age, samesite='Lax')
            resp.set_cookie('saved_password', password, max_age=max_age, httponly=True, samesite='Lax')

        return resp

    except (SQLAlchemyError, OperationalError) as e:
        print(f"Datenbankfehler beim Login: {str(e)}")
        flash('Verbindungsproblem zur Datenbank. Bitte versuche es später erneut.', 'error')
        return redirect(url_for('index'))
    except Exception as e:
        print(f"Unerwarteter Fehler beim Login: {str(e)}")
        flash('Ein unerwarteter Fehler ist aufgetreten.', 'error')
        return redirect(url_for('index'))

@app.route('/register', methods=['POST'])
def register():
    try:
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        # Validierungen
        if not username or not password:
            flash('Bitte fülle alle Felder aus', 'error')
            return redirect(url_for('index'))

        if len(username) > 12:
            flash('Benutzername darf maximal 12 Zeichen haben', 'error')
            return redirect(url_for('index'))

        if User.query.filter_by(username=username).first():
            flash('Benutzername bereits vergeben', 'error')
            return redirect(url_for('index'))

        if len(password) < 5:
            flash('Passwort muss mindestens 5 Zeichen haben!', 'error')
            return redirect(url_for('index'))

        # Benutzer anlegen
        new_user = User(
            username=username,
            first_played=datetime.now(timezone.utc)
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        # Direkt einloggen
        session['username'] = username

        if request.cookies.get('cookie_consent') == 'true':
            session.permanent = True
        else:
            session.permanent = False

        target_endpoint = 'admin_panel' if new_user.is_admin else 'playermenu'
        resp = redirect(url_for(target_endpoint))

        # Login-Daten speichern nur bei Consent
        if request.cookies.get('cookie_consent') == 'true':
            max_age = 60 * 60 * 24 * 30  # 30 Tage
            resp.set_cookie('saved_username', username, max_age=max_age, samesite='Lax')
            resp.set_cookie('saved_password', password, max_age=max_age, httponly=True, samesite='Lax')

        return resp

    except (SQLAlchemyError, OperationalError) as e:
        db.session.rollback()
        print(f"Datenbankfehler bei der Registrierung: {str(e)}")
        flash('Verbindungsproblem zur Datenbank. Bitte versuche es später erneut.', 'error')
        return redirect(url_for('index'))
    except Exception as e:
        db.session.rollback()
        print(f"Unerwarteter Fehler bei der Registrierung: {str(e)}")
        flash('Ein unerwarteter Fehler ist aufgetreten.', 'error')
        return redirect(url_for('index'))


    except (SQLAlchemyError, OperationalError) as e:
        db.session.rollback()
        print(f"Datenbankfehler bei der Registrierung: {str(e)}")
        flash('Verbindungsproblem zur Datenbank. Bitte versuche es später erneut.', 'error')
        return redirect(url_for('index'))
    except Exception as e:
        db.session.rollback()
        print(f"Unerwarteter Fehler bei der Registrierung: {str(e)}")
        flash('Ein unerwarteter Fehler ist aufgetreten', 'error')
        return redirect(url_for('index'))

@app.route("/settings")
@logout_required 
def settings():
    return render_template("settings.html", is_logged_in=('user_id' in session))

@app.route('/change_username', methods=['POST'])
def change_username():
    current_username = request.form.get('current_username', '').strip()
    new_username = request.form.get('new_username', '').strip()
    password = request.form.get('password', '')

    # Benutzer anhand des eingegebenen aktuellen Benutzernamens suchen
    user = User.query.filter_by(username=current_username).first()
    if not user:
        flash("Benutzer nicht gefunden!", "error")
        return redirect(url_for('settings'))

    # Passwort prüfen
    if not user.check_password(password):
        flash("Falsches Passwort!", "error")
        return redirect(url_for('settings'))

    # Neuer Benutzername darf nicht leer sein oder zu lang
    if not new_username:
        flash("Neuer Benutzername darf nicht leer sein!", "error")
        return redirect(url_for('settings'))
    if len(new_username) > 12:
        flash("Benutzername darf maximal 12 Zeichen haben!", "error")
        return redirect(url_for('settings'))

    # Prüfen, ob Benutzername schon existiert
    if User.query.filter_by(username=new_username).first():
        flash("Benutzername bereits vergeben!", "error")
        return redirect(url_for('settings'))

    # Benutzernamen ändern
    user.username = new_username
    db.session.commit()

    # Session aktualisieren, falls der User gerade eingeloggt war
    if 'username' in session and session['username'] == current_username:
        session['username'] = new_username

    flash("Benutzername erfolgreich geändert!", "success")
    return redirect(url_for('settings'))



@app.route('/change_password', methods=['POST'])
def change_password():
    username = request.form.get('username', '').strip()
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')

    # 1. Benutzer anhand des Usernames finden
    user = User.query.filter_by(username=username).first()
    if not user:
        flash("Benutzer nicht gefunden!", "error")
        return redirect(url_for('settings'))

    # 2. Aktuelles Passwort prüfen
    if not user.check_password(current_password):
        flash("Aktuelles Passwort ist falsch!", "error")
        return redirect(url_for('settings'))

    # 3. Prüfen, ob neues Passwort korrekt eingegeben wurde
    if new_password != confirm_password:
        flash("Neue Passwörter stimmen nicht überein!", "error")
        return redirect(url_for('settings'))

    if len(new_password) < 5:
        flash("Neues Passwort muss mindestens 5 Zeichen haben!", "error")
        return redirect(url_for('settings'))

    # 4. Neues Passwort setzen
    user.set_password(new_password)
    db.session.commit()

    flash("Passwort erfolgreich geändert!", "success")
    return redirect(url_for('settings'))

@app.route('/change_avatar', methods=['POST'])
def change_avatar():
    avatar = request.form.get('avatar')
    username = request.form.get('username')
    password = request.form.get('password')

    # Validierung der Eingaben
    if not avatar:
        return jsonify({"success": False, "error": "Kein Avatar ausgewählt!"})
    
    if not username or not password:
        return jsonify({"success": False, "error": "Bitte fülle alle Felder aus!"})

    # Benutzer über eingegebenen Username finden
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"success": False, "error": "Benutzer nicht gefunden!"})

    # Passwort prüfen
    if not user.check_password(password):
        return jsonify({"success": False, "error": "Falsches Passwort!"})

    # Validieren, dass der Avatar existiert
    valid_avatars = [f"avatar{i}.png" for i in range(26)]
    if avatar not in valid_avatars:
        return jsonify({"success": False, "error": "Ungültiger Avatar!"})

    # Prüfen ob der Avatar gleich ist
    if user.avatar == avatar:
        return jsonify({"success": True, "unchanged": True})

    user.avatar = avatar
    db.session.commit()
    return jsonify({"success": True})

@app.route('/delete_account', methods=['POST'])
def delete_account():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    confirm_delete = request.form.get('confirm_delete', '').strip()

    # 1. Benutzer finden
    user = User.query.filter_by(username=username).first()
    if not user:
        flash("Benutzer nicht gefunden!", "error")
        return redirect(url_for('settings'))

    # 2. Passwort prüfen
    if not user.check_password(password):
        flash("Passwort ist falsch!", "error")
        return redirect(url_for('settings'))

    # 3. Bestätigung prüfen
    if confirm_delete != "LÖSCHEN":
        flash("Bitte schreibe exakt 'LÖSCHEN', um den Account zu löschen.", "error")
        return redirect(url_for('settings'))

    # 4. Benutzer löschen
    db.session.delete(user)
    db.session.commit()
    session.clear()

    flash("Dein Account wurde dauerhaft gelöscht.", "success")
    return redirect(url_for('settings'))


@app.route('/clear_cookies', methods=['POST'])
def clear_cookies():
    confirm_delete = request.form.get('confirm_delete', '').strip()

    if confirm_delete != "LÖSCHEN":
        flash("Bitte schreibe exakt 'LÖSCHEN', um die Cookies zu löschen.", "error")
        return redirect(url_for('settings'))

    resp = redirect(url_for('settings'))

    # Alle relevanten Cookies löschen
    cookies_to_delete = ['session', 'saved_username', 'saved_password', 'cookie_consent']
    for cookie_name in cookies_to_delete:
        resp.delete_cookie(cookie_name, path='/')

    session.clear()
    flash("Alle Cookies wurden erfolgreich gelöscht. Du bist nun ausgeloggt.", "success")
    return resp

@app.route('/playermenu')
@login_required
@prevent_quiz_exit 
def playermenu():
    user = User.query.filter_by(username=session['username']).first()
    return render_template(
        'playermenu.html',
        username=user.username,
        avatar=user.avatar,
        first_played=user.first_played,
        highscore=user.highscore,
        number_of_games=user.number_of_games
    )

@app.route('/update_avatar', methods=['POST'])
@login_required
def update_avatar():
    avatar = request.form.get('avatar')
    if not avatar:
        return jsonify({"success": False, "error": "Kein Avatar ausgewählt!"})

    # Validieren, dass der Avatar existiert
    valid_avatars = [f"avatar{i}.png" for i in range(26)]
    if avatar not in valid_avatars:
        return jsonify({"success": False, "error": "Ungültiger Avatar!"})

    # Benutzer über Session-Username holen
    user = User.query.filter_by(username=session.get('username')).first()
    if not user:
        return jsonify({"success": False, "error": "Benutzer nicht gefunden!"})

    user.avatar = avatar
    db.session.commit()
    return jsonify({"success": True})

@app.route('/homepage')
@login_required
@prevent_quiz_exit
def homepage():
    try:
        # Alte Auswertungsdaten löschen, wenn Benutzer zur Homepage zurückkehrt
        if 'evaluation_data' in session:
            session.pop('evaluation_data', None)
            
        if 'username' in session:
            user = User.query.filter_by(username=session['username']).first()
            # Zeige Info-Nachricht nur beim ersten Aufruf
            if not session.get('info_shown'):
                flash('Du kannst bis zu 16 Themen gleichzeitig auswählen!', 'info')
                session['info_shown'] = True
            return render_template(
                'homepage.html',
                username=session['username'],
                highscore=user.highscore if user else 0
            )
        return redirect(url_for('index'))
    except (SQLAlchemyError, OperationalError) as e:
        print(f"Datenbankfehler auf der Homepage: {str(e)}")
        flash('Verbindungsproblem zur Datenbank. Bitte versuche es später erneut.', 'error')
        return redirect(url_for('index'))
    
@app.route('/logout')
@login_required
def logout():
    # Alte Auswertungsdaten löschen
    if 'evaluation_data' in session:
        session.pop('evaluation_data', None)
        
    # Falls Quiz aktiv: Timer stoppen
    if 'quiz_data' in session:
        room_id = session['quiz_data'].get('room_id')
        if room_id:
            stop_timer(room_id)

    session.clear()
    return redirect(url_for('index'))

@app.route('/start_custom_quiz', methods=['POST'])
@login_required
def start_custom_quiz():
    # Alte Auswertungsdaten löschen, wenn ein neues Quiz startet
    if 'evaluation_data' in session:
        session.pop('evaluation_data', None)

    # Alte pending_navigation löschen
    if 'pending_navigation' in session:
        session.pop('pending_navigation', None)

    if request.method != 'POST':
        abort(405)

    if 'username' not in session:
        return redirect(url_for('index'))
    
    # Alten Timer stoppen, falls vorhanden
    if 'quiz_data' in session:
        old_room_id = session['quiz_data'].get('room_id')
        if old_room_id:
            stop_timer(old_room_id)
    
    selected_topics = request.form.getlist('topics')
    
    if not selected_topics:
        flash('Bitte wähle mindestens ein Thema aus', 'error')
        return redirect(url_for('homepage'))

    conditions = [func.lower(Question.subject) == func.lower(topic) for topic in selected_topics]
    all_questions = Question.query.filter(or_(*conditions)).all()

    if not all_questions:
        flash('Keine Fragen für die ausgewählten Themen gefunden', 'error')
        return redirect(url_for('homepage'))

    questions_by_topic = defaultdict(list)
    for q in all_questions:
        questions_by_topic[q.subject.lower()].append(q)
    
    selected_questions = []
    target_per_topic = max(1, 30 // len(selected_topics))
    
    for topic in selected_topics:
        topic_questions = questions_by_topic.get(topic.lower(), [])
        random.shuffle(topic_questions)
        selected_questions.extend(topic_questions[:target_per_topic])
    
    remaining = 30 - len(selected_questions)
    if remaining > 0:
        extra_questions = [q for q in all_questions if q not in selected_questions]
        random.shuffle(extra_questions)
        selected_questions.extend(extra_questions[:remaining])
    
    random.shuffle(selected_questions)
    num_questions = min(30, len(selected_questions))

    # Room-ID für WebSocket erstellen
    room_id = str(uuid.uuid4())
    
    session['quiz_data'] = {
        'subject': ', '.join(selected_topics),
        'questions': [q.id for q in selected_questions],
        'current_index': 0,
        'total_questions': num_questions,
        'score': 0,
        'correct_count': 0,
        'room_id': room_id
    }
    
    return redirect(url_for('show_question'))

@app.route('/show_question')
@login_required
@quiz_required 
def show_question():
    if request.method != 'GET':
        abort(405)

    try:
        if 'quiz_data' not in session:
            return redirect(url_for('homepage'))
        
        quiz_data = session['quiz_data']

        # Prüfe ob das Quiz bereits beendet wurde
        if quiz_data.get('completed', False):
            return redirect(url_for('evaluate_quiz'))
        
        # Wenn Frage bereits beantwortet wurde, leite direkt zur nächsten Frage weiter
        if quiz_data.get('answered', False):
            current_index = quiz_data['current_index']
            if current_index >= quiz_data['total_questions'] - 1:
                # Letzte Frage - zur Auswertung
                return redirect(url_for('evaluate_quiz'))
            else:
                # Nächste Frage laden
                quiz_data['current_index'] += 1
                if 'options_order' in quiz_data:
                    del quiz_data['options_order']
                quiz_data['answered'] = False
                session['quiz_data'] = quiz_data
                return redirect(url_for('show_question'))
        
        current_index = quiz_data['current_index']
        question = Question.query.get(quiz_data['questions'][current_index])

        if not question:
            flash('Frage nicht gefunden.', 'error')
            return redirect(url_for('homepage'))
        
        if 'options_order' not in quiz_data:
            options = [question.true, question.wrong1, question.wrong2, question.wrong3]
            random.shuffle(options)
            quiz_data['options_order'] = options
            session['quiz_data'] = quiz_data
        else:
            options = quiz_data['options_order']
        
        was_correct = session.pop('last_answer_correct', False)
        
        # Berechne die verbleibende Zeit vom Server-Timer
        room_id = quiz_data.get('room_id')
        time_left = 30
        
        if room_id:
            with timer_lock:
                timer = active_timers.get(room_id)
                if timer and timer.is_running:
                    time_left = timer.get_time_left()

        # Prüfe ob Modal angezeigt werden soll (bei versuchtem Seitenwechsel)
        show_exit_modal = request.args.get('show_exit_modal') == 'true'
        pending_navigation = session.get('pending_navigation', '')

        # Wenn show_exit_modal gesetzt ist, entferne pending_navigation aus der Session
        if show_exit_modal:
            session.pop('pending_navigation', None)
        
        response = make_response(render_template(
            'quiz.html',
            subject=quiz_data['subject'],
            question=question,
            options=options,
            progress=current_index + 1,
            total_questions=quiz_data['total_questions'],
            score=quiz_data['score'],
            was_correct=was_correct,
            room_id=room_id,
            time_left=time_left,
            show_exit_modal=show_exit_modal,
            pending_navigation=pending_navigation
        ))
        
        # Cache-Header für Quiz-Seite
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        return response
    
    except (SQLAlchemyError, OperationalError) as e:
        print(f"Datenbankfehler in show_question: {str(e)}")
        flash('Verbindungsproblem zur Datenbank. Bitte versuche es später erneut.', 'error')
        return redirect(url_for('index'))
    except Exception as e:
        print(f"Unerwarteter Fehler in show_question: {str(e)}")
        flash('Ein unerwarteter Fehler ist aufgetreten.', 'error')
        return redirect(url_for('homepage'))

@app.route('/check_answer', methods=['POST'])
@login_required
@quiz_required 
def check_answer():
    if request.method != 'POST':
        abort(405)

    try:
        if 'quiz_data' not in session:
            return jsonify({'error': 'Session expired'}), 400
            
        quiz_data = session['quiz_data']
        current_index = quiz_data['current_index']
        question_id = quiz_data['questions'][current_index]
        question = Question.query.get(question_id)
        
        if not question:
            return jsonify({'error': 'Question not found'}), 404
            
        user_answer = request.form.get('answer', '')
        
        is_correct = user_answer == question.true
        
        # Vereinfachte Punkteberechnung (da Timer über WebSocket läuft)
        points_earned = 100 if is_correct else 0

        if is_correct:
            quiz_data['correct_count'] += 1

        new_score = quiz_data['score'] + points_earned
        quiz_data['score'] = new_score
        quiz_data['answered'] = True

        if current_index >= quiz_data['total_questions'] - 1:
            quiz_data['completed'] = True

        session['quiz_data'] = quiz_data
        
        return jsonify({
            'is_correct': is_correct,
            'correct_answer': question.true,
            'points_earned': points_earned,
            'current_score': new_score,
            'is_last_question': (current_index >= quiz_data['total_questions'] - 1)
        })
    
    except (SQLAlchemyError, OperationalError) as e:
        print(f"Datenbankfehler in check_answer: {str(e)}")
        return jsonify({'error': 'Datenbankfehler aufgetreten. Bitte versuche es später erneut.'}), 500
    except Exception as e:
        print(f"Unerwarteter Fehler in check_answer: {str(e)}")
        return jsonify({'error': 'Ein unerwarteter Fehler ist aufgetreten.'}), 500

@app.route('/next_question', methods=['POST'])
@login_required
@quiz_required 
def next_question():
    if request.method != 'POST':
        abort(405)
    
    try:
        if 'quiz_data' not in session or 'username' not in session:
            return jsonify({'redirect': url_for('homepage')})
        
        quiz_data = session['quiz_data']
        
        # Entferne "answered" Flag
        if 'answered' in quiz_data:
            del quiz_data['answered']

        # Prüfe ob dies die letzte Frage war, die gerade beantwortet wurde
        current_index_after_answer = quiz_data['current_index']
        
        # Wenn die gerade beantwortete Frage die letzte war (Index = total_questions - 1)
        if current_index_after_answer >= quiz_data['total_questions'] - 1:
            quiz_data['completed'] = True
            session['quiz_data'] = quiz_data
            return jsonify({'redirect': url_for('evaluate_quiz')})
        
        quiz_data['current_index'] += 1
        
        # Optionen für die nächste Frage zurücksetzen
        if 'options_order' in quiz_data:
            del quiz_data['options_order']
        
        session['quiz_data'] = quiz_data
        
        # Frage als JSON zurückgeben
        question = Question.query.get(quiz_data['questions'][quiz_data['current_index']])
        options = [question.true, question.wrong1, question.wrong2, question.wrong3]
        random.shuffle(options)
        
        return jsonify({
            'question': question.question,
            'options': options,
            'progress': quiz_data['current_index'] + 1,
            'total_questions': quiz_data['total_questions'],
            'score': quiz_data['score']
        })
    
    except (SQLAlchemyError, OperationalError) as e:
        print(f"Datenbankfehler in next_question: {str(e)}")
        return jsonify({'error': 'Datenbankfehler aufgetreten. Bitte versuche es später erneut.', 'redirect': url_for('homepage')})
    except Exception as e:
        print(f"Unerwarteter Fehler in next_question: {str(e)}")
        return jsonify({'error': 'Ein unerwarteter Fehler ist aufgetreten.', 'redirect': url_for('homepage')})

@app.route('/evaluate')
@login_required
def evaluate_quiz():
    try:
        # Prüfe ob Auswertungsdaten in der Session vorhanden sind (für Neuladen)
        if 'evaluation_data' in session:
            data = session['evaluation_data']
            
            # Benutzerdaten für Avatar holen
            user = User.query.filter_by(username=session['username']).first()
            user_avatar = user.avatar if user else "avatar0.png"
            
            response = make_response(render_template(
                'evaluate.html',
                score=data['score'],
                total=data['total'],
                correct_answers=data['correct_answers'],
                new_highscore=data['new_highscore'],
                highscore=data['highscore'],
                user_avatar=user_avatar  # Avatar hinzugefügt
            ))
            # Cache-Header setzen
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
            return response
        
        if 'quiz_data' not in session or 'username' not in session:
            flash('Kein Quiz zur Auswertung gefunden.', 'error')
            return redirect(url_for('homepage'))
        
        quiz_data = session['quiz_data']

        # Prüfe ob das Quiz als abgeschlossen markiert wurde ODER alle Fragen beantwortet wurden
        is_completed = quiz_data.get('completed', False)
        all_questions_answered = (quiz_data.get('current_index', 0) >= quiz_data.get('total_questions', 0) - 1)
        
        if not is_completed and not all_questions_answered:
            flash('Du musst erst alle Fragen beantworten!', 'error')
            return redirect(url_for('show_question'))
        
        # Timer stoppen und Raum komplett aufräumen
        room_id = quiz_data.get('room_id') if quiz_data else None
        if room_id:
            stop_timer(room_id)
            # WebSocket-Raum aufräumen
            with timer_lock:
                if room_id in active_timers:
                    del active_timers[room_id]
        
        score = quiz_data.get('score', 0)
        total = quiz_data.get('total_questions', 0)
        correct_count = quiz_data.get('correct_count', 0)
        
        # Highscore-Logik
        user = User.query.filter_by(username=session['username']).first()
        new_highscore = False
        now = datetime.now(timezone.utc)
        
        if user:
            if not user.first_played:
                user.first_played = now
            
            # Highscore für Punkte
            if score > user.highscore:
                user.highscore = score
                user.highscore_time = now
                new_highscore = True

            if correct_count > user.correct_high:
                user.correct_high = correct_count

	        # prüfen nochmal explizit auf vollständigen Abschluss (defensive Prüfung)
            try:
                quiz_completed_flag = is_completed or all_questions_answered
                if quiz_completed_flag:
                    # Defensive: falls Feld nicht existiert oder None
                    if getattr(user, 'number_of_games', None) is None:
                        user.number_of_games = 0
                    user.number_of_games += 1
            except Exception as e:
                # Fehler beim Erhöhen soll die Auswertung nicht abbrechen
                print(f"Fehler beim Erhöhen von number_of_games: {e}")
            
            db.session.commit()

        # Benutzerdaten für Avatar holen
        user_avatar = user.avatar if user else "avatar0.png"

        # Speichere Auswertungsdaten in separater Session-Variable für Neuladen
        evaluation_data = {
            'score': score,
            'total': total,
            'correct_answers': correct_count,
            'new_highscore': new_highscore,
            'highscore': user.highscore if user else score
        }
        session['evaluation_data'] = evaluation_data

        # WICHTIG: Komplette Quiz-Daten aus Session entfernen
        session.pop('quiz_data', None)
        
        # Flag setzen, dass Quiz ordnungsgemäß beendet wurde
        session['quiz_properly_ended'] = True
        
        # Response mit Cache-Control Headern
        response = make_response(render_template(
            'evaluate.html',
            score=score,
            total=total,
            correct_answers=correct_count,
            new_highscore=new_highscore,
            highscore=user.highscore if user else score,
            user_avatar=user_avatar  # Avatar hinzugefügt
        ))
        
        # Verhindert, dass der Browser die Seite cached
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        return response
        
    except (SQLAlchemyError, OperationalError) as e:
        print(f"Datenbankfehler in evaluate_quiz: {str(e)}")
        flash('Verbindungsproblem zur Datenbank. Bitte versuche es später erneut.', 'error')
        return redirect(url_for('index'))

@app.route('/cancel_quiz', methods=['POST'])
@login_required
@quiz_required 
def cancel_quiz():
    if request.method != 'POST':
        abort(405)
    
    if 'quiz_data' in session:
        # Timer stoppen, falls vorhanden
        room_id = session['quiz_data'].get('room_id')
        if room_id:
            stop_timer(room_id)
        
        session.pop('quiz_data', None)

    # Prüfe ob eine ausstehende Navigation existiert
    target = session.pop('pending_navigation', None)
    
    # WICHTIG: Flag setzen, dass Quiz absichtlich abgebrochen wurde
    session['quiz_cancelled'] = True
    session.modified = True  # Sicherstellen, dass Session gespeichert wird

    if target:
        return jsonify({'redirect': url_for(target)})
    
    # WICHTIG: Immer JSON zurückgeben, auch wenn kein Target
    return jsonify({'redirect': url_for('homepage')})

@app.route('/quiz_session_status')
@login_required
@quiz_required
def quiz_session_status():
    """Gibt den aktuellen Quiz-Status zurück - verhindert Session-Timeouts"""
    if 'quiz_data' in session:
        return jsonify({
            'active': True,
            'current_question': session['quiz_data'].get('current_index', 0) + 1,
            'total_questions': session['quiz_data'].get('total_questions', 30)
        })
    return jsonify({'active': False})

@app.route('/db_stats')
@login_required
@admin_required
def db_stats():
    try:
        total = db.session.query(func.count(Question.id)).scalar()
        topic_counts = db.session.query(
            Question.subject,
            func.count(Question.id)
        ).group_by(Question.subject).all()

        return render_template(
            "db_stats.html", 
            total=total, topic_counts=topic_counts
        )
    except (SQLAlchemyError, OperationalError) as e:
        print(f"Datenbankfehler auf der Homepage: {str(e)}")
        flash('Verbindungsproblem zur Datenbank. Bitte versuche es später erneut.', 'error')
        return redirect(url_for('index'))

@app.route('/ranking')      
@login_required     
@prevent_quiz_exit           
def ranking():
    try:
        # Sortierung: highscore (absteigend) -> highscore_time (aufsteigend)
        players_with_highscore = User.query.filter(User.first_played.isnot(None)).order_by(
            User.highscore.desc(),
            User.highscore_time.asc(), # Wer zuerst den Score erreicht hat, kommt höher
            User.username.asc()
        ).all()

        # Top 10 Spieler
        top_players = players_with_highscore[:10]

        # Aktuellen Benutzer finden
        current_user = session.get('username')
        current_player = None
        player_rank = None
        
        if current_user:
            # Finde den aktuellen Benutzer in der Datenbank
            current_player = User.query.filter_by(username=current_user).first()

            # Bestimme den Rang des Benutzers
            for idx, player in enumerate(players_with_highscore, start=1):
                if player.username == current_user:
                    current_player = player
                    player_rank = idx
                    break

        # Flash-Nachricht beim ersten Besuch
        if not session.get('ranking_info_shown'):
            flash("Weitere Informationen zum Spieler durch Klick oder Suche", "info")
            session['ranking_info_shown'] = True

        player_rank_map = {player.id: idx for idx, player in enumerate(players_with_highscore, start=1)}

        return render_template(
            'ranking.html',
            top_players=top_players,
            current_player=current_player,
            player_rank=player_rank,
            player_rank_map=player_rank_map
        )
    except (SQLAlchemyError, OperationalError) as e:
        print(f"Datenbankfehler auf der Homepage: {str(e)}")
        flash('Verbindungsproblem zur Datenbank. Bitte versuche es später erneut.', 'error')
        return redirect(url_for('index'))

@app.route('/api/search_player', methods=['POST'])
@login_required
@csrf.exempt
def search_player():
    try:
        # Bessere JSON/Form-Daten Handhabung
        if request.content_type and 'application/json' in request.content_type:
            data = request.get_json() or {}
        else:
            data = request.form

        username = data.get('username', '').strip()
        if not username:
            return jsonify({'error': 'Bitte gib einen Benutzernamen ein'}), 400

        # Case-sensitive Suche mit exaktem Match
        user = User.query.filter(User.username == username).first()
        if not user:
            return jsonify({'error': 'Spieler nicht gefunden'}), 404
        
        # Rang berechnen - optimierte Version
        # Zuerst alle Highscores abrufen und dann lokal sortieren
        all_players = User.query.filter(
            User.first_played.isnot(None),
            User.highscore.isnot(None)
        ).with_entities(
            User.id, 
            User.highscore, 
            User.highscore_time,
            User.username
        ).all()
        
        # Lokal sortieren für bessere Performance
        sorted_players = sorted(
            all_players, 
            key=lambda x: (-x.highscore, x.highscore_time or datetime.min)
        )
        
        # Rang finden
        rank = next((idx for idx, p in enumerate(sorted_players, start=1) if p.id == user.id), None)

        # Helper-Funktion für lokale Zeit-Konvertierung
        def to_local_time(utc_time):
            if utc_time is None:
                return "N/A"
            local_time = utc_time + timedelta(hours=2)
            return local_time.strftime('%d.%m.%Y %H:%M')
        
        return jsonify({
            'rank': rank if rank else "N/A",
            'username': user.username,
            'id': user.id,
            'first_played': to_local_time(user.first_played) if user.first_played else "N/A",
            'number_of_games': user.number_of_games if user.number_of_games else 0,
            'highscore': user.highscore,
            'highscore_time': to_local_time(user.highscore_time) if user.highscore_time else "N/A",
            'correct_high': user.correct_high
        })
    
    except (SQLAlchemyError, OperationalError) as e:
        print(f"Datenbankfehler in search_player: {str(e)}")
        return jsonify({'error': 'Datenbankfehler aufgetreten. Bitte versuche es später erneut.'}), 500
    except Exception as e:
        print(f"Unerwarteter Fehler in search_player: {str(e)}")
        return jsonify({'error': 'Ein unerwarteter Fehler ist aufgetreten.'}), 500

@app.route('/imprint')
@logout_required 
def imprint():
    return render_template('imprint.html')

@app.route('/support', methods=['GET', 'POST'])
@prevent_quiz_exit 
def support():
    if request.method == 'POST':
        category = request.form.get('category')
        username = request.form.get('username')
        phone = request.form.get('phone')
        email = request.form.get('email')
        message = request.form.get('message')

        if not category or not username or not message:
            flash("Bitte alle Pflichtfelder ausfüllen!", "error")
            return render_template(
                'support.html',
                category=category,
                username=username,
                phone=phone,
                email=email,
                message=message,
                # Rücksprungziel merken
                back_target=session.get("support_back_target", "homepage" if 'username' in session else "index")
            )

        try:
            # In Datenbank speichern
            new_request = SupportRequest(
                category=category,
                username=username,
                phone=phone,
                email=email,
                message=message
            )
            db.session.add(new_request)
            db.session.commit()

            flash("Deine Anfrage wurde verschickt!", "success")
            return redirect(url_for('support'))

        except Exception as e:
            db.session.rollback()
            print(f"Fehler beim Speichern der Support-Anfrage: {str(e)}")
            flash("Ein Fehler ist aufgetreten. Bitte versuche es später erneut.", "error")
            return render_template(
                'support.html',
                category=category,
                username=username,
                phone=phone,
                email=email,
                message=message,
                back_target=session.get("support_back_target", "homepage" if 'username' in session else "index")
            )

    # GET: Bestimme die Rückkehrseite basierend auf Login-Status
    if 'username' in session:
        session["support_back_target"] = "homepage"
    else:
        session["support_back_target"] = "index"

    return render_template(
        'support.html',
        back_target=session["support_back_target"]
    )


@app.route('/support_requests')
@login_required
@admin_required
def support_requests_page():
    try:
        # Alle Support-Anfragen abrufen, neueste zuerst
        requests = SupportRequest.query.order_by(SupportRequest.created_at.desc()).all()
        return render_template('support_requests.html', requests=requests)
    except Exception as e:
        print(f"Fehler beim Abrufen der Support-Anfragen: {str(e)}")
        flash("Fehler beim Laden der Support-Anfragen", "error")
        return render_template('support_requests.html', requests=[])

@app.route('/delete_request/<request_id>', methods=['POST'])
@login_required
@admin_required
def delete_request(request_id):
    try:
        request_to_delete = SupportRequest.query.get_or_404(request_id)
        db.session.delete(request_to_delete)
        db.session.commit()
        flash("Anfrage erfolgreich gelöscht!", "success")
    except Exception as e:
        db.session.rollback()
        print(f"Fehler beim Löschen der Support-Anfrage: {str(e)}")
        flash("Fehler beim Löschen der Anfrage", "error")
    
    return redirect(url_for('support_requests_page'))

@app.route('/automatic_logout')
@login_required
def automatic_logout():
    # Prüfe, ob der Aufruf vom Inaktivitäts-Timer kommt
    if not request.referrer or not request.referrer.startswith(request.host_url):
        flash('Ungültiger Zugriff auf den automatischen Logout.', 'error')
        return redirect(url_for('homepage'))
    
    # Timer stoppen bei Logout
    if 'quiz_data' in session:
        room_id = session['quiz_data'].get('room_id')
        if room_id:
            stop_timer(room_id)
    
    session.clear()
    flash('Sie wurden aufgrund von Inaktivität automatisch abgemeldet.', 'permanent')
    return redirect(url_for('index'))

#Admin Panel
@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    try:
        # Statistiken für das Dashboard sammeln
        total_users = User.query.count()
        total_questions = Question.query.count()
        total_support_requests = SupportRequest.query.count()
        
        return render_template(
            'admin_panel.html',
            total_users=total_users,
            total_questions=total_questions,
            total_support_requests=total_support_requests
        )
    except (SQLAlchemyError, OperationalError) as e:
        print(f"Datenbankfehler auf der Homepage: {str(e)}")
        flash('Verbindungsproblem zur Datenbank. Bitte versuche es später erneut.', 'error')
        return redirect(url_for('index'))

@app.route('/add_question', methods=['POST'])
@login_required
@admin_required
def add_question():
    if request.method != 'POST':
        abort(405)

    try:
        subject = request.form['subject'].lower().strip()
        question_text = request.form['question'].strip()
        true_answer = request.form['true'].strip()
        wrong1 = request.form['wrong1'].strip()
        wrong2 = request.form['wrong2'].strip()
        wrong3 = request.form['wrong3'].strip()
        
        # Validierung der Eingaben
        if not all([subject, question_text, true_answer, wrong1, wrong2, wrong3]):
            flash('Bitte fülle alle Felder aus', 'error')
            return redirect(url_for('admin_panel'))
            
        if len(question_text) > 500:
            flash('Frage darf maximal 500 Zeichen haben', 'error')
            return redirect(url_for('admin_panel'))
            
        # Prüfen ob Frage bereits existiert
        existing = Question.query.filter_by(question=question_text).first()
        if existing:
            flash('Diese Frage existiert bereits', 'error')
            return redirect(url_for('admin_panel'))
            
        new_question = Question(
            subject=subject,
            question=question_text,
            true=true_answer,
            wrong1=wrong1,
            wrong2=wrong2,
            wrong3=wrong3
        )
        db.session.add(new_question)
        db.session.commit()
        flash('Frage erfolgreich hinzugefügt!', 'success')
        
    except (SQLAlchemyError, OperationalError) as e:
        db.session.rollback()
        print(f"Datenbankfehler beim Hinzufügen der Frage: {str(e)}")
        flash('Datenbankfehler beim Hinzufügen der Frage', 'error')
    except Exception as e:
        db.session.rollback()
        print(f"Unerwarteter Fehler beim Hinzufügen der Frage: {str(e)}")
        flash('Ein unerwarteter Fehler ist aufgetreten', 'error')
    
    return redirect(url_for('admin_panel'))

# WebSocket Event Handlers
@socketio.on('connect')
def handle_connect():
    print(f"Client connected: {request.sid}")
    if 'username' in session:
        emit('connection_success', {'message': 'Verbunden'})
    else:
        emit('connection_error', {'error': 'Nicht angemeldet'})

@socketio.on('disconnect')
def handle_disconnect():
    print(f"Client disconnected: {request.sid}")
    # Cleanup socket_rooms
    if request.sid in socket_rooms:
        room_id = socket_rooms[request.sid]
        leave_room(room_id)
        del socket_rooms[request.sid]

@socketio.on('reset_timer')
def handle_reset_timer(data):
    room_id = data.get('room_id')
    if room_id in active_timers:
        active_timers[room_id].stop()
        active_timers[room_id].start()
        print(f"Timer für Raum {room_id} zurückgesetzt")

@socketio.on('join_quiz_session')
def handle_join_quiz_session(data):
    room_id = data.get('room_id')
    if not room_id:
        emit('error', {'error': 'Keine Room-ID'})
        return
    
    print(f"Client {request.sid} joining room {room_id}")
    join_room(room_id)
    socket_rooms[request.sid] = room_id
    
    # Timer für diesen Raum erstellen/abrufen und starten
    timer = get_or_create_timer(room_id)
    
    # Aktuellen Timer-Stand senden
    print(f"Client {request.sid} hat Raum {room_id} betreten, Timer läuft")

@socketio.on('submit_answer')
def handle_submit_answer(data):
    try:
        room_id = data.get('room_id')
        user_answer = data.get('answer', '')
        
        if not room_id or 'quiz_data' not in session:
            emit('answer_result', {'error': 'Session expired'})
            return
            
        quiz_data = session['quiz_data']
        current_index = quiz_data['current_index']
        question_id = quiz_data['questions'][current_index]
        question = Question.query.get(question_id)
        
        if not question:
            emit('answer_result', {'error': 'Question not found'})
            return
        
        # Timer stoppen für diesen Raum
        with timer_lock:
            timer = active_timers.get(room_id)
            if timer:
                time_left = timer.get_time_left()
                timer.stop()
            else:
                time_left = 0
        
        # Antwort prüfen
        is_correct = user_answer == question.true
        
        # Zeitbasierte Punkteberechnung
        if is_correct and time_left > 0:
            # Zeitbonus: 30 Basispunkte + bis zu 70 Bonuspunkte
            points_earned = 30 + int(70 * (time_left / 30) ** 2.0)
        else:
            points_earned = 0

        if is_correct:
            quiz_data['correct_count'] += 1

        new_score = quiz_data['score'] + points_earned
        quiz_data['score'] = new_score
        quiz_data['answered'] = True

        if current_index >= quiz_data['total_questions'] - 1:
            quiz_data['completed'] = True

        session['quiz_data'] = quiz_data
        
        # Ergebnis an Client senden
        emit('answer_result', {
            'is_correct': is_correct,
            'correct_answer': question.true,
            'points_earned': points_earned,
            'current_score': new_score,
            'time_left': time_left,
            'user_answer': user_answer,
            'is_last_question': (current_index >= quiz_data['total_questions'] - 1) 
        })
    except (SQLAlchemyError, OperationalError) as e:
        print(f"Datenbankfehler in submit_answer: {str(e)}")
        emit('answer_result', {'error': 'Datenbankfehler aufgetreten'})
    except Exception as e:
        print(f"Unerwarteter Fehler in submit_answer: {str(e)}")
        emit('answer_result', {'error': 'Ein unerwarteter Fehler ist aufgetreten'})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    
    # In Production: verwende den Port von der Environment Variable
    if is_production:
        socketio.run(app, host='0.0.0.0', port=port)
    else:
        socketio.run(app, host='0.0.0.0', port=port, debug=True)