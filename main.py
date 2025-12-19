from gevent import monkey, spawn, sleep
monkey.patch_all()

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort, make_response
from flask_bcrypt import Bcrypt  # Passwort-Hashing
from flask_sqlalchemy import SQLAlchemy  # ORM für Datenbank
from sqlalchemy.exc import SQLAlchemyError, OperationalError  # Datenbank-Fehler
from sqlalchemy import func, or_  # Datenbank-Funktionen und Operatoren
import os
import random
import csv
import time
import io
from collections import defaultdict
from flask_session import Session  # Serverseitige Sessions
from datetime import datetime, timezone, timedelta
from flask_socketio import SocketIO, emit, join_room, leave_room  # WebSockets für Echtzeit-Quiz
import uuid  # Eindeutige IDs für Quiz-Räume
from threading import Lock  # Thread-Sicherheit für Timer
from werkzeug.middleware.proxy_fix import ProxyFix  # Proxy-Unterstützung
from functools import wraps  # Für Decorator-Funktionen
from flask_wtf.csrf import CSRFProtect, generate_csrf, CSRFError  # CSRF-Schutz
from dotenv import load_dotenv  # Umgebungsvariablen aus .env-Datei

load_dotenv() # Lädt Umgebungsvariablen aus .env-Datei

# Flask-App-Initialisierung
app = Flask(__name__)
csrf = CSRFProtect(app)  # CSRF-Schutz aktivieren (automatischer before handler)

# Proxy-Einstellungen für Render 
app.wsgi_app = ProxyFix(
    app.wsgi_app, 

    # x_for=1: Vertraut einem 'X-Forwarded-For' Header
    # Damit erhält 'request.remote_addr' die echte IP des Nutzers statt der internen IP des Hosters
    x_for=1, 

    # x_proto=1: Vertraut dem 'X-Forwarded-Proto' Header
    # Wichtig, damit Flask erkennt, ob der User HTTPS nutzt. Verhindert Probleme bei Redirects 
    # und sorgt dafür, dass Cookies mit 'secure=True' korrekt funktionieren
    x_proto=1, 

    # x_host=1: Vertraut dem 'X-Forwarded-Host' Header.
    # Stellt sicher, dass die App ihren eigenen Hostnamen korrekt kennt.
    x_host=1, 

    # x_prefix=1: Vertraut dem 'X-Forwarded-Prefix' Header
    # Nützlich, wenn die App in einem Unterverzeichnis läuft, damit URLs korrekt generiert werden
    x_prefix=1
    )

# WebSocket-Konfiguration
socketio = SocketIO(app, 
                   async_mode='gevent', # Asynchrone Verarbeitung mit gevent
                   manage_session=False,
                   logger=True,  # Für Debugging aktivieren
                   engineio_logger=True,  # Für Debugging aktivieren
                   ping_timeout=60,
                   ping_interval=25,
                   max_http_buffer_size=1e8,
                   allow_upgrades=True,  # WebSocket-Upgrades erlauben
                   transports=['websocket', 'polling'])  # Beide Transportmethoden

# Datenbank-Konfiguration (PostgreSQL in Production, SQLite lokal)
database_url = os.environ.get('DATABASE_URL', 'sqlite:///quiz.db')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

is_production = os.environ.get('FLASK_ENV') == 'production'

# Sicherheits- und Session-Konfiguration
app.config.update(
    SESSION_COOKIE_SECURE=is_production, # HTTPS nur in Production
    SESSION_COOKIE_HTTPONLY=True, # Verhindert JavaScript-Zugriff auf Cookies
    SESSION_COOKIE_SAMESITE='Lax', # CSRF-Schutz
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
    SECRET_KEY=os.environ.get('SECRET_KEY', os.urandom(24).hex()), # Zufälliger Key falls nicht gesetzt (Fallback)
    SESSION_COOKIE_DOMAIN=None,
    SESSION_COOKIE_PATH='/'
)

# Datenbank- und Authentifizierungs-Initialisierung
db = SQLAlchemy(app)

# ============================================
# DATENBANK-MODELLE
# ============================================

# Verbindungstabelle für Gelesen-Status
news_views = db.Table('news_views',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('news_id', db.Integer, db.ForeignKey('news.id'), primary_key=True)
)

class User(db.Model):
    """Benutzermodell mit allen Benutzerdaten und Statistiken"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), nullable=True)
    phone = db.Column(db.String(50), nullable=True)
    password_hash = db.Column(db.String(150), nullable=False)  # Gehashtes Passwort
    highscore = db.Column(db.Integer, default=0)  # Bester Punktestand
    highscore_time = db.Column(db.DateTime)  # Zeitpunkt des Highscores
    correct_high = db.Column(db.Integer, default=0)  # Höchste Anzahl korrekter Antworten
    first_played = db.Column(db.DateTime)  # Erstes Spiel
    is_admin = db.Column(db.Boolean, default=False)  # Admin-Rechte
    avatar = db.Column(db.String(200), default="avatar0.png")  # Benutzeravatar
    number_of_games = db.Column(db.Integer, default=0)  # Anzahl gespielter Spiele
    agb_accepted = db.Column(db.Boolean, default=False)  # AGB-Akzeptierung

    # Beziehung: Welche News hat der User gesehen?
    seen_news = db.relationship('News', secondary=news_views, backref=db.backref('viewers', lazy='dynamic'))
    
    # Hilfsmethode zum Markieren von News als gesehen
    def has_seen_news(self, news_entry):
        return self.seen_news.append(news_entry) if news_entry not in self.seen_news else None

    # Passwort-Hashing
    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    # Passwort-Überprüfung
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Question(db.Model):
    """Fragenmodell für Quiz-Fragen"""
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(150), nullable=False)  # Thema
    question = db.Column(db.String(500), unique=True, nullable=False)  # Frage
    true = db.Column(db.String(150), nullable=False)  # Richtige Antwort
    wrong1 = db.Column(db.String(150), nullable=False)  # Falsche Antwort 1
    wrong2 = db.Column(db.String(150), nullable=False)  # Falsche Antwort 2
    wrong3 = db.Column(db.String(150), nullable=False)  # Falsche Antwort 3

class News(db.Model):
    """News-Modell"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)  # Titel
    content = db.Column(db.Text, nullable=False)  # Inhalt
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))  # Erstellungszeit

    def to_dict(self):
        """Konvertiert News-Objekt zu Dictionary für JSON-Antworten"""
        return {
            'id': self.id,
            'title': self.title,
            'content': self.content,
            'created_at': self.created_at
        }

class Ticket(db.Model):
    """Support-Ticket-Modell"""
    id = db.Column(db.Integer, primary_key=True)
    
    # User-Fremdschlüssel
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Beziehung zum Benutzer
    user = db.relationship('User', backref=db.backref('tickets', lazy=True))

    # Ticket-Details
    subject = db.Column(db.String(100), nullable=False, index=True)  # Betreff
    category = db.Column(db.String(50), nullable=False, index=True)  # Kategorie
    status = db.Column(db.String(20), default='open', nullable=False, index=True)  # Status

    # Zeitstempel
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    # Beziehung zu den Nachrichten
    messages = db.relationship('TicketMessage', backref='ticket', lazy='dynamic')
    
    # Initialnachricht
    initial_message_content = db.Column(db.Text, nullable=False)

class TicketMessage(db.Model):
    """Nachrichten innerhalb eines Tickets"""
    id = db.Column(db.Integer, primary_key=True)
    
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    
    # Autor der Nachricht: 'user' oder 'admin'
    sender_type = db.Column(db.String(10), nullable=False)
    sender_name = db.Column(db.String(80), nullable=False)

    content = db.Column(db.Text, nullable=False)  # Nachrichteninhalt
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    read = db.Column(db.Boolean, default=False)  # Gelesen-Status

# Hilfsfunktion für ungelesene Nachrichten
def get_unread_ticket_messages_count(user):
    """Zählt ungelesene Ticket-Nachrichten für Benutzer oder Admin"""
    if user.is_admin:
        # Admin: Zähle ALLE Nachrichten im System, die von Usern kommen und ungelesen sind
        return TicketMessage.query.filter_by(sender_type='user', read=False).count()
    else:
        # User: Zähle Nachrichten von Admins, die zu Tickets dieses Users gehören
        return TicketMessage.query.join(Ticket).filter(
            Ticket.user_id == user.id,
            TicketMessage.sender_type == 'admin',
            TicketMessage.read == False
        ).count()

class QuizTimer:
    """Timer-Klasse für Quiz-Fragen mit WebSocket-Unterstützung"""
    def __init__(self, socketio, room_id, duration=30):
        self.socketio = socketio
        self.room_id = room_id
        self.duration = duration
        self.time_left = duration
        self.is_running = False
        self.lock = Lock()  # Thread-Sicherheit
        self.start_time = None
        self.greenlet = None  # Asynchroner Task
        self.timed_out = False

    def start(self):
        """Startet den Timer"""
        with self.lock:
            if self.is_running:
                return
            self.is_running = True
            self.start_time = time.time()
            self.time_left = self.duration
            self.timed_out = False
            # Starte den Timer in einem Greenlet (asynchron)
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
                
                # Sende Update an den Raum über WebSocket
                try:
                    self.socketio.emit('time_update', 
                                    {'time_left': self.time_left}, 
                                    room=self.room_id)
                except Exception as e:
                    print(f"Fehler beim Senden des Timer-Updates: {e}")
                
                # Zeit abgelaufen?
                if self.time_left <= 0:
                    try:
                        # NUR das Socket-Event senden
                        self.socketio.emit('time_out', room=self.room_id)
                    except Exception as e:
                        print(f"Fehler beim Timeout: {e}")
                    
                    # Flags setzen
                    self.is_running = False
                    self.timed_out = True
                    break # Schleife beenden
            
            # Exakt 1 Sekunde warten
            next_update = start_time + (self.duration - self.time_left + 1)
            sleep_time = max(0, next_update - time.time())
            sleep(sleep_time)

    def stop(self):
        """Stoppt den Timer"""
        with self.lock:
            self.is_running = False
            if self.greenlet:
                try:
                    self.greenlet.kill()  # Beende den asynchronen Task
                except:
                    pass
                self.greenlet = None

    def get_time_left(self):
        """Gibt die verbleibende Zeit zurück"""
        with self.lock:
            if not self.is_running or not self.start_time:
                return 0
            elapsed = time.time() - self.start_time
            return max(0, self.duration - int(elapsed))

# Thread-safe Timer Management
active_timers = {}  # Speichert aktive Timer pro Raum
timer_lock = Lock()  # Synchronisation
socket_rooms = {}  # Speichere Socket-Sessions zu Räumen

# Serverseitige Session-Konfiguration
app.config['SESSION_TYPE'] = 'sqlalchemy'
app.config['SESSION_SQLALCHEMY'] = db
app.config['SESSION_PERMANENT'] = False

server_session = Session(app)
bcrypt = Bcrypt(app) # Passwort-Hashing

# ============================================
# TIMER-MANAGEMENT-FUNKTIONEN
# ============================================

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
    
# ============================================
# TEMPLATE-FILTER UND CONTEXT-PROCESSOR
# ============================================

# Template-Filter für lokale Zeit
@app.template_filter('to_iso')
def to_iso(utc_dt):
    """Konvertiert UTC-Zeit zu ISO-Format für JavaScript"""
    if not utc_dt:
        return ''  # leer, damit Template entscheiden kann
    # Sicherstellen, dass dt timezone-aware ist (UTC)
    if utc_dt.tzinfo is None:
        utc_dt = utc_dt.replace(tzinfo=timezone.utc)
    else:
        utc_dt = utc_dt.astimezone(timezone.utc)
    return utc_dt.strftime('%Y-%m-%dT%H:%M:%SZ')

@app.context_processor
def inject_csrf_token():
    """Macht CSRF-Token in allen Templates verfügbar"""
    return dict(csrf_token=generate_csrf)

@app.context_processor
def inject_user():
    """Macht Benutzerinformationen in allen Templates verfügbar"""
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
                
@app.after_request
def add_cache_headers(response):
    """
    Fügt global Cache-Control-Header zu allen Antworten hinzu, die HTML enthalten.
    Dies verhindert, dass Browser sensible Seiten (wie Profile oder Quiz-Stände) speichern.
    """
    try:
        # Prüfen, ob die Antwort HTML enthält
        content_type = response.headers.get('Content-Type', '') or ''
        
        if 'text/html' in content_type:
            # no-store: Der Browser darf die Seite NICHT auf der Festplatte speichern (wichtig für Sicherheit/Logout)
            # no-cache: Der Browser muss vor jeder Anzeige den Server fragen, ob die Seite noch aktuell ist
            # must-revalidate: Zwingt den Browser zur Überprüfung, auch wenn er glaubt, die Seite sei noch "frisch"
            # private: Die Seite ist nur für diesen einen User bestimmt
            # max-age=0: Die Seite ist sofort "abgelaufen".
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private, max-age=0'
            
            # Ein veralteter Header für HTTP/1.0 Kompatibilität (z.B. alte IE Versionen)
            response.headers['Pragma'] = 'no-cache'
            
            # Datum in der Vergangenheit/0 stellt sicher, dass die Seite sofort als ungültig gilt
            response.headers['Expires'] = '0'
            
    except Exception:
        # Falls ein unerwarteter Fehler beim Setzen der Header auftritt,
        # soll die App nicht abstürzen, sondern die Antwort einfach ohne die Header senden.
        pass
        
    return response

# ============================================
# DATENBANK-INITIALISIERUNG BEI START
# ============================================

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
            
            print("Prüfe auf neue Fragen...")
            categories = [
                'wirtschaft', 'technologie', 'sprache', 'promis', 
                'sport', 'natur', 'musik', 'glauben', 'kunst', 
                'geschichte', 'geographie', 'essen', 'filme', 
                'automobil', 'gaming'
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
                {'username': 'Timo', 'password': 'test', 'highscore': 1524, 'highscore_time': datetime(2025, 9, 15, tzinfo=timezone.utc), 'correct_high': 18},
                {'username': 'Felixone', 'password': 'test', 'highscore': 1247, 'highscore_time': datetime(2025, 10, 12, tzinfo=timezone.utc), 'correct_high': 15},
                {'username': 'Tobi', 'password': 'test', 'highscore': 1068, 'highscore_time': datetime(2025, 10, 11, tzinfo=timezone.utc), 'correct_high': 12},
                {'username': 'Sofia', 'password': 'test', 'highscore': 957, 'highscore_time': datetime(2025, 9, 18, tzinfo=timezone.utc), 'correct_high': 10},
                {'username': 'König', 'password': 'test', 'highscore': 895, 'highscore_time': datetime(2025, 7, 11, tzinfo=timezone.utc), 'correct_high': 9},
                {'username': 'Anna', 'password': 'test', 'highscore': 801, 'highscore_time': datetime(2025, 9, 20, tzinfo=timezone.utc), 'correct_high': 10},
                {'username': 'Felix', 'password': 'test', 'highscore': 725, 'highscore_time': datetime(2025, 9, 6, tzinfo=timezone.utc), 'correct_high': 9},
                {'username': '2468', 'password': 'test', 'highscore': 715, 'highscore_time': datetime(2025, 9, 13, tzinfo=timezone.utc), 'correct_high': 8},
                {'username': 'Nino', 'password': 'test', 'highscore': 675, 'highscore_time': datetime(2025, 10, 7, tzinfo=timezone.utc), 'correct_high': 8},
                {'username': 'Willi', 'password': 'test', 'highscore': 624, 'highscore_time': datetime(2025, 10, 8, tzinfo=timezone.utc), 'correct_high': 7},
                {'username': 'Laura', 'password': 'test', 'highscore': 605, 'highscore_time': datetime(2025, 10, 17, tzinfo=timezone.utc), 'correct_high': 8},
                {'username': 'Emily', 'password': 'test', 'highscore': 576, 'highscore_time': datetime(2025, 9, 21, tzinfo=timezone.utc), 'correct_high': 6},
                {'username': 'Christian', 'password': 'test', 'highscore': 535, 'highscore_time': datetime(2025, 9, 10, tzinfo=timezone.utc), 'correct_high': 7},
                {'username': 'Lena', 'password': 'test', 'highscore': 517, 'highscore_time': datetime(2025, 10, 28, tzinfo=timezone.utc), 'correct_high': 6},
                {'username': 'Seelenlose', 'password': '#12345', 'highscore': 1000, 'highscore_time': datetime(2025, 10, 4, tzinfo=timezone.utc), 'correct_high': 12}
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

            print("Prüfe Test-News...")
            test_news = [
                # 1. News: Ticket-Feedback-Anfrage (11.12.2025)
                {
                    'title': 'Dein Feedback ist gefragt!',
                    'content': 'Liebe Community, da dieses Game für euch ist würden wir uns freuen über Ihre Unterstützung bei der Weiterentwicklung: Ideen, Anregungen und Vorschläge für neue Fragen freuen. Erreichen können Sie uns jederzeit über <a href="/tickets" style="color: #6cf; text-decoration: underline;">Ticketsystem</a>. Ihr Feedback ist uns wichtig, um das Quiz-Erlebnis kontinuierlich zu verbessern!',
                    'created_at': datetime(2025, 12, 11, 5, 0, tzinfo=timezone.utc)
                },

                # 2. News: Fragen-Bugfix (10.12.2025)
                {
                    'title': 'Wichtige Meldung: Fragen-Update und Bugfixing',
                    'content': 'Liebe Community, aufgrund häufiger technischer Fehlermeldungen und inkorrekter Inhalte haben wir entschieden, <strong>alle alten Fragen</strong> aus dem System zu entfernen. Wir haben den gesamten Katalog für 15 Themen überarbeitet und durch <strong>1.500 brandneue, geprüfte Fragen</strong> ersetzt (100 pro Thema). Dieser Schritt sorgt für <strong>Stabilität und Korrektheit</strong> im Spiel. Wir arbeiten bereits mit Hochdruck daran, <strong> schnellstmöglich weitere neue Fragen</strong> nachzureichen.',
                    'created_at': datetime(2025, 12, 10, 5, 0, tzinfo=timezone.utc)
                },

                # 3. News: Multiplayer-Update (30.11.2025)
                {
                    'title': 'Multiplayer-News: Kleine Verzögerung, große Features',
                    'content': 'Ein kurzes Update zum <strong>Multiplayer-Modus</strong>: Die Entwicklung läuft bereits, wird jedoch erst <strong>Anfang Februar 2026</strong> abgeschlossen sein. Wir bitten die Verzögerung zu entschuldigen.<br><br>Zusätzlich zu den Einstellungen <strong>„privat“</strong> und <strong>„öffentlich“</strong> wird es neue Optionen geben – darunter die Wahl, ob <strong>Themen gezielt ausgewählt</strong> oder <strong>zufällig</strong> erstellt werden. Außerdem lässt sich die <strong>Bestenliste</strong> künftig als <strong>PDF</strong> exportieren.<br><br>Weitere Infos folgen bald!',
                    'created_at': datetime(2025, 11, 30, 5, 0, tzinfo=timezone.utc)
                },

                # 4. News: Ticketsystem (18.10.2025)
                {
                    'title': 'Du kannst jetzt mit uns schreiben!',
                    'content': 'Ende des Monats möchten wir ein neues Feature einführen in Support. <br> Dann könnt ihr nicht nur eine Anfrage schicken sondern direkt mit uns schreiben!',
                    'created_at': datetime(2025, 10, 18, 5, 0, tzinfo=timezone.utc)
                },

                # 5. News: Zufallsmodus (16.10.2025)
                {
                    'title': 'Neuer Modus in Planung: Zufällige Themen!',
                    'content': 'Um das Quiz-Erlebnis abwechslungsreicher zu gestalten, planen wir die Einführung eines <strong>Zufallsmodus</strong>.<br><br>Dabei werden die Fragen aus <strong>einer zufälligen Anzahl von Themenbereichen</strong> zufällig gezogen. Seid gespannt auf die ultimative Wissensherausforderung!',
                    'created_at': datetime(2025, 10, 16, 10, 0, tzinfo=timezone.utc)
                },

                # 6. News: Einführung AGB & Datenschutz (15.10.2025)
                {
                    'title': 'Wichtige Einführung: AGB und Datenschutz',
                    'content': 'Wir haben unsere <strong>Allgemeinen Geschäftsbedingungen (AGB)</strong> und die <strong>Datenschutzerklärung</strong> eingeführt, um Transparenz und Rechtssicherheit zu gewährleisten.<br><br>Du findest die vollständigen Dokumente jederzeit unter "Rechtliche Informationen" im Login-Menü. Wir behalten uns Änderungen vor. Wesentliche Anpassungen werden immer rechtzeitig angekündigt.',
                    'created_at': datetime(2025, 10, 15, 12, 0, tzinfo=timezone.utc)
                },

                # 7. News: Multiplayer-Ankündigung (25.09.2025)
                {
                    'title': '💥 Ankündigung: Der Multiplayer kommt!',
                    'content': 'Wir freuen uns, den Start des mit Spannung erwarteten <strong>Multiplayer-Modus</strong> bekanntzugeben – geplant für <strong>Januar 2026</strong>!<br><br>Spieler können in eigenen Räumen gegeneinander antreten. Die Räume werden mit Einstellungen wie <strong>"privat"</strong> oder <strong>"öffentlich"</strong> anpassbar sein. Weitere Details zum Beta-Start folgen in Kürze!',
                    'created_at': datetime(2025, 9, 25, 18, 30, tzinfo=timezone.utc)
                },
            ]

            added_news = 0
            for news_data in test_news:
                # Prüfen ob News bereits existiert (anhand des Titels)
                existing = News.query.filter_by(title=news_data['title']).first()
                if not existing:
                    new_news = News(
                        title=news_data['title'],
                        content=news_data['content'],
                        created_at=news_data['created_at']
                    )
                    db.session.add(new_news)
                    added_news += 1

            if added_news > 0:
                db.session.commit()
                print(f"✅ {added_news} Test-News hinzugefügt")
            else:
                print("ℹ️ Keine neuen Test-News benötigt")

            # ========================================================
            # NEU: User "admin" (Normaler User) & Tickets erstellen
            # ========================================================
            print("Prüfe User 'admin' für Tickets...")

            # 1. User erstellen oder holen
            ticket_user = User.query.filter_by(username="admin").first()
            if not ticket_user:
                ticket_user = User(
                    username="admin",
                    is_admin=False, # WICHTIG: Wie gewünscht KEIN Admin-Recht
                    first_played=datetime.now(timezone.utc),
                    agb_accepted=True,
                    email="admin@example.com"
                )
                # Passwort setzen
                ticket_user.set_password("xxxxx")
                db.session.add(ticket_user)
                db.session.commit()
                print("✅ User 'admin' (Normaler User) erstellt")

            # 2. Tickets erstellen, falls noch keine da sind
            # Wir prüfen einfach, ob dieser User schon Tickets hat
            current_ticket_count = Ticket.query.filter_by(user_id=ticket_user.id).count()

            if current_ticket_count < 10:
                print("Erstelle 10 offene Tickets für User 'admin'...")
                
                categories = ['Feedback', 'Account', 'Fehlermeldung', 'Missbrauch', 'Quiz Frage', 'Sonstiges']
                subjects = [
                    "Login funktioniert manchmal nicht",
                    "Frage zu Punktzahl in Runde 3",
                    "Rechtschreibfehler gefunden",
                    "Account löschen anfragen",
                    "Vorschlag für neue Kategorie",
                    "Badge wurde nicht vergeben",
                    "Server scheint langsam zu sein",
                    "Kann mein Passwort nicht ändern",
                    "Melde einen Bug im Chat",
                    "Allgemeines Feedback zum Design"
                ]

                # Aktuelle Zeit für Zeitstempel
                base_time = datetime.now(timezone.utc)

                for i in range(10):
                    # Wir variieren die Zeit rückwirkend, damit die Liste sortiert aussieht
                    # Jedes Ticket ist 2 Stunden älter als das vorherige
                    fake_time = base_time - timedelta(hours=i*2, minutes=random.randint(1, 59))
                    
                    cat = categories[i % len(categories)]
                    subj = subjects[i]
                    msg_content = f"Dies ist eine automatisch erstellte Testnachricht für das Ticket '{subj}'. Bitte um Hilfe."

                    # Ticket Objekt
                    ticket = Ticket(
                        user_id=ticket_user.id,
                        subject=subj,
                        category=cat,
                        status="open",
                        initial_message_content=msg_content,
                        created_at=fake_time
                    )
                    db.session.add(ticket)
                    db.session.flush() # Nötig, um ticket.id zu generieren

                    # Erste Nachricht im Chat-Verlauf (TicketMessage)
                    initial_msg = TicketMessage(
                        ticket_id=ticket.id,
                        sender_type='user',
                        sender_name=ticket_user.username,
                        content=msg_content,
                        created_at=fake_time,
                        read=False
                    )
                    db.session.add(initial_msg)

                db.session.commit()
                print("✅ 10 Test-Tickets erstellt.")
                
                # ========================================================
                # NEU: Erweitertes Ticket mit Chatverlauf
                # ========================================================
                print("Erstelle erweitertes Ticket mit Chatverlauf...")
                
                # Wir nehmen das erste Ticket (Login-Problem) und erweitern es
                extended_ticket = Ticket.query.filter_by(subject="Login funktioniert manchmal nicht").first()
                
                if extended_ticket:
                    # Chatverlauf mit verschiedenen Daten erstellen
                    chat_messages = [
                        # Tag 1: Ticket-Erstellung (bereits vorhanden als initial_msg)
                        
                        # Tag 1 - Später am Tag: Antwort vom Support
                        {
                            'sender_type': 'admin',
                            'sender_name': 'Support',
                            'content': 'Hallo! Danke für Ihre Meldung. Können Sie uns bitte genauer beschreiben, wann genau der Login nicht funktioniert? Handelt es sich um eine bestimmte Uhrzeit oder ein bestimmtes Gerät?',
                            'created_at': extended_ticket.created_at + timedelta(hours=2, minutes=15),
                            'read': False
                        },
                        
                        # Tag 1 - Abends: Antwort vom User
                        {
                            'sender_type': 'user',
                            'sender_name': ticket_user.username,
                            'content': 'Das Problem tritt meistens morgens zwischen 8 und 9 Uhr auf, wenn ich versuche mich vom Handy aus einzuloggen. Am PC funktioniert es normal.',
                            'created_at': extended_ticket.created_at + timedelta(hours=5, minutes=30),
                            'read': True
                        },
                        
                        # Tag 2 - Vormittag: Antwort vom Support
                        {
                            'sender_type': 'admin',
                            'sender_name': 'Support',
                            'content': 'Vielen Dank für die genaue Beschreibung! Das klingt nach einem bekannten Problem mit der mobilen Version. Wir prüfen das gerade. Können Sie mir bitte sagen, welchen Browser Sie auf dem Handy verwenden?',
                            'created_at': extended_ticket.created_at + timedelta(days=1, hours=10, minutes=45),
                            'read': True
                        },
                        
                        # Tag 2 - Nachmittag: Antwort vom User
                        {
                            'sender_type': 'user',
                            'sender_name': ticket_user.username,
                            'content': 'Ich benutze Safari auf dem iPhone. Das Problem tritt aber auch in der Chrome App auf. Vielleicht liegt es an der mobilen Internetverbindung?',
                            'created_at': extended_ticket.created_at + timedelta(days=1, hours=15, minutes=20),
                            'read': True
                        },
                        
                        # Tag 3 - Vormittag: Antwort vom Support
                        {
                            'sender_type': 'admin',
                            'sender_name': 'Support',
                            'content': 'Wir haben tatsächlich ein Problem mit der Session-Verwaltung auf mobilen Geräten identifiziert. Unser Entwicklungsteam arbeitet bereits an einem Fix. In der Zwischenzeit könnte es helfen, die App-Cache zu leeren oder die App neu zu installieren.',
                            'created_at': extended_ticket.created_at + timedelta(days=2, hours=9, minutes=10),
                            'read': True
                        },
                        
                        # Tag 4 - Mittag: Follow-up vom User
                        {
                            'sender_type': 'user',
                            'sender_name': ticket_user.username,
                            'content': 'Danke für die Info! Ich habe den Cache geleert und es scheint jetzt besser zu funktionieren. Gibt es schon einen Zeitplan für den Fix?',
                            'created_at': extended_ticket.created_at + timedelta(days=3, hours=12, minutes=0),
                            'read': True
                        },
                        
                        # Tag 4 - Nachmittag: Antwort vom Support
                        {
                            'sender_type': 'admin',
                            'sender_name': 'Support',
                            'content': 'Das freut mich zu hören! Der Fix ist für das nächste Update geplant, das voraussichtlich Ende nächster Woche erscheint. Ich halte Sie auf dem Laufenden. Wenn das Problem bis dahin wieder auftritt, melden Sie sich bitte erneut.',
                            'created_at': extended_ticket.created_at + timedelta(days=3, hours=16, minutes=30),
                            'read': True
                        },
                        
                        # Tag 7 - Vormittag: Abschluss vom Support
                        {
                            'sender_type': 'admin',
                            'sender_name': 'Support',
                            'content': 'Guten Tag! Nur eine kurze Info: Das Update mit dem Fix für das mobile Login-Problem wurde heute morgen veröffentlicht. Können Sie bitte testen, ob das Problem bei Ihnen jetzt behoben ist?',
                            'created_at': extended_ticket.created_at + timedelta(days=6, hours=11, minutes=0),
                            'read': False
                        },
                        
                        # Tag 7 - Nachmittag: Bestätigung vom User
                        {
                            'sender_type': 'user',
                            'sender_name': ticket_user.username,
                            'content': 'Perfekt! Habe es gerade getestet und es funktioniert einwandfrei. Vielen Dank für die schnelle Hilfe und die gute Kommunikation!',
                            'created_at': extended_ticket.created_at + timedelta(days=6, hours=14, minutes=45),
                            'read': True
                        },
                        
                        # Tag 7 - Abends: Abschluss vom Support
                        {
                            'sender_type': 'admin',
                            'sender_name': 'Support',
                            'content': 'Sehr gerne! Wir freuen uns, dass das Problem gelöst wurde. Das Ticket werde ich nun schließen. Bei weiteren Fragen können Sie jederzeit ein neues Ticket erstellen. Vielen Dank für Ihr Feedback!',
                            'created_at': extended_ticket.created_at + timedelta(days=6, hours=18, minutes=20),
                            'read': False
                        }
                    ]
                    
                    # Alle Chat-Nachrichten hinzufügen
                    for msg_data in chat_messages:
                        msg = TicketMessage(
                            ticket_id=extended_ticket.id,
                            sender_type=msg_data['sender_type'],
                            sender_name=msg_data['sender_name'],
                            content=msg_data['content'],
                            created_at=msg_data['created_at'],
                            read=msg_data['read']
                        )
                        db.session.add(msg)
                    
                    # Ticket als geschlossen markieren (da Problem gelöst)
                    extended_ticket.status = 'closed'
                    
                    db.session.commit()
                    print("✅ Erweitertes Ticket mit Chatverlauf erstellt (11 zusätzliche Nachrichten).")
                
            else:
                print("ℹ️ Tickets für 'admin' existieren bereits.")
                
                # Prüfen, ob wir den erweiterten Chatverlauf nachträglich hinzufügen müssen
                extended_ticket = Ticket.query.filter_by(subject="Login funktioniert manchmal nicht").first()
                
                if extended_ticket:
                    # Prüfen, ob schon Nachrichten vorhanden sind (außer der initialen)
                    existing_messages = TicketMessage.query.filter(
                        TicketMessage.ticket_id == extended_ticket.id,
                        TicketMessage.id != extended_ticket.messages.first().id  # Nicht die Initialnachricht
                    ).count()
                    
                    if existing_messages == 0:
                        print("Ergänze Chatverlauf für bestehendes Ticket...")
                        
                        # Gleicher Chatverlauf wie oben...
                        chat_messages = [
                            # ... (gleicher Code wie oben) ...
                            {
                                'sender_type': 'admin',
                                'sender_name': 'Support',
                                'content': 'Hallo! Danke für Ihre Meldung. Können Sie uns bitte genauer beschreiben, wann genau der Login nicht funktioniert? Handelt es sich um eine bestimmte Uhrzeit oder ein bestimmtes Gerät?',
                                'created_at': extended_ticket.created_at + timedelta(hours=2, minutes=15),
                                'read': False
                            },
                            {
                                'sender_type': 'user',
                                'sender_name': ticket_user.username,
                                'content': 'Das Problem tritt meistens morgens zwischen 8 und 9 Uhr auf, wenn ich versuche mich vom Handy aus einzuloggen. Am PC funktioniert es normal.',
                                'created_at': extended_ticket.created_at + timedelta(hours=5, minutes=30),
                                'read': True
                            },
                            {
                                'sender_type': 'admin',
                                'sender_name': 'Support',
                                'content': 'Vielen Dank für die genaue Beschreibung! Das klingt nach einem bekannten Problem mit der mobilen Version. Wir prüfen das gerade. Können Sie mir bitte sagen, welchen Browser Sie auf dem Handy verwenden?',
                                'created_at': extended_ticket.created_at + timedelta(days=1, hours=10, minutes=45),
                                'read': True
                            },
                            {
                                'sender_type': 'user',
                                'sender_name': ticket_user.username,
                                'content': 'Ich benutze Safari auf dem iPhone. Das Problem tritt aber auch in der Chrome App auf. Vielleicht liegt es an der mobilen Internetverbindung?',
                                'created_at': extended_ticket.created_at + timedelta(days=1, hours=15, minutes=20),
                                'read': True
                            },
                            {
                                'sender_type': 'admin',
                                'sender_name': 'Support',
                                'content': 'Wir haben tatsächlich ein Problem mit der Session-Verwaltung auf mobilen Geräten identifiziert. Unser Entwicklungsteam arbeitet bereits an einem Fix. In der Zwischenzeit könnte es helfen, die App-Cache zu leeren oder die App neu zu installieren.',
                                'created_at': extended_ticket.created_at + timedelta(days=2, hours=9, minutes=10),
                                'read': True
                            },
                            {
                                'sender_type': 'user',
                                'sender_name': ticket_user.username,
                                'content': 'Danke für die Info! Ich habe den Cache geleert und es scheint jetzt besser zu funktionieren. Gibt es schon einen Zeitplan für den Fix?',
                                'created_at': extended_ticket.created_at + timedelta(days=3, hours=12, minutes=0),
                                'read': True
                            },
                            {
                                'sender_type': 'admin',
                                'sender_name': 'Support',
                                'content': 'Das freut mich zu hören! Der Fix ist für das nächste Update geplant, das voraussichtlich Ende nächster Woche erscheint. Ich halte Sie auf dem Laufenden. Wenn das Problem bis dahin wieder auftritt, melden Sie sich bitte erneut.',
                                'created_at': extended_ticket.created_at + timedelta(days=3, hours=16, minutes=30),
                                'read': True
                            },
                            {
                                'sender_type': 'admin',
                                'sender_name': 'Support',
                                'content': 'Guten Tag! Nur eine kurze Info: Das Update mit dem Fix für das mobile Login-Problem wurde heute morgen veröffentlicht. Können Sie bitte testen, ob das Problem bei Ihnen jetzt behoben ist?',
                                'created_at': extended_ticket.created_at + timedelta(days=6, hours=11, minutes=0),
                                'read': False
                            },
                            {
                                'sender_type': 'user',
                                'sender_name': ticket_user.username,
                                'content': 'Perfekt! Habe es gerade getestet und es funktioniert einwandfrei. Vielen Dank für die schnelle Hilfe und die gute Kommunikation!',
                                'created_at': extended_ticket.created_at + timedelta(days=6, hours=14, minutes=45),
                                'read': True
                            },
                            {
                                'sender_type': 'admin',
                                'sender_name': 'Support',
                                'content': 'Sehr gerne! Wir freuen uns, dass das Problem gelöst wurde. Das Ticket werde ich nun schließen. Bei weiteren Fragen können Sie jederzeit ein neues Ticket erstellen. Vielen Dank für Ihr Feedback!',
                                'created_at': extended_ticket.created_at + timedelta(days=6, hours=18, minutes=20),
                                'read': False
                            }
                        ]
                        
                        for msg_data in chat_messages:
                            msg = TicketMessage(
                                ticket_id=extended_ticket.id,
                                sender_type=msg_data['sender_type'],
                                sender_name=msg_data['sender_name'],
                                content=msg_data['content'],
                                created_at=msg_data['created_at'],
                                read=msg_data['read']
                            )
                            db.session.add(msg)
                        
                        extended_ticket.status = 'closed'
                        db.session.commit()
                        print("✅ Chatverlauf nachträglich zum Ticket hinzugefügt.")

            # ========================================================
            # ENDE NEU
            # ========================================================

            admin_username = os.environ.get('ADMIN_USERNAME', 'AdminZugang')
            admin_password = os.environ.get('ADMIN_PASSWORD', 'adminzugang')

            admin_user = User.query.filter_by(username=admin_username).first()
            if not admin_user:
                admin_user = User(
                    username=admin_username,
                    is_admin=True,
                    first_played=datetime.now(timezone.utc),
                    agb_accepted=True
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

# ===============
# ERROR HANDLER
# ===============

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    """Behandelt CSRF-Fehler (Session abgelaufen)"""
    # Logge den Benutzer sicherheitshalber aus
    session.clear()
    flash('Deine Sitzung ist abgelaufen. Bitte melde dich erneut an.', 'error')
    return redirect(url_for('index'))

@app.errorhandler(405)
def method_not_allowed(error):
    """Behandelt ungültige HTTP-Methoden"""
    # Session beenden bei ungültiger Zugriffsmethode
    if 'quiz_data' in session:
        room_id = session['quiz_data'].get('room_id')
        if room_id:
            stop_timer(room_id)
    
    session.clear()
    flash('Ungültige Zugriffsmethode für diese Seite.', 'error')
    return render_template('index.html'), 405

# ============================================
# DECORATOR-FUNKTIONEN FÜR ZUGRIFFSKONTROLLE
# ============================================
    
def quiz_required(f):
    """Prüft ob ein Quiz aktiv ist - nur für Quiz-Routen"""
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

def admin_required(f):
    """Prüft ob Benutzer Admin-Rechte hat"""
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
    """Prüft ob Benutzer angemeldet ist"""
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
            if route_name == 'legal':
                flash('Rechtliche Informationen nur über Startseite erreichbar.', 'error')
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
            # WICHTIG: Nur für GET-Requests redirecten
            # POST-Requests (wie cancel_quiz) sollten durchgelassen werden
            if request.method == 'GET':
                # Prüfe ob wir bereits auf show_question sind
                if request.endpoint == 'show_question':
                    # Bereits auf Quiz-Seite, erlaube Zugriff
                    return f(*args, **kwargs)
                
                # User versucht Quiz zu verlassen
                print(f"prevent_quiz_exit: User versucht von {request.endpoint} wegzunavigieren")
                
                # Hole aktuelle Frage
                quiz_data = session.get('quiz_data', {})
                current_q = quiz_data.get('current_index', 0) + 1
                
                # Redirect zur aktuellen Quiz-Frage mit Modal-Parameter
                return redirect(url_for('show_question', q=current_q, show_exit_modal='true'))
        
        return f(*args, **kwargs)
    return decorated_function

# ===================
# ROUTEN (ENDPUNKTE)
# ===================

@app.route('/')
@prevent_quiz_exit 
def index():
    """Startseite der Anwendung"""
    # Wenn Benutzer angemeldet ist: serverseitig ausloggen
    if 'username' in session:
        # Falls ein Quiz läuft: Timer stoppen
        if 'quiz_data' in session:
            room_id = session['quiz_data'].get('room_id')
            if room_id:
                stop_timer(room_id)
        # Nur User-Daten entfernen
        keys_to_remove = ['username', 'quiz_data', 'user_id', 'is_admin']
        for key in keys_to_remove:
            session.pop(key, None)

    # Prüfe ob AGB Modal gezeigt werden soll
    show_agb_modal = request.args.get('show_agb_modal') == 'true'

    # Ermittle, ob es ein pending für registration oder login gibt
    pending_registration = session.get('pending_registration')
    pending_login = session.get('pending_login')

    agb_action = None
    if show_agb_modal:
        if pending_registration:
            agb_action = 'register'
        elif pending_login:
            agb_action = 'login'

    return render_template(
        'index.html',
        show_agb_modal=show_agb_modal,
        agb_action=agb_action,
        pending_registration=pending_registration
    )

@app.route('/login', methods=['POST'])
def login():
    """Verarbeitet Benutzer-Login mit AGB-Überprüfung"""
    try:
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        agb_accepted = request.form.get('agb_accepted', 'false') == 'true'

        if not username or not password:
            flash('Bitte fülle alle Felder aus', 'error')
            return redirect(url_for('index'))

        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            flash('Ungültige Anmeldedaten', 'error')
            return redirect(url_for('index'))
        
        # Prüfe ob AGBs bereits akzeptiert wurden
        if user.agb_accepted:
            # AGBs bereits akzeptiert - normaler Login
            session['username'] = username
            session.permanent = False
            target_endpoint = 'admin_panel' if user.is_admin else 'playermenu'
            return redirect(url_for(target_endpoint))
        else:
            # AGBs noch nicht akzeptiert - prüfe ob in diesem Login akzeptiert
            if agb_accepted:
                # AGBs wurden in diesem Login akzeptiert
                user.agb_accepted = True
                db.session.commit()
                session['username'] = username
                session.permanent = False
                target_endpoint = 'admin_panel' if user.is_admin else 'playermenu'
                return redirect(url_for(target_endpoint))
            else:
                # AGBs noch nicht akzeptiert - zeige Modal
                session['pending_login'] = {
                    'user_id': user.id,
                    'username': user.username
                }
                return redirect(url_for('index', show_agb_modal='true'))

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
    """Registriert einen neuen Benutzer"""
    try:
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        agb_accepted = request.form.get('agb_accepted') == 'true' 

        # Validierungen
        if not username or not password:
            flash('Um einen Account anzulegen bitte Usernamen und Passwort wählen!', 'error')
            return redirect(url_for('index'))

        if len(username) > 12:
            flash('Benutzername darf maximal 12 Zeichen haben!', 'error')
            return redirect(url_for('index'))

        if User.query.filter_by(username=username).first():
            flash('Benutzername bereits vergeben', 'error')
            return redirect(url_for('index'))

        if len(password) < 5:
            flash('Passwort muss mindestens 5 Zeichen haben!', 'error')
            return redirect(url_for('index'))
        
        # Prüfe AGB-Akzeptierung
        if not agb_accepted:
            # Speichere die bereits validierten Daten für das Modal
            session['pending_registration'] = { 'username': username }
            return redirect(url_for('index', show_agb_modal='true'))

        # Benutzer anlegen
        new_user = User(
            username=username,
            first_played=datetime.now(timezone.utc),
            agb_accepted=True 
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        # Direkt einloggen
        session['username'] = username
        session.permanent = False

        target_endpoint = 'admin_panel' if new_user.is_admin else 'playermenu'
        return redirect(url_for(target_endpoint))

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
    
@app.route('/check_username', methods=['GET'])
def check_username():
    """API-Endpunkt zur Überprüfung der Verfügbarkeit eines Benutzernamens"""
    try:
        username = (request.args.get('username') or '').strip()
        if not username:
            return jsonify({'available': False, 'message': 'Bitte gib einen Benutzernamen an.'}), 400
        if len(username) > 12:
            return jsonify({'available': False, 'message': 'Benutzername darf maximal 12 Zeichen haben!'}), 200

        # Prüfung in DB
        user = User.query.filter_by(username=username).first()
        if user:
            return jsonify({'available': False, 'message': 'Benutzername bereits vergeben.'}), 200

        return jsonify({'available': True}), 200

    except (SQLAlchemyError, OperationalError) as e:
        print(f"Datenbankfehler in check_username: {str(e)}")
        return jsonify({'available': False, 'message': 'Datenbankfehler. Bitte versuche es später erneut.'}), 500
    except Exception as e:
        print(f"Unerwarteter Fehler in check_username: {str(e)}")
        return jsonify({'available': False, 'message': 'Ein unerwarteter Fehler ist aufgetreten.'}), 500

@app.route('/accept_agb', methods=['POST'])
def accept_agb():
    """Verarbeitet die AGB-Akzeptierung für ausstehende Logins"""
    try:
        pending = session.get('pending_login')
        if not pending:
            flash('Sitzung abgelaufen. Bitte melden Sie sich erneut an.', 'error')
            return redirect(url_for('index'))
        
        # Benutzer per ID holen
        user = None
        user_id = pending.get('user_id')
        if user_id:
            user = db.session.get(User, user_id)
        else:
            user = User.query.filter_by(username=pending.get('username')).first()

        if not user:
            session.pop('pending_login', None)
            flash('Ungültige Anmeldedaten', 'error')
            return redirect(url_for('index'))
        
        # Aktualisiere AGB-Status
        user.agb_accepted = True
        db.session.commit()
        
        # Logge den Benutzer ein
        session['username'] = user.username
        session.pop('pending_login', None)
        session.permanent = False

        target_endpoint = 'admin_panel' if user.is_admin else 'playermenu'
        return redirect(url_for(target_endpoint))
        
    except (SQLAlchemyError, OperationalError) as e:
        db.session.rollback()
        print(f"Datenbankfehler bei AGB-Akzeptierung: {str(e)}")
        flash('Verbindungsproblem zur Datenbank. Bitte versuchen Sie es später erneut.', 'error')
        return redirect(url_for('index'))
    except Exception as e:
        db.session.rollback()
        print(f"Unerwarteter Fehler bei AGB-Akzeptierung: {str(e)}")
        flash('Ein Fehler ist aufgetreten. Bitte versuchen Sie es erneut.', 'error')
        return redirect(url_for('index'))

@app.route("/settings")
@login_required
@prevent_quiz_exit
def settings():
    """Einstellungsseite für angemeldete Benutzer"""
    return render_template("settings.html", is_logged_in=True)

@app.route('/change_username', methods=['POST'])
def change_username():
    """Ändert den Benutzernamen eines angemeldeten Benutzers."""
    try:
        new_username = request.form.get('new_username', '').strip()
        password = request.form.get('password', '')

        # Validierung der Eingaben
        if not new_username or not password:
            flash("Bitte fülle alle Felder aus!", "error")
            return redirect(url_for('settings'))

        # Benutzer aus Session verwenden
        if 'username' not in session:
            flash("Nicht angemeldet!", "error")
            return redirect(url_for('settings'))

        user = User.query.filter_by(username=session['username']).first()
        if not user:
            flash("Benutzer nicht gefunden!", "error")
            return redirect(url_for('settings'))

        # Passwort prüfen
        if not user.check_password(password):
            flash("Falsches Passwort!", "error")
            return redirect(url_for('settings'))

        # Neuer Benutzername darf nicht zu lang sein
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

        # Session aktualisieren
        session['username'] = new_username

        flash("Benutzername erfolgreich geändert!", "success")
        return redirect(url_for('settings'))

    except (SQLAlchemyError, OperationalError) as e:
        db.session.rollback()
        print(f"Datenbankfehler beim Ändern des Benutzernamens: {str(e)}")
        flash("Verbindungsproblem zur Datenbank. Bitte versuche es später erneut.", "error")
        return redirect(url_for('settings'))
    except Exception as e:
        db.session.rollback()
        print(f"Unerwarteter Fehler beim Ändern des Benutzernamens: {str(e)}")
        flash("Ein unerwarteter Fehler ist aufgetreten.", "error")
        return redirect(url_for('settings'))

@app.route('/change_password', methods=['POST'])
def change_password():
    """Ändert das Passwort eines angemeldeten Benutzers"""
    try:
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Validierung der Eingaben
        if not current_password or not new_password or not confirm_password:
            flash("Bitte fülle alle Felder aus!", "error")
            return redirect(url_for('settings'))

        # Benutzer aus Session verwenden
        if 'username' not in session:
            flash("Nicht angemeldet!", "error")
            return redirect(url_for('settings'))

        user = User.query.filter_by(username=session['username']).first()
        if not user:
            flash("Benutzer nicht gefunden!", "error")
            return redirect(url_for('settings'))

        # Aktuelles Passwort prüfen
        if not user.check_password(current_password):
            flash("Aktuelles Passwort ist falsch!", "error")
            return redirect(url_for('settings'))

        # Prüfen, ob neues Passwort korrekt eingegeben wurde
        if new_password != confirm_password:
            flash("Neue Passwörter stimmen nicht überein!", "error")
            return redirect(url_for('settings'))

        if len(new_password) < 5:
            flash("Neues Passwort muss mindestens 5 Zeichen haben!", "error")
            return redirect(url_for('settings'))

        # Neues Passwort setzen
        user.set_password(new_password)
        db.session.commit()

        flash("Passwort erfolgreich geändert!", "success")
        return redirect(url_for('settings'))

    except (SQLAlchemyError, OperationalError) as e:
        db.session.rollback()
        print(f"Datenbankfehler beim Ändern des Passworts: {str(e)}")
        flash("Verbindungsproblem zur Datenbank. Bitte versuche es später erneut.", "error")
        return redirect(url_for('settings'))
    except Exception as e:
        db.session.rollback()
        print(f"Unerwarteter Fehler beim Ändern des Passworts: {str(e)}")
        flash("Ein unerwarteter Fehler ist aufgetreten.", "error")
        return redirect(url_for('settings'))

@app.route('/change_avatar', methods=['POST'])
def change_avatar():
    """Ändert den Avatar eines Benutzers"""
    try:
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

    except (SQLAlchemyError, OperationalError) as e:
        db.session.rollback()
        print(f"Datenbankfehler beim Ändern des Avatars: {str(e)}")
        return jsonify({"success": False, "error": "Verbindungsproblem zur Datenbank. Bitte versuche es später erneut."})
    except Exception as e:
        db.session.rollback()
        print(f"Unerwarteter Fehler beim Ändern des Avatars: {str(e)}")
        return jsonify({"success": False, "error": "Ein unerwarteter Fehler ist aufgetreten."})

@app.route('/reject_agb', methods=['POST'])
def reject_agb():
    """Verarbeitet die Ablehnung der AGBs"""
    try:
        confirm_reject = request.form.get('confirm_reject', 'false') == 'true'

        # Validierung
        if not confirm_reject:
            flash("Bitte bestätige die Ablehnung der AGBs und Datenschutzverordnung!", "error")
            return redirect(url_for('settings'))

        # Benutzer aus Session verwenden
        if 'username' not in session:
            flash("Nicht angemeldet!", "error")
            return redirect(url_for('settings'))

        user = User.query.filter_by(username=session['username']).first()
        if not user:
            flash("Benutzer nicht gefunden!", "error")
            return redirect(url_for('settings'))

        # AGBs ablehnen
        user.agb_accepted = False
        db.session.commit()

        # Benutzer abmelden
        session.clear()
        flash("AGBs abgelehnt. Du wurdest abgemeldet.", "success")
        return redirect(url_for('index'))

    except (SQLAlchemyError, OperationalError) as e:
        db.session.rollback()
        print(f"Datenbankfehler beim Ablehnen der AGBs: {str(e)}")
        flash("Verbindungsproblem zur Datenbank. Bitte versuche es später erneut.", "error")
        return redirect(url_for('settings'))
    except Exception as e:
        db.session.rollback()
        print(f"Unerwarteter Fehler beim Ablehnen der AGBs: {str(e)}")
        flash("Ein unerwarteter Fehler ist aufgetreten.", "error")
        return redirect(url_for('settings'))

@app.route('/delete_account', methods=['POST'])
def delete_account():
    """Löscht den Account eines Benutzers dauerhaft"""
    try:
        confirm_delete = request.form.get('confirm_delete', '').strip()

        # Validierung
        if not confirm_delete:
            flash("Bitte fülle alle Felder aus!", "error")
            return redirect(url_for('settings'))

        # Benutzer aus Session verwenden
        if 'username' not in session:
            flash("Nicht angemeldet!", "error")
            return redirect(url_for('settings'))

        user = User.query.filter_by(username=session['username']).first()
        if not user:
            flash("Benutzer nicht gefunden!", "error")
            return redirect(url_for('settings'))

        # Bestätigung prüfen
        if confirm_delete != "DELETE":
            flash("Bitte schreibe exakt 'DELETE', um den Account zu löschen.", "error")
            return redirect(url_for('settings'))

        # Benutzer löschen
        db.session.delete(user)
        db.session.commit()
        session.clear()

        flash("Dein Account wurde dauerhaft gelöscht.", "success")
        return redirect(url_for('index'))

    except (SQLAlchemyError, OperationalError) as e:
        db.session.rollback()
        print(f"Datenbankfehler beim Löschen des Accounts: {str(e)}")
        flash("Verbindungsproblem zur Datenbank. Bitte versuche es später erneut.", "error")
        return redirect(url_for('settings'))
    except Exception as e:
        db.session.rollback()
        print(f"Unerwarteter Fehler beim Löschen des Accounts: {str(e)}")
        flash("Ein unerwarteter Fehler ist aufgetreten.", "error")
        return redirect(url_for('settings'))

@app.route('/playermenu')
@login_required
@prevent_quiz_exit 
def playermenu():
    """Hauptmenü für angemeldete Spieler"""
    try:
        user = User.query.filter_by(username=session['username']).first()
        if not user:
            session.clear()
            flash('Benutzer nicht gefunden. Bitte melden Sie sich erneut an.', 'error')
            return redirect(url_for('index'))
        
        # Stelle sicher, dass avatar immer einen Wert hat
        avatar = user.avatar if user.avatar else "avatar0.png"

        # Hole alle ungelesenen News-IDs
        unseen_count = News.query.filter(~News.viewers.any(id=user.id)).count()

        # Ticket-Count holen
        ticket_count = get_unread_ticket_messages_count(user)
            
        return render_template(
            'playermenu.html',
            username=user.username,
            avatar=avatar,
            first_played=user.first_played,
            highscore=user.highscore,
            number_of_games=user.number_of_games,
            news_notification_count=unseen_count,
            ticket_notification_count=ticket_count
        )
    except (SQLAlchemyError, OperationalError) as e:
        print(f"Datenbankfehler im Playermenu: {str(e)}")
        flash('Verbindungsproblem zur Datenbank. Bitte versuche es später erneut.', 'error')
        return redirect(url_for('index'))
    except Exception as e:
        print(f"Unerwarteter Fehler im Playermenu: {str(e)}")
        flash('Ein unerwarteter Fehler ist aufgetreten.', 'error')
        return redirect(url_for('index'))

@app.route('/update_avatar', methods=['POST'])
@login_required
def update_avatar():
    """API-Endpunkt zum Aktualisieren des Avatars (AJAX)"""
    try:
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

    except (SQLAlchemyError, OperationalError) as e:
        db.session.rollback()
        print(f"Datenbankfehler beim Aktualisieren des Avatars: {str(e)}")
        return jsonify({"success": False, "error": "Verbindungsproblem zur Datenbank. Bitte versuche es später erneut."})
    except Exception as e:
        db.session.rollback()
        print(f"Unerwarteter Fehler beim Aktualisieren des Avatars: {str(e)}")
        return jsonify({"success": False, "error": "Ein unerwarteter Fehler ist aufgetreten."})

@app.route('/homepage')
@login_required
@prevent_quiz_exit
def homepage():
    """Homepage für angemeldete Benutzer (Themen)"""
    try:
        # Alte Auswertungsdaten löschen, wenn Benutzer zur Homepage zurückkehrt
        if 'evaluation_data' in session:
            session.pop('evaluation_data', None)
            
        if 'username' in session:
            user = User.query.filter_by(username=session['username']).first()

            ticket_count = 0
            if user:
                ticket_count = get_unread_ticket_messages_count(user)

            # Zeige Info-Nachricht nur beim ersten Aufruf
            if not session.get('info_shown'):
                flash('Du kannst bis zu 16 Themen gleichzeitig auswählen!', 'info')
                session['info_shown'] = True
            return render_template(
                'homepage.html',
                username=session['username'],
                highscore=user.highscore if user else 0,
                ticket_notification_count=ticket_count
            )
        return redirect(url_for('index'))
    except (SQLAlchemyError, OperationalError) as e:
        print(f"Datenbankfehler auf der Homepage: {str(e)}")
        flash('Verbindungsproblem zur Datenbank. Bitte versuche es später erneut.', 'error')
        return redirect(url_for('index'))
    
@app.route('/logout')
@login_required
def logout():
    """Loggt den Benutzer aus"""
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
    """Startet ein benutzerdefiniertes Quiz"""
    try:
        # Alte Auswertungsdaten löschen
        if 'evaluation_data' in session:
            session.pop('evaluation_data', None)
        if 'pending_navigation' in session:
            session.pop('pending_navigation', None)

        if request.method != 'POST':
            abort(405)

        # Alten Timer stoppen
        if 'quiz_data' in session:
            old_room_id = session['quiz_data'].get('room_id')
            if old_room_id:
                stop_timer(old_room_id)

        if 'username' not in session:
            return redirect(url_for('index'))
        
        selected_topics = request.form.getlist('topics')
        random_mode = request.form.get('random_mode') == 'true'
        
        all_questions = []
        selected_questions = []
        subject_display = ""

        # =====================
        # LOGIK ZUFALLSMODUS
        # =====================

        if random_mode:
            
            # 1. Alle verfügbaren Themen holen
            all_topics = db.session.query(Question.subject.distinct()).all()
            all_topics = [topic[0] for topic in all_topics]
            
            # 2. Zufällige Anzahl von Themen auswählen (zwischen 1 und 15)
            num_random_topics = random.randint(1, min(15, len(all_topics)))
            selected_topics = random.sample(all_topics, num_random_topics)
            
            subject_display = f"Zufällige Themen ({len(selected_topics)} Kategorien)"

            # 3. Hole ALLE Fragen aus dem Pool der gewählten Themen
            conditions = [func.lower(Question.subject) == func.lower(topic) for topic in selected_topics]
            all_questions = Question.query.filter(or_(*conditions)).all()

            if not all_questions:
                flash('Keine Fragen für die ausgewählten Themen gefunden', 'error')
                return redirect(url_for('homepage'))
            
            # 4. Mische den gesamten Pool und nimm die ersten 30
            random.shuffle(all_questions)
            selected_questions = all_questions[:30]
        
        else:
            # ==========================
            # LOGIK FÜR MANUELLEN MODUS
            # ==========================
            if not selected_topics:
                flash('Bitte wähle mindestens ein Thema aus', 'error')
                return redirect(url_for('homepage'))

            subject_display = ', '.join(selected_topics)

            conditions = [func.lower(Question.subject) == func.lower(topic) for topic in selected_topics]
            all_questions = Question.query.filter(or_(*conditions)).all()

            if not all_questions:
                flash('Keine Fragen für die ausgewählten Themen gefunden', 'error')
                return redirect(url_for('homepage'))

            # Fragen auswählen basierend auf den ausgewählten Themen
            questions_by_topic = defaultdict(list)
            for q in all_questions:
                questions_by_topic[q.subject.lower()].append(q)
            
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
            
            # Mischen der finalen Liste
            random.shuffle(selected_questions)
            
            # Stelle sicher, dass maximal 30 Fragen genommen werden
            selected_questions = selected_questions[:30]
        
        # Finale Anzahl der Fragen
        num_questions = len(selected_questions)

        if num_questions == 0:
            flash('Konnte keine Fragen für die Auswahl finden', 'error')
            return redirect(url_for('homepage'))

        # Room-ID für WebSocket erstellen
        room_id = str(uuid.uuid4())
        
        session['quiz_data'] = {
            'subject': subject_display,
            'questions': [q.id for q in selected_questions],
            'current_index': 0,
            'total_questions': num_questions,
            'score': 0,
            'correct_count': 0,
            'room_id': room_id,
            'random_mode': random_mode,
            'random_topics_count': len(selected_topics) if random_mode else None
        }
        
        return redirect(url_for('show_question'))

    except (SQLAlchemyError, OperationalError) as e:
        print(f"Datenbankfehler in start_custom_quiz: {str(e)}")
        flash('Verbindungsproblem zur Datenbank. Bitte versuche es später erneut.', 'error')
        return redirect(url_for('homepage'))
    except Exception as e:
        print(f"Unerwarteter Fehler in start_custom_quiz: {str(e)}")
        flash('Ein unerwarteter Fehler ist aufgetreten.', 'error')
        return redirect(url_for('homepage'))

@app.route('/show_question')
@login_required
@quiz_required 
def show_question():
    """Zeigt die aktuelle Quiz-Frage"""
    if request.method != 'GET':
        abort(405)

    try:
        if 'quiz_data' not in session:
            return redirect(url_for('homepage'))
        
        quiz_data = session['quiz_data']

        # 1. Zuerst prüfen, ob das Quiz beendet ist
        if quiz_data.get('completed', False):
            print("show_question: Quiz ist 'completed', redirecting to evaluate.")
            return redirect(url_for('evaluate_quiz'))

        # 2. Prüfen, ob die aktuelle Frage bereits beantwortet wurde
        if quiz_data.get('answered', False):
            print(f"show_question: Frage {quiz_data['current_index']+1} war bereits beantwortet. Forciere nächste Frage.")
            
            # 'answered'-Flag entfernen
            quiz_data.pop('answered', None)
            
            current_index = quiz_data['current_index']
            total_questions = quiz_data['total_questions']
            
            # Wenn letzte Frage
            if current_index >= total_questions - 1:
                print("show_question: Letzte Frage. Setze 'completed' und redirect to evaluate.")
                quiz_data['completed'] = True
                session['quiz_data'] = quiz_data
                return redirect(url_for('evaluate_quiz'))
            
            # Wenn NICHT letzte Frage -> Index serverseitig vorrücken
            quiz_data['current_index'] += 1
            
            # Optionen für die (jetzt neue) nächste Frage zurücksetzen
            quiz_data.pop('options_order', None)
            
            # Timer für die neue Frage zurücksetzen
            room_id = quiz_data.get('room_id')
            if room_id:
                stop_timer(room_id)
                get_or_create_timer(room_id)
                
            # Session speichern
            session['quiz_data'] = quiz_data
            session.modified = True
            
            # Redirect zur URL der NEUEN Frage
            new_question_number = quiz_data['current_index'] + 1
            print(f"show_question: Redirecting to new question q={new_question_number}")
            return redirect(url_for('show_question', q=new_question_number))

        # URL-Parameter q handling: 1-basierter Index
        q_param = request.args.get('q')
        if q_param is not None:
            try:
                q_index = int(q_param) - 1
            except ValueError:
                flash('Ungültiger Frage-Parameter.', 'error')
                return redirect(url_for('homepage'))

            if q_index < 0 or q_index >= quiz_data.get('total_questions', 0):
                flash('Frage nicht gefunden.', 'error')
                return redirect(url_for('homepage'))

            if q_index != quiz_data.get('current_index', 0):
                return redirect(url_for('show_question', q=quiz_data['current_index'] + 1))

        # Timer-Zeit holen
        room_id = quiz_data.get('room_id')
        time_left = 30
        
        if room_id:
            with timer_lock:
                timer = active_timers.get(room_id)
                if timer:
                    if timer.timed_out and not quiz_data.get('answered', False):
                        print(f"Sitzung desynchronisiert für Raum {room_id}. Korrigiere serverseitig...")
                        result = _process_answer(room_id, '', 0) 
                        if 'error' in result:
                            print(f"Fehler bei Sitzungs-Heilung: {result['error']}")
                        else:
                            quiz_data = session['quiz_data'] 
                        timer.timed_out = False 
                    elif timer.is_running:
                        time_left = timer.get_time_left()
        
        current_index = quiz_data['current_index']
        question = db.session.get(Question, quiz_data['questions'][current_index])
        
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
        show_exit_modal = request.args.get('show_exit_modal') == 'true'
        
        print(f"show_question: show_exit_modal={show_exit_modal}, current_index={current_index}")
        
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
            show_exit_modal=show_exit_modal
        ))
        
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        return response
    
    except (SQLAlchemyError, OperationalError) as e:
        print(f"Datenbankfehler in show_question: {str(e)}")
        flash('Verbindungsproblem zur Datenbank. Bitte versuche es später erneut.', 'error')
        return redirect(url_for('homepage'))
    except Exception as e:
        print(f"Unerwarteter Fehler in show_question: {str(e)}")
        flash('Ein unerwarteter Fehler ist aufgetreten.', 'error')
        return redirect(url_for('homepage'))

@app.route('/check_answer', methods=['POST'])
@login_required
@quiz_required 
def check_answer():
    """Überprüft eine Quiz-Antwort (AJAX-Endpunkt)"""
    if request.method != 'POST':
        abort(405)

    try:
        if 'quiz_data' not in session:
            return jsonify({'error': 'Session expired'}), 400
            
        quiz_data = session['quiz_data']
        current_index = quiz_data['current_index']
        question_id = quiz_data['questions'][current_index]
        question = db.session.get(Question, question_id)
        
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
    """Lädt die nächste Quiz-Frage (AJAX-Endpunkt)."""
    if request.method != 'POST':
        abort(405)
    
    try:
        if 'quiz_data' not in session or 'username' not in session:
            return jsonify({'redirect': url_for('homepage')})
        
        quiz_data = session['quiz_data']

        if 'answered' not in quiz_data or not quiz_data['answered']:
            print(f"WARNUNG: next_question ohne 'answered'-Flag aufgerufen. User: {session['username']}")
            # Sende die aktuellen Daten einfach nochmal, ohne den Index zu erhöhen
            question = db.session.get(Question, quiz_data['questions'][quiz_data['current_index']])
            options = quiz_data.get('options_order', [question.true, question.wrong1, question.wrong2, question.wrong3])
            
            return jsonify({
                'question': question.question,
                'options': options,
                'progress': quiz_data['current_index'] + 1,
                'total_questions': quiz_data['total_questions'],
                'score': quiz_data['score']
            })
        
        # Entferne "answered" Flag
        if 'answered' in quiz_data:
            del quiz_data['answered']

        # Prüfe ob dies die letzte Frage war, die gerade beantwortet wurde
        current_index_after_answer = quiz_data['current_index']
        
        # Wenn die gerade beantwortete Frage die letzte war
        if current_index_after_answer >= quiz_data['total_questions'] - 1:
            quiz_data['completed'] = True
            session['quiz_data'] = quiz_data
            return jsonify({'redirect': url_for('evaluate_quiz')})
        
        quiz_data['current_index'] += 1
        
        # Optionen für die nächste Frage zurücksetzen
        if 'options_order' in quiz_data:
            del quiz_data['options_order']
        
        session['quiz_data'] = quiz_data

        room_id = quiz_data.get('room_id')
        if room_id:
            print(f"Setze Timer für nächste Frage in Raum {room_id} zurück")

            # 1. Stoppt den alten Timer und löscht ihn aus dem 'active_timers'-Dict
            stop_timer(room_id)
            
            # 2. Erstellt eine brandneue Timer-Instanz, da die alte gelöscht wurde
            get_or_create_timer(room_id)
        
        # Frage als JSON zurückgeben
        question = db.session.get(Question, quiz_data['questions'][quiz_data['current_index']])
        options = [question.true, question.wrong1, question.wrong2, question.wrong3]
        random.shuffle(options)

        quiz_data['options_order'] = options
        session['quiz_data'] = quiz_data
        session.modified = True
        
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
    """Zeigt die Auswertung eines abgeschlossenen Quiz an und speichert Ergebnisse."""
    try:
        # Prüfe, ob wir bereits fertige Auswertungsdaten in der Session haben
        if 'evaluation_data' in session:
            data = session['evaluation_data']
            
            # Benutzerdaten für Avataranzeige nachladen
            user = User.query.filter_by(username=session['username']).first()
            user_avatar = user.avatar if user else "avatar0.png"
            
            # Seite rendern mit den gespeicherten Daten
            return render_template(
                'evaluate.html',
                score=data['score'],
                total=data['total'],
                correct_answers=data['correct_answers'],
                new_highscore=data['new_highscore'],
                highscore=data['highscore'],
                user_avatar=user_avatar
            )
        
        # Sicherheitsprüfung: Gibt es Quiz-Daten
        if 'quiz_data' not in session or 'username' not in session:
            flash('Kein Quiz zur Auswertung gefunden.', 'error')
            return redirect(url_for('homepage'))
        
        quiz_data = session['quiz_data']

        # Validierung: Wurde das Quiz wirklich beendet oder alle Fragen beantwortet
        # Verhindert, dass User die URL manuell aufrufen, um das Quiz zu überspringen.
        is_completed = quiz_data.get('completed', False)
        all_questions_answered = (quiz_data.get('current_index', 0) >= quiz_data.get('total_questions', 0) - 1)
        
        if not is_completed and not all_questions_answered:
            flash('Du musst erst alle Fragen beantworten!', 'error')
            return redirect(url_for('show_question'))
        
        # Timer stoppen und WebSocket-Raum freigeben
        room_id = quiz_data.get('room_id') if quiz_data else None
        if room_id:
            stop_timer(room_id)
            with timer_lock:
                if room_id in active_timers:
                    del active_timers[room_id]
        
        # Daten aus der Session extrahieren
        score = quiz_data.get('score', 0)
        total = quiz_data.get('total_questions', 0)
        correct_count = quiz_data.get('correct_count', 0)
        
        # Datenbank-Update
        user = User.query.filter_by(username=session['username']).first()
        new_highscore = False
        now = datetime.now(timezone.utc)
        
        if user:
            # evtl first_played Datum
            if not user.first_played:
                user.first_played = now
            
            # Prüfen auf neuen Highscore
            if score > user.highscore:
                user.highscore = score
                user.highscore_time = now
                new_highscore = True

            # Prüfen auf Rekord bei korrekten Antworten
            if correct_count > user.correct_high:
                user.correct_high = correct_count

            # Anzahl der gespielten Spiele erhöhen
            try:
                if getattr(user, 'number_of_games', None) is None:
                    user.number_of_games = 0
                user.number_of_games += 1
            except Exception as e:
                print(f"Fehler beim Erhöhen von number_of_games: {e}")
            
            # Alle Änderungen in die DB schreiben
            db.session.commit()

        user_avatar = user.avatar if user else "avatar0.png"

        # Wir speichern das Ergebnis separat, damit 'quiz_data' gelöscht werden kann,
        # die Auswertung aber bei einem Reload erhalten bleibt.
        evaluation_data = {
            'score': score,
            'total': total,
            'correct_answers': correct_count,
            'new_highscore': new_highscore,
            'highscore': user.highscore if user else score
        }
        session['evaluation_data'] = evaluation_data

        # Das eigentliche Quiz-Objekt wird jetzt gelöscht
        session.pop('quiz_data', None)
        
        # Flag setzen
        session['quiz_properly_ended'] = True
        
        # Seite rendern
        return render_template(
            'evaluate.html',
            score=score,
            total=total,
            correct_answers=correct_count,
            new_highscore=new_highscore,
            highscore=user.highscore if user else score,
            user_avatar=user_avatar
        )
        
    except (SQLAlchemyError, OperationalError) as e:
        print(f"Datenbankfehler in evaluate_quiz: {str(e)}")
        flash('Verbindungsproblem zur Datenbank. Bitte versuche es später erneut.', 'error')
        return redirect(url_for('homepage'))

@app.route('/cancel_quiz', methods=['POST'])
@login_required
def cancel_quiz():
    """Bricht ein laufendes Quiz ab (AJAX-Endpunkt)"""
    try:
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
        
        # Flag setzen, dass Quiz absichtlich abgebrochen wurde
        session['quiz_cancelled'] = True
        session.modified = True  # Sicherstellen, dass Session gespeichert wird

        if target:
            return jsonify({'redirect': url_for(target)})
        
        # Immer JSON zurückgeben, auch wenn kein Target
        return jsonify({'redirect': url_for('homepage')})

    except Exception as e:
        print(f"Fehler beim Abbrechen des Quiz: {str(e)}")
        return jsonify({'error': 'Ein Fehler ist aufgetreten.'}), 500

@app.route('/ranking')      
@login_required     
@prevent_quiz_exit           
def ranking():
    """Zeigt die Highscore-Rangliste"""
    try:
        # Lade nur die erste Seite für initiales Rendering
        per_page = 20
        
        players_first_page = User.query.filter(
            User.first_played.isnot(None),
            User.is_admin == False
        ).order_by(
            User.highscore.desc(),
            User.highscore_time.asc(),
            User.username.asc()
        ).limit(per_page).all()
        
        # Berechne Ränge für die erste Seite
        top_players = players_first_page
        
        # Aktuellen Benutzer finden
        current_user = session.get('username')
        current_player = None
        player_rank = None
        
        if current_user:
            current_player = User.query.filter_by(username=current_user).first()
            if current_player:
                # Rang des aktuellen Benutzers berechnen
                player_rank = db.session.query(
                    func.count(User.id)
                ).filter(
                    User.highscore > current_player.highscore,
                    User.first_played.isnot(None),
                    User.is_admin == False
                ).scalar() + 1

        return render_template(
            'ranking.html',
            top_players=top_players,
            current_player=current_player,
            player_rank=player_rank
        )
    except Exception as e:
        flash('Fehler beim Laden der Rangliste', 'error')
        return redirect(url_for('homepage'))

@app.route('/api/ranking_players')
@login_required
def api_ranking_players():
    """API-Endpunkt für paginierte Ranglistendaten"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 20
        
        players = User.query.filter(
            User.first_played.isnot(None), # bereits gespielt
            User.is_admin == False # keine Admins
        ).order_by(
            User.highscore.desc(),
            User.highscore_time.asc()
        ).paginate(page=page, per_page=per_page, error_out=False)
        
        players_data = []
        offset = (page - 1) * per_page
        
        for idx, player in enumerate(players.items):
            players_data.append({
                'id': player.id,
                'username': player.username,
                'highscore': player.highscore,
                'highscore_time': player.highscore_time.isoformat() if player.highscore_time else None,
                'avatar': player.avatar,
                'rank': offset + idx + 1,
                'correct_high': player.correct_high,
                'number_of_games': player.number_of_games,
                'first_played': player.first_played.isoformat() if player.first_played else None
            })
        
        return jsonify({
            'players': players_data,
            'has_next': players.has_next,
            'total_pages': players.pages
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/search_player', methods=['POST'])
@login_required
def search_player():
    """Sucht nach einem bestimmten Spieler in der Rangliste"""
    try:
        #  JSON/Form-Daten Handhabung
        if request.content_type and 'application/json' in request.content_type:
            data = request.get_json() or {}
        else:
            data = request.form

        username = data.get('username', '').strip()
        if not username:
            return jsonify({'error': 'Bitte gib einen Benutzernamen ein'}), 400

        # Case-sensitive Suche mit exaktem Match
        user = User.query.filter(
            User.username == username,
            User.is_admin == False  # Nur Nicht-Admins
        ).first()
        if not user:
            return jsonify({'error': 'Spieler nicht gefunden'}), 404
        
        # Rang berechnen
        # Zuerst alle Highscores abrufen und dann lokal sortieren
        all_players = User.query.filter(
            User.first_played.isnot(None),
            User.highscore.isnot(None),
            User.is_admin == False  # Nur Nicht-Admins
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
        def to_iso_str(utc_time):
            if not utc_time:
                return None
            if utc_time.tzinfo is None:
                utc_time = utc_time.replace(tzinfo=timezone.utc)
            else:
                utc_time = utc_time.astimezone(timezone.utc)
            return utc_time.strftime('%Y-%m-%dT%H:%M:%SZ')
        
        return jsonify({
            'rank': rank if rank else "N/A",
            'username': user.username,
            'id': user.id,
            'avatar': user.avatar,
            'first_played': to_iso_str(user.first_played) if user.first_played else None,
            'number_of_games': user.number_of_games if user.number_of_games else 0,
            'highscore': user.highscore,
            'highscore_time': to_iso_str(user.highscore_time) if user.highscore_time else None,
            'correct_high': user.correct_high
        })
    
    except (SQLAlchemyError, OperationalError) as e:
        print(f"Datenbankfehler in search_player: {str(e)}")
        return jsonify({'error': 'Datenbankfehler aufgetreten. Bitte versuche es später erneut.'}), 500
    except Exception as e:
        print(f"Unerwarteter Fehler in search_player: {str(e)}")
        return jsonify({'error': 'Ein unerwarteter Fehler ist aufgetreten.'}), 500

@app.route('/legal')
@logout_required # Nur für nicht-angemeldete Benutzer
def legal():
    """Zeigt rechtliche Informationen (AGB, Datenschutz)"""
    return render_template('legal.html')

@app.route('/automatic_logout')
@login_required 
def automatic_logout():
    """Verarbeitet automatischen Logout bei Inaktivität"""
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
    """Admin-Dashboard mit Übersichtsstatistiken"""
    try:
        # Statistiken für das Dashboard sammeln
        total_users = User.query.count()
        total_questions = Question.query.count()
        total_tickets = Ticket.query.count()
        
        return render_template(
            'admin_panel.html',
            total_users=total_users,
            total_questions=total_questions,
            total_tickets=total_tickets
        )
    except (SQLAlchemyError, OperationalError) as e:
        print(f"Datenbankfehler auf der Homepage: {str(e)}")
        flash('Verbindungsproblem zur Datenbank. Bitte versuche es später erneut.', 'error')
        return redirect(url_for('index'))

@app.route('/admin/add_question_page', methods=['GET'])
@login_required
@admin_required
def add_question_page():
    """Zeigt das Formular zum Hinzufügen einer neuen Frage"""
    return render_template('add_question.html')
    
@app.route('/db_stats')
@login_required
@admin_required
def db_stats():
    """Zeigt Datenbank-Statistiken für Admins"""
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

@app.route('/admin/data-management')
@login_required
@admin_required
def data_management():
    """Datenmanagement-Übersicht für Admins"""
    return render_template('data_management.html')

@app.route('/admin/export/<table_slug>')
@login_required
@admin_required
def export_data(table_slug):
    """Exportiert eine Datenbanktabelle als CSV-Datei"""
    models = {
        'user': User,
        'news': News,
        'ticket': Ticket,
        'ticket_message': TicketMessage
    }

    model = models.get(table_slug)
    if not model:
        flash("Tabelle nicht gefunden.", "error")
        return redirect(url_for('data_management'))

    try:
        data = model.query.all()
        output = io.StringIO()
        writer = csv.writer(output, delimiter=';', quotechar='"', quoting=csv.QUOTE_MINIMAL)

        columns = [column.key for column in model.__table__.columns]
        writer.writerow(columns)

        for row in data:
            writer.writerow([getattr(row, col) for col in columns])

        output.seek(0)
        response = make_response(output.getvalue())
        filename = f"export_{table_slug}_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
        response.headers["Content-Disposition"] = f"attachment; filename={filename}"
        response.headers["Content-type"] = "text/csv"
        return response

    except Exception as e:
        flash(f"Fehler beim Export: {str(e)}", "error")
        return redirect(url_for('data_management'))

@app.route('/admin/import', methods=['POST'])
@login_required
@admin_required
def import_data():
    """Importiert Daten aus einer CSV-Datei in eine Datenbanktabelle"""
    table_name = request.form.get('table')
    file = request.files.get('file')

    if not file or not table_name:
        flash("Datei oder Tabelle fehlt.", "error")
        return redirect(url_for('data_management'))

    models = {
        'user': User,
        'news': News,
        'ticket': Ticket,
        'ticket_message': TicketMessage
    }

    model = models.get(table_name)
    if not model:
        flash("Ungültige Tabelle.", "error")
        return redirect(url_for('data_management'))

    try:
        stream = io.StringIO(file.stream.read().decode("utf-8"), newline=None)
        reader = csv.DictReader(stream, delimiter=';')

        valid_columns = [c.key for c in model.__table__.columns]
        count = 0

        for row in reader:
            clean_data = {}

            for column in valid_columns:
                if column not in row:
                    continue

                value = row[column]

                # Leere Werte → None
                if value in ("", None):
                    clean_data[column] = None
                    continue

                # TYP-KONVERTIERUNG
                column_type = model.__table__.columns[column].type

                if isinstance(column_type, db.Integer):
                    clean_data[column] = csv_int(value)

                elif isinstance(column_type, db.Boolean):
                    clean_data[column] = csv_bool(value)

                elif isinstance(column_type, db.DateTime):
                    clean_data[column] = csv_datetime(value)

                else:
                    clean_data[column] = value

            # ID nicht überschreiben
            entry_id = clean_data.pop("id", None)

            if entry_id:
                existing = db.session.get(model, entry_id)
                if existing:
                    for k, v in clean_data.items():
                        setattr(existing, k, v)
                else:
                    clean_data["id"] = entry_id
                    db.session.add(model(**clean_data))
            else:
                db.session.add(model(**clean_data))

            count += 1

        db.session.commit()
        flash(f"{count} Datensätze in '{table_name}' erfolgreich importiert!", "success")

    except Exception as e:
        db.session.rollback()
        print(f"Import Fehler: {e}")
        flash(f"Fehler beim Import: {str(e)}", "error")

    return redirect(url_for('data_management'))

# ---------- HILFSFUNKTIONEN ----------

def csv_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def csv_bool(value):
    return str(value).lower() in ("1", "true", "yes", "ja")


def csv_datetime(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.split("+")[0])
    except ValueError:
        return None   
    
@app.route('/add_question', methods=['POST'])
@login_required
@admin_required
def add_question():
    """Verarbeitet das Hinzufügen einer neuen Frage"""
    if request.method != 'POST':
        abort(405)

    redirect_url = url_for('add_question_page') 

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
            return redirect(redirect_url) 
            
        if len(question_text) > 500:
            flash('Frage darf maximal 500 Zeichen haben', 'error')
            return redirect(redirect_url) 
            
        # Prüfen ob Frage bereits existiert
        existing = Question.query.filter_by(question=question_text).first()
        if existing:
            flash('Diese Frage existiert bereits', 'error')
            return redirect(redirect_url) 
            
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
        
        return redirect(redirect_url)

    except (SQLAlchemyError, OperationalError) as e:
        db.session.rollback()
        print(f"Datenbankfehler beim Hinzufügen der Frage: {str(e)}")
        flash('Datenbankfehler beim Hinzufügen der Frage', 'error')
        return redirect(redirect_url)
    except Exception as e:
        db.session.rollback()
        print(f"Unerwarteter Fehler beim Hinzufügen der Frage: {str(e)}")
        flash('Ein unerwarteter Fehler ist aufgetreten', 'error')
        return redirect(redirect_url)

@app.route("/news")
@login_required
@prevent_quiz_exit
def news():
    """Zeigt News-Einträge für Spieler."""
    try:
        user = User.query.filter_by(username=session['username']).first()
        news_entries = News.query.order_by(News.created_at.desc()).all()
        
        # Wir erstellen eine Liste von IDs, die der User schon kennt.
        seen_ids = [n.id for n in user.seen_news]

        return render_template("news.html", news_entries=news_entries, seen_ids=seen_ids)
    except Exception as e:
        print(f"Fehler beim Laden der News: {str(e)}")
        flash('Fehler beim Laden der News', 'error')
        return render_template("news.html", news_entries=[])
    
@app.route('/api/mark_news_read', methods=['POST'])
@login_required
def mark_news_read():
    """Markiert eine News als gelesen (AJAX-Endpunkt)"""
    try:
        data = request.get_json()
        news_id = data.get('news_id')
        
        user = User.query.filter_by(username=session['username']).first()
        news_item = db.session.get(News, news_id)
        
        if user and news_item:
            if news_item not in user.seen_news:
                user.seen_news.append(news_item)
                db.session.commit()
                return jsonify({'success': True})
            
        return jsonify({'success': True}) # Auch success, wenn schon gesehen
    except Exception as e:
        print(f"Error marking news read: {e}")
        return jsonify({'success': False}), 500

@app.route("/admin/news", methods=["GET", "POST"])
@login_required
@admin_required
def news_admin():
    """News-Verwaltung für Administratoren"""
    try:
        if request.method == "POST":
            action = request.form.get("action")
            
            # Erstellen neuer News
            if action == "create":
                title = request.form.get("title", "").strip()
                content = request.form.get("content", "").strip()
                
                if not title or not content:
                    flash("Bitte fülle alle Felder aus!", "error")
                else:
                    new_entry = News(title=title, content=content)
                    db.session.add(new_entry)
                    db.session.commit()
                    flash("News erfolgreich erstellt!", "success")
                    
            #  Bearbeiten bestehender News
            elif action == "edit":
                news_id = request.form.get("news_id")
                if news_id:
                    entry = db.session.get(News, int(news_id))
                    if entry:
                        entry.title = request.form.get("title", "").strip()
                        entry.content = request.form.get("content", "").strip()
                        db.session.commit()
                        flash("News erfolgreich aktualisiert!", "success")

            # Löschen von News  
            elif action == "delete":
                news_id = request.form.get("news_id")
                if news_id:
                    entry = db.session.get(News, int(news_id))
                    if entry:
                        db.session.delete(entry)
                        db.session.commit()
                        flash("News erfolgreich gelöscht!", "success")
        
        news_entries = News.query.order_by(News.created_at.desc()).all()
        return render_template("news_admin.html", news_entries=news_entries)
        
    except Exception as e:
        print(f"Fehler in News-Admin: {str(e)}")
        flash('Ein Fehler ist aufgetreten', 'error')
        return redirect(url_for('news_admin'))
    
@app.route('/tickets', methods=['GET'])
@login_required
def tickets_overview():
    """Übersicht über Support-Tickets"""
    try:
        user = User.query.filter_by(username=session['username']).first()
        if not user:
            flash("Benutzer nicht gefunden", "error")
            return redirect(url_for('homepage'))
        
        per_page = 10

        # Tickets basierend auf Benutzerrolle laden
        if user.is_admin:
            tickets_query = Ticket.query.order_by(Ticket.created_at.desc())
        else:
            tickets_query = Ticket.query.filter_by(user_id=user.id).order_by(Ticket.created_at.desc())
        
        # Nur die erste Seite laden für initiales Rendering
        tickets = tickets_query.limit(per_page).all()
        
        # Rückkehr-Ziel aus URL-Parameter holen
        return_to = request.args.get('return_to', 'homepage')
        
        return render_template(
            'tickets.html', 
            tickets=tickets, 
            is_admin=user.is_admin,
            return_to=return_to
        )
    except Exception as e:
        print(f"Fehler beim Laden der Tickets: {str(e)}")
        flash("Fehler beim Laden der Tickets", "error")
        return redirect(url_for('homepage'))
    
@app.route('/api/tickets')
@login_required
def api_tickets():
    """
    API für das Nachladen von Tickets mit Paging und Filtern
    Wird für Filterung, Sortierung und Paginierung verwendet.
    """
    try:
        user = User.query.filter_by(username=session['username']).first()
        if not user:
            return jsonify({'error': 'Benutzer nicht gefunden'}), 401
        
        # 1. Parameter aus URL holen
        page = request.args.get('page', 1, type=int)
        per_page = 10
        
        sort_by = request.args.get('sort', 'date_desc')
        filter_status = request.args.get('status', 'all')
        filter_category = request.args.get('category', 'all')
        filter_player = request.args.get('player', '').strip()

        # 2. Basis-Query erstellen
        query = Ticket.query

        # Berechtigung: Admin sieht alle, User nur eigene
        if not user.is_admin:
            query = query.filter_by(user_id=user.id)
        
        # 3. Filter anwenden
        
        # Status Filter
        if filter_status != 'all':
            query = query.filter(Ticket.status == filter_status)
            
        # Kategorie Filter
        if filter_category != 'all':
            query = query.filter(Ticket.category == filter_category)
            
        # Admin: Spieler-Suche
        if user.is_admin and filter_player:
            # Join mit User Tabelle, um nach Username zu suchen (case insensitive über ilike)
            query = query.join(User).filter(User.username.ilike(f"%{filter_player}%"))
            
        # 4. Sortierung anwenden
        if sort_by == 'date_asc':
            query = query.order_by(Ticket.created_at.asc())
        elif sort_by == 'subject_asc':
            query = query.order_by(Ticket.subject.asc())
        elif sort_by == 'subject_desc':
            query = query.order_by(Ticket.subject.desc())
        else:
            # Standard: date_desc
            query = query.order_by(Ticket.created_at.desc())

        # 5. Paginierung ausführen
        tickets_paginated = query.paginate(page=page, per_page=per_page, error_out=False)
        
        tickets_data = []
        for ticket in tickets_paginated.items:

            # Zähle ungelesene Nachrichten
            if user.is_admin:
                unread = ticket.messages.filter_by(sender_type='user', read=False).count()
            else:
                unread = ticket.messages.filter_by(sender_type='admin', read=False).count()

            # Username holen
            username = ticket.user.username if ticket.user else "Unbekannt"

            tickets_data.append({
                'id': ticket.id,
                'created_at': ticket.created_at.isoformat() if ticket.created_at else None,
                'subject': ticket.subject,
                'category': ticket.category,
                'status': ticket.status,
                'user': username,
                'user_id': ticket.user_id,
                'unread_count': unread
            })
        
        return jsonify({
            'tickets': tickets_data,
            'has_next': tickets_paginated.has_next,
            'total_pages': tickets_paginated.pages,
            'current_page': page
        })
        
    except Exception as e:
        print(f"Fehler in api_tickets: {str(e)}")
        return jsonify({'error': 'Ein Fehler ist aufgetreten'}), 500

TICKET_CATEGORIES = [
    "Feedback", 
    "Account", 
    "Fehlermeldung", 
    "Missbrauch",
    "Quiz Frage",
    "Sonstiges"
]

@app.route('/create_ticket', methods=['GET', 'POST'])
@login_required
def ticket_create():
    """Erstellt ein neues Support-Ticket"""
    try:
        user = User.query.filter_by(username=session['username']).first()
        if not user:
            flash("Benutzer nicht gefunden", "error")
            return redirect(url_for('homepage'))

        if request.method == 'POST':
            # 1. Daten aus dem Formular holen
            category = request.form.get('category')
            subject = request.form.get('subject')
            message = request.form.get('message')
            email = request.form.get('email')
            phone = request.form.get('phone')

            # 2. Validierung
            if not all([category, subject, message]):
                flash('Bitte füllen Sie alle Pflichtfelder aus.', 'error')
                return render_template('ticket_create.html', categories=TICKET_CATEGORIES, current_user=user)
        
            if subject and len(subject) > 80:
                flash('Der Betreff ist zu lang (maximal 80 Zeichen).', 'error')
                return render_template('ticket_create.html', categories=TICKET_CATEGORIES, current_user=user)
            
            if len(message) > 500:
                flash('Die Nachricht ist zu lang (maximal 500 Zeichen).', 'error')
                return render_template('ticket_create.html', categories=TICKET_CATEGORIES, current_user=user)
            
            # 3. User-Profil aktualisieren
            if email:
                user.email = email
            if phone:
                user.phone = phone

            # 4. Neues Ticket in der DB speichern
            new_ticket = Ticket(
                user_id=user.id,
                subject=subject,
                category=category,
                status='open',
                initial_message_content=message
            )
            db.session.add(new_ticket)
            db.session.flush()

            # 5. Erste Nachricht des Users speichern
            initial_msg = TicketMessage(
                ticket_id=new_ticket.id,
                sender_type='user',
                sender_name=user.username,
                content=message
            )
            db.session.add(initial_msg)
            db.session.commit()

            flash('Ihr Ticket wurde erfolgreich erstellt.', 'success')
            return redirect(url_for('tickets_overview'))
                                    
        # GET-Anfrage: Formular rendern
        return render_template('ticket_create.html', categories=TICKET_CATEGORIES, current_user=user)
        
    except Exception as e:
        db.session.rollback()
        print(f"Fehler beim Erstellen des Tickets: {e}")
        flash('Ein Fehler ist beim Speichern aufgetreten.', 'error')
        return redirect(url_for('tickets_overview'))

@app.route('/ticket/<int:ticket_id>', methods=['GET', 'POST'])
@login_required
def ticket_detail(ticket_id):
    """Detailansicht eines Tickets mit Chat"""
    try:
        ticket = db.session.get(Ticket, ticket_id)
        if ticket is None:
            abort(404)
        
        user = User.query.filter_by(username=session['username']).first()
        if not user:
            flash("Benutzer nicht gefunden", "error")
            return redirect(url_for('homepage'))
        
        is_admin = user.is_admin if user else False

        # Sicherheitsprüfung: Nur der Ersteller oder Admin darf das Ticket sehen
        if ticket.user_id != user.id and not is_admin:
            abort(403)

        # Nur die neuesten 20 Nachrichten laden
        initial_messages = ticket.messages.order_by(TicketMessage.created_at.desc()).limit(20).all()
        # Liste umdrehen, damit sie chronologisch (alt --> neu) im Chat angezeigt werden
        messages = list(reversed(initial_messages))

        target_sender_type = 'user' if is_admin else 'admin'

        unread_messages = TicketMessage.query.filter_by(
            ticket_id=ticket.id, 
            sender_type=target_sender_type, 
            read=False
        ).all()
        
        if unread_messages:
            for msg in unread_messages:
                msg.read = True
            db.session.commit()

        if request.method == 'POST':
            new_message_content = request.form.get('message_content')
            
            if not new_message_content:
                flash('Nachricht darf nicht leer sein.', 'warning')
                return redirect(url_for('ticket_detail', ticket_id=ticket.id))
            
            if len(new_message_content) > 500:
                flash('Die Nachricht ist zu lang (maximal 500 Zeichen).', 'error')
                return redirect(url_for('ticket_detail', ticket_id=ticket.id))

            # Prüfe Status: Wenn geschlossen, kann niemand mehr schreiben
            if ticket.status == 'closed':
                flash('Dieses Ticket ist geschlossen. Es können keine neuen Nachrichten gesendet werden.', 'error')
                return redirect(url_for('ticket_detail', ticket_id=ticket.id))
            
            # Nachricht speichern
            if is_admin:
                sender_type = 'admin'
                sender_name = user.username
            else:
                sender_type = 'user'
                sender_name = user.username
                
            new_msg = TicketMessage(
                ticket_id=ticket.id,
                sender_type=sender_type,
                sender_name=sender_name,
                content=new_message_content
            )
            db.session.add(new_msg)
            
            db.session.commit()
            flash('Nachricht gesendet.', 'success')
            return redirect(url_for('ticket_detail', ticket_id=ticket.id))

        # GET-Anfrage
        return render_template('ticket_detail.html', ticket=ticket, messages=messages, is_admin=is_admin)
        
    except Exception as e:
        db.session.rollback()
        print(f"Fehler in ticket_detail: {e}")
        flash('Ein Fehler ist aufgetreten.', 'error')
        return redirect(url_for('tickets_overview'))
    
@app.route('/api/ticket/<int:ticket_id>/messages')
@login_required
def api_ticket_messages(ticket_id):
    """API für paginierte Nachladen älterer Nachrichten"""
    try:
        ticket = db.session.get(Ticket, ticket_id)
        if not ticket:
            return jsonify({'error': 'Ticket not found'}), 404
            
        # Berechtigung prüfen
        user = User.query.filter_by(username=session['username']).first()
        if ticket.user_id != user.id and not user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
            
        # Pagination Parameter
        offset = request.args.get('offset', 0, type=int)
        limit = 20
        
        # Ältere Nachrichten holen (überspringe die ersten 'offset' Nachrichten)
        older_messages = ticket.messages.order_by(TicketMessage.created_at.desc())\
            .offset(offset).limit(limit).all()
        
        # Umdrehen für chronologische Reihenfolge
        older_messages = list(reversed(older_messages))
        
        # JSON formatieren
        messages_data = []
        for msg in older_messages:
            messages_data.append({
                'id': msg.id,
                'sender_type': msg.sender_type,
                'sender_name': 'Support' if msg.sender_type == 'admin' else msg.sender_name,
                'content': msg.content,
                'created_at_iso': msg.created_at.isoformat() if msg.created_at else None,
                'created_at_formatted': msg.created_at.strftime('%H:%M') if msg.created_at else ''
            })
            
        return jsonify({
            'messages': messages_data,
            'has_more': len(older_messages) == limit
        })
        
    except Exception as e:
        print(f"API Error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/ticket/toggle_status/<int:ticket_id>', methods=['POST'])
@login_required
def toggle_ticket_status(ticket_id):
    """Schließt oder öffnet ein Ticket"""
    try:
        user = User.query.filter_by(username=session['username']).first()
        if not user:
            flash('Benutzer nicht gefunden', 'error')
            return redirect(url_for('ticket_detail', ticket_id=ticket_id))

        ticket = db.session.get(Ticket, ticket_id)
        if ticket is None:
            abort(404)
        
        # Berechtigung prüfen: Nur Admin oder der Ersteller des Tickets
        if not (user.is_admin or ticket.user_id == user.id):
            abort(403)

        # Status umschalten
        if ticket.status == 'open':
            ticket.status = 'closed'
            flash('Ticket wurde geschlossen.', 'success')
        else:
            ticket.status = 'open'
            flash('Ticket wurde wieder geöffnet.', 'success')
        
        db.session.commit()

    except Exception as e:
        db.session.rollback()
        flash('Fehler beim Ändern des Ticket-Status.', 'error')
        print(f"Fehler beim Status-Toggle: {e}")
        
    return redirect(url_for('ticket_detail', ticket_id=ticket_id))

@app.route('/admin/ticket/delete/<int:ticket_id>', methods=['POST'])
@admin_required
def admin_delete_ticket(ticket_id):
    """Löscht ein geschlossenes Ticket komplett (nur für Admins)."""
    try:
        ticket = db.session.get(Ticket, ticket_id)
        if ticket is None:
            abort(404)
        
        # Nur geschlossene Tickets können gelöscht werden
        if ticket.status != 'closed':
            flash('Nur geschlossene Tickets können gelöscht werden.', 'error')
            return redirect(url_for('ticket_detail', ticket_id=ticket.id))
        
        # Ticket und alle zugehörigen Nachrichten löschen
        ticket_messages = TicketMessage.query.filter_by(ticket_id=ticket.id).all()
        
        for message in ticket_messages:
            db.session.delete(message)
        
        db.session.delete(ticket)
        db.session.commit()
        
        flash('Ticket wurde erfolgreich gelöscht.', 'success')
        return redirect(url_for('tickets_overview'))
        
    except Exception as e:
        db.session.rollback()
        print(f"Fehler beim Löschen des Tickets: {e}")
        flash('Fehler beim Löschen des Tickets.', 'error')
        return redirect(url_for('ticket_detail', ticket_id=ticket_id))

# ========================
# WEBSOCKET-EVENT-HANDLER
# ========================

@socketio.on('connect')
def handle_connect():
    """Verarbeitet WebSocket-Verbindungsaufbau"""
    print(f"Client connected: {request.sid}")
    if 'username' not in session:
        print(f"Socket connect denied for sid={request.sid} (not authenticated)")
        return False  # trennt Verbindung sofort
    emit('connection_success', {'message': 'Verbunden'})

@socketio.on('disconnect')
def handle_disconnect():
    """Verarbeitet WebSocket-Verbindungstrennung"""
    print(f"Client disconnected: {request.sid}")
    # Socket rooms aufräumen
    if request.sid in socket_rooms:
        room_id = socket_rooms[request.sid]
        leave_room(room_id)
        del socket_rooms[request.sid]

def handle_reset_timer(data):
    room_id = data.get('room_id')
    if not room_id:
        return

    # 1. Stoppt den alten Timer und löscht ihn aus dem 'active_timers'-Dict
    stop_timer(room_id)
    
    # 2. Erstellt eine brandneue Timer-Instanz, da die alte gelöscht wurde
    get_or_create_timer(room_id)
    
    print(f"Timer für Raum {room_id} zurückgesetzt)")

@socketio.on('join_quiz_session')
def handle_join_quiz_session(data):
    """Tritt einem Quiz-Room bei und startet Timer"""
    room_id = data.get('room_id')
    if not room_id:
        emit('error', {'error': 'Keine Room-ID'})
        return
    
    print(f"Client {request.sid} joining room {room_id}")
    join_room(room_id)
    socket_rooms[request.sid] = room_id
    
    # Timer für diesen Raum erstellen/abrufen und starten
    timer = get_or_create_timer(room_id)
    
    # Damit der Client nicht erst auf den nächsten Tick warten muss
    current_time = timer.get_time_left()
    emit('time_update', {'time_left': current_time})

    print(f"Client {request.sid} hat Raum {room_id} betreten, Timer läuft")

def _process_answer(room_id, user_answer, time_left):
    """
    Logik zur Verarbeitung einer Antwort (ob per Socket oder Timeout)
    Aktualisiert die Session und gibt ein Dict zurück
    """
    try:
        if 'quiz_data' not in session:
            print(f"Fehler in _process_answer: Keine quiz_data in Session für Raum {room_id}")
            return {'error': 'Session expired'}
            
        quiz_data = session['quiz_data']
        
        # Verhindere doppelte Verarbeitung
        if quiz_data.get('answered', False):
            print(f"WARNUNG: _process_answer für Raum {room_id} aufgerufen, aber 'answered' ist bereits True.")
            # Gib die Daten der bereits verarbeiteten Antwort zurück (defensiv)
            return {
                'is_correct': session.get('last_answer_correct', False),
                'correct_answer': session.get('last_correct_answer', ''),
                'points_earned': session.get('last_points_earned', 0),
                'current_score': quiz_data['score'],
                'time_left': time_left,
                'user_answer': user_answer,
                'is_last_question': (quiz_data['current_index'] >= quiz_data['total_questions'] - 1) 
            }

        current_index = quiz_data['current_index']
        question_id = quiz_data['questions'][current_index]
        question = db.session.get(Question, question_id)
        
        if not question:
            return {'error': 'Question not found'}
        
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

        # Für defensive Prüfung in Schritt 2
        session['last_answer_correct'] = is_correct
        session['last_correct_answer'] = question.true
        session['last_points_earned'] = points_earned
        
        session['quiz_data'] = quiz_data
        session.modified = True # Explizit speichern
        
        return {
            'is_correct': is_correct,
            'correct_answer': question.true,
            'points_earned': points_earned,
            'current_score': new_score,
            'time_left': time_left,
            'user_answer': user_answer,
            'is_last_question': (current_index >= quiz_data['total_questions'] - 1) 
        }
    except (SQLAlchemyError, OperationalError) as e:
        db.session.rollback()
        print(f"Datenbankfehler in _process_answer: {str(e)}")
        return {'error': 'Datenbankfehler aufgetreten'}
    except Exception as e:
        db.session.rollback()
        print(f"Unerwarteter Fehler in _process_answer: {str(e)}")
        return {'error': 'Ein unerwarteter Fehler ist aufgetreten'}

@socketio.on('submit_answer')
def handle_submit_answer(data):
    """Verarbeitet Quiz-Antworten über WebSocket"""
    try:
        room_id = data.get('room_id')
        user_answer = data.get('answer', '')
        
        if not room_id or 'quiz_data' not in session:
            emit('answer_result', {'error': 'Session expired'})
            return
            
        # Timer stoppen für diesen Raum
        with timer_lock:
            timer = active_timers.get(room_id)
            if timer:
                time_left = timer.get_time_left()
                timer.stop()
                timer.timed_out = False
            else:
                time_left = 0
        
        # Antwort in der Session verarbeiten
        result = _process_answer(room_id, user_answer, time_left)
        
        # Ergebnis an Client senden
        emit('answer_result', result)

    except (SQLAlchemyError, OperationalError) as e:
        db.session.rollback()
        print(f"Datenbankfehler in _process_answer: {str(e)}")
        return {'error': 'Datenbankfehler aufgetreten'}
    except Exception as e:
        db.session.rollback()
        print(f"Unerwarteter Fehler in _process_answer: {str(e)}")
        return {'error': 'Ein unerwarteter Fehler ist aufgetreten'}

# ============================================
# HAUPTFUNKTION FÜR SERVER-START
# ============================================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    
    # In Production: verwende den Port von der Environment Variable
    if is_production:
        socketio.run(app, host='0.0.0.0', port=port)
    else:
        socketio.run(app, host='0.0.0.0', port=port, debug=True)