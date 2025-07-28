from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, or_
import os
import random
import csv
import time
from collections import defaultdict
from flask_session import Session
from datetime import datetime, timezone, timedelta

app = Flask(__name__)

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
    SECRET_KEY=os.environ.get('SECRET_KEY', os.urandom(24).hex())
)

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    highscore = db.Column(db.Integer, default=0)
    highscore_time = db.Column(db.DateTime)
    correct_high = db.Column(db.Integer, default=0)
    first_played = db.Column(db.DateTime)  

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

# Serverseitige Session-Konfiguration
app.config['SESSION_TYPE'] = 'sqlalchemy'
app.config['SESSION_SQLALCHEMY'] = db
app.config['SESSION_PERMANENT'] = False
server_session = Session(app)

bcrypt = Bcrypt(app)

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
                {'username': 's4005560', 'password': 'test', 'highscore': 736, 'highscore_time': datetime(2025, 1, 29, tzinfo=timezone.utc), 'correct_high': 28}
            ]

            added_users = 0
            for user_data in test_users:
                user = User.query.filter_by(username=user_data['username']).first()
                if not user:
                    new_user = User(
                        username=user_data['username'],
                        highscore=user_data['highscore'],
                        highscore_time=user_data['highscore_time'],
                        first_played=user_data['highscore_time']  # Erstes Spiel setzen
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
            
            print("Datenbankinitialisierung abgeschlossen")
            
        except Exception as e:
            print(f"❌❌ KRITISCHER FEHLER: {str(e)}")

# Initialisierung beim App-Start
initialize_database()

# Ab hier alle Routes 
@app.route('/')
def index():
    if 'username' in session: 
        return redirect(url_for('homepage')) 
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username'].strip()
    password = request.form['password'].strip()

    if username and password:
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['username'] = username
            return redirect(url_for('homepage')) 
        
        flash('Ungültige Anmeldedaten', 'error')
        return redirect(url_for('index'))
    
    flash('Bitte fülle alle Felder aus', 'error')
    return redirect(url_for('index'))

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username'].strip()
    password = request.form['password'].strip()

    #Mindestanforderungen
    if len(username) > 12:
        flash('Benutzername darf maximal 12 Zeichen haben', 'error')
        return redirect(url_for('index'))
    if len(password) < 5:
        flash('Passwort muss mindestens 5 Zeichen haben', 'error')
        return redirect(url_for('index'))

    if username and password:
        if User.query.filter_by(username=username).first():
            flash('Benutzername bereits vergeben', 'error')
            return redirect(url_for('index'))
        
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        session['username'] = username
        return redirect(url_for('homepage'))
    
    flash('Bitte fülle alle Felder aus', 'error')
    return redirect(url_for('index'))

@app.route('/homepage')
def homepage():
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

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/start_custom_quiz', methods=['POST'])
def start_custom_quiz():
    if 'username' not in session:
        return redirect(url_for('index'))
    
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

    session['quiz_data'] = {
        'subject': ', '.join(selected_topics),
        'questions': [q.id for q in selected_questions],
        'current_index': 0,
        'total_questions': num_questions,
        'score': 0,
        'correct_count': 0
    }
    
    return redirect(url_for('show_question'))

@app.route('/show_question')
def show_question():
    if 'quiz_data' not in session:
        return redirect(url_for('homepage'))
    
    quiz_data = session['quiz_data']
    
    # Wenn die Frage bereits beantwortet wurde, zur nächsten Frage weiterleiten
    if quiz_data.get('answered', False):
        return redirect(url_for('next_question'))
    
    current_index = quiz_data['current_index']
    question = Question.query.get(quiz_data['questions'][current_index])
    
    # Antwortoptionen nur beim ersten Aufruf mischen
    if 'options_order' not in quiz_data:
        options = [question.true, question.wrong1, question.wrong2, question.wrong3]
        random.shuffle(options)
        quiz_data['options_order'] = options
        session['quiz_data'] = quiz_data
    else:
        options = quiz_data['options_order']
    
    # Timer-Status initialisieren oder beibehalten
    if 'timer_start' not in quiz_data:
        quiz_data['timer_start'] = int(time.time())
        session['quiz_data'] = quiz_data
    
    was_correct = session.pop('last_answer_correct', False)
    
    return render_template(
        'quiz.html',
        subject=quiz_data['subject'],
        question=question,
        options=options,
        progress=current_index + 1,
        total_questions=quiz_data['total_questions'],
        score=quiz_data['score'],
        was_correct=was_correct,
        timer_start=quiz_data['timer_start']  # Wichtig für den Timer
    )

@app.route('/check_answer', methods=['POST'])
def check_answer():
    if 'quiz_data' not in session:
        return jsonify({'error': 'Session expired'}), 400
        
    quiz_data = session['quiz_data']
    current_index = quiz_data['current_index']
    question_id = quiz_data['questions'][current_index]
    question = Question.query.get(question_id)
    
    if not question:
        return jsonify({'error': 'Question not found'}), 404
        
    user_answer = request.form.get('answer', '')
    time_left = int(request.form.get('time_left', 0))
    is_correct = user_answer == question.true
    
    # Punkte basierend auf verbleibender Zeit berechnen
    if is_correct and time_left > 0:
        points_earned = 30 + 70 * (time_left / 30) ** 2.0
        points_earned = round(points_earned)
    else:
        points_earned = 0

    # Neuer Zähler für korrekte Antworten
    if is_correct:
        quiz_data['correct_count'] += 1

    # Score übergeben
    new_score = quiz_data['score'] + points_earned
    quiz_data['score'] = new_score
    
    # Markiere Frage als beantwortet
    quiz_data['answered'] = True
    session['quiz_data'] = quiz_data
    
    return jsonify({
        'is_correct': is_correct,
        'correct_answer': question.true,
        'points_earned': points_earned,
        'current_score': new_score
    })

@app.route('/next_question', methods=['GET', 'POST'])
def next_question():
    if 'quiz_data' not in session or 'username' not in session:
        return redirect(url_for('homepage'))
    
    quiz_data = session['quiz_data']
    
    # Entferne "answered" Flag
    if 'answered' in quiz_data:
        del quiz_data['answered']
    
    quiz_data['current_index'] += 1
    
    # Timer und Optionen für die nächste Frage zurücksetzen
    if 'timer_start' in quiz_data:
        del quiz_data['timer_start']
    if 'options_order' in quiz_data:
        del quiz_data['options_order']
    
    session['quiz_data'] = quiz_data
    
    if quiz_data['current_index'] < quiz_data['total_questions']:
        return redirect(url_for('show_question'))
    return redirect(url_for('evaluate_quiz'))

@app.route('/evaluate')
def evaluate_quiz():
    if 'quiz_data' not in session or 'username' not in session:
        return redirect(url_for('homepage'))
    
    quiz_data = session.pop('quiz_data', None)
    score = quiz_data.get('score', 0)
    total = quiz_data.get('total_questions', 0)
    correct_count = quiz_data.get('correct_count', 0)
    
    # Highscore-Logik
    user = User.query.filter_by(username=session['username']).first()
    new_highscore = False
    now = datetime.now(timezone.utc)
    
    if user:
        # Setze Zeitpunkt des ersten Spiels, falls noch nicht vorhanden
        if not user.first_played:
            user.first_played = now
        
        # Highscore für Punkte
        if quiz_data['score'] > user.highscore:
            user.highscore = quiz_data['score']
            user.highscore_time = now
            new_highscore = True

        if correct_count > user.correct_high:
            user.correct_high = correct_count
        
        db.session.commit()
    
    return render_template(
        'evaluate.html',
        score=score,
        total=total,
        correct_answers=quiz_data.get('correct_count', 0),
        new_highscore=new_highscore,
        highscore=user.highscore if user else score
    )

@app.route('/cancel_quiz', methods=['POST'])
def cancel_quiz():
    if 'quiz_data' in session:
        session.pop('quiz_data', None)
    return '', 204

@app.route('/db_stats')
def db_stats():
    """Zeigt Datenbankstatistiken an (Gesamtzahl und pro Thema)"""
    try:
        # Gesamtzahl der Fragen
        total = db.session.query(func.count(Question.id)).scalar()
        
        # Anzahl pro Thema
        topic_counts = db.session.query(
            Question.subject,
            func.count(Question.id)
        ).group_by(Question.subject).all()
        
        # Erstelle eine formatierte Ausgabe
        output = f"<h2>📊 Datenbank-Statistiken</h2>"
        output += f"<p><b>Gesamtzahl der Fragen:</b> {total}</p>"
        output += "<h3>Fragen pro Thema:</h3><ul>"
        
        for topic, count in topic_counts:
            output += f"<li><b>{topic.capitalize()}:</b> {count} Fragen</li>"
            
        output += "</ul>"
        output += "<p><i>ℹ️ Diese Route kann später entfernt werden</i></p>"
        
        return output
        
    except Exception as e:
        return f"<p style='color:red;'>Fehler: {str(e)}</p>"

@app.route('/ranking')                      
def ranking():
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

    return render_template(
        'ranking.html',
        top_players=top_players,
        current_player=current_player,
        player_rank=player_rank
    )

@app.route('/api/search_player')
def search_player():
    username = request.args.get('username', '').strip()
    if not username:
        return jsonify({'error': 'Bitte gib einen Benutzernamen ein'}), 400
    
    user = User.query.filter(func.lower(User.username) == func.lower(username)).first()
    if not user:
        return jsonify({'error': 'Spieler nicht gefunden'}), 404
    
    return jsonify({
        'id': user.id,
        'username': user.username,
        'first_played': to_local_time(user.first_played) if user.first_played else "N/A",
        'highscore': user.highscore,
        'highscore_time': to_local_time(user.highscore_time) if user.highscore_time else "N/A",
        'correct_high': user.correct_high
    })


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)