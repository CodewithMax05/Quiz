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
    registration = db.Column(db.Date, nullable=True )               #Todo: nullable noch auf false ändern
    highscore = db.Column(db.Integer, default=0)
    points = db.Column(db.Integer, default=0)
    set_up_time = db.Column(db.Date, nullable=True)                    #Todo: nullable noch auf false ändern

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
            
            print(f"Datenbankinitialisierung abgeschlossen. Importierte Fragen: {total_imported}")
            
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
        'score': 0
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
    is_correct = user_answer == question.true
    
    # Score aktualisieren
    new_score = quiz_data['score']
    if is_correct:
        new_score += 1
        quiz_data['score'] = new_score
    
    # Markiere Frage als beantwortet
    quiz_data['answered'] = True
    session['quiz_data'] = quiz_data
    
    # Aktualisierten Score in der Antwort zurückgeben
    return jsonify({
        'is_correct': is_correct,
        'correct_answer': question.true,
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
    
    # Highscore-Logik
    user = User.query.filter_by(username=session['username']).first()
    new_highscore = False
    
    if user:
        if score > user.highscore:
            user.highscore = score
            new_highscore = True
            db.session.commit()
    
    return render_template(
        'evaluate.html',
        score=score,
        total=total,
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











from datetime import datetime

@app.route('/ranking')                      
def ranking():
    from datetime import datetime

    # ✳️ Liste aller Spieler (Demo – später aus DB laden)
    all_players = [
        {'username': 'Michael', 'id': 1, 'registration': datetime.now(), 'highscore': 30, 'points': 900, 'set_up_time': datetime.now()},
        {'username': 'Laura', 'id': 2, 'registration': datetime.now(), 'highscore': 28, 'points': 839, 'set_up_time': datetime.now()},
        {'username': 'Tobi', 'id': 3, 'registration': datetime.now(), 'highscore': 27, 'points': 818, 'set_up_time': datetime.now()},
        {'username': 'Sofia', 'id': 4, 'registration': datetime.now(), 'highscore': 24, 'points': 739, 'set_up_time': datetime.now()},
        {'username': 'Ben', 'id': 5, 'registration': datetime.now(), 'highscore': 21, 'points': 714, 'set_up_time': datetime.now()},
        {'username': 'Anna', 'id': 6, 'registration': datetime.now(), 'highscore': 20, 'points': 677, 'set_up_time': datetime.now()},
        {'username': 'Felix', 'id': 7, 'registration': datetime.now(), 'highscore': 19, 'points': 630, 'set_up_time': datetime.now()},
        {'username': 'Nina', 'id': 8, 'registration': datetime.now(), 'highscore': 16, 'points': 528, 'set_up_time': datetime.now()},
        {'username': 'Jonas', 'id': 9, 'registration': datetime.now(), 'highscore': 15, 'points': 435, 'set_up_time': datetime.now()},
        {'username': 'Lea', 'id': 10, 'registration': datetime.now(), 'highscore': 14, 'points': 426, 'set_up_time': datetime.now()},
        {'username': 'Tim', 'id': 11, 'registration': datetime.now(), 'highscore': 10, 'points': 331, 'set_up_time': datetime.now()},
        {'username': 'Emily', 'id': 12, 'registration': datetime.now(), 'highscore': 8, 'points': 322, 'set_up_time': datetime.now()},
        {'username': 'Chris', 'id': 13, 'registration': datetime.now(), 'highscore': 5, 'points': 230, 'set_up_time': datetime.now()},
        {'username': 'Lena', 'id': 14, 'registration': datetime.now(), 'highscore': 3, 'points': 121, 'set_up_time': datetime.now()},
        {'username': 's4005560', 'id': 15, 'registration': datetime.now(), 'highscore': 2, 'points': 736, 'set_up_time': datetime.now()},
    ]

    # 🔢 Sortiere nach Punkten absteigend
    sorted_players = sorted(all_players, key=lambda x: x['points'], reverse=True)

    # 🔟 Top 10 extrahieren
    top_players = sorted_players[:10]

    # 👤 Aktuellen Benutzer aus der Session holen
    current_user = session.get('username')

    # 👉 Variablen für den eingeloggten Spieler initialisieren
    current_player = None
    player_rank = None

    # 🔍 Aktuellen Benutzer in der vollständigen Rangliste finden
    if current_user:
        for idx, player in enumerate(sorted_players, start=1):
            if player['username'] == current_user:
                current_player = player     # Spieler-Objekt speichern
                player_rank = idx           # Platz speichern (1-basiert)
                break

    # 📤 An ranking.html übergeben:
    return render_template(
        'ranking.html',
        top_players=top_players,          # Nur Top 10
        current_player=current_player,    # Falls außerhalb der Top 10
        player_rank=player_rank           # Position des Spielers
    )


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)