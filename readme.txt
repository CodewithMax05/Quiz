Clash under Minds (Betriebsanleitung)

Live-Version
Die Anwendung ist live auf Render erreichbar unter: https://quiz-1ki1.onrender.com
Der Server fährt durch Inaktivität alle 15min runter. Man muss 2-5min warten, bis der Server hochgefahren ist.

Lokale Inbetriebnahme
Folge diesen Schritten, um das Projekt lokal auf deinem Computer zu starten.

1. Projekt klonen
Klone das Repository auf deinen lokalen Rechner. Wähle eine der beiden Methoden (HTTPS oder SSH).
### WICHTIG: Es wird Python Version 3.12 benötigt!!! ###

# Navigiere zuerst in das Verzeichnis, in das du klonen willst
Zum Beispiel: cd "C:\Users\<NAME>\Downloads>"

# HTTPS
git clone https://git-stu.ba-glauchau.de/game-quiz/game-quiz.git

# ODER über SSH (benötigt einen konfigurierten SSH-Key)
git clone git@git-stu.ba-glauchau.de:game-quiz/game-quiz.git

--> Ordner "quiz-game" wird im Verzeichnis erstellt

cd <PROJEKT_ORDNER>
Zum Beispiel: cd "C:\Users\<NAME>\Downloads\quiz-game>"

2. (Empfohlen) Virtuelle Umgebung erstellen
Es ist empfehlenswert eine virtuelle Umgebung zu verwenden, um Abhängigkeiten zu isolieren.

# Erstelle eine venv
python3.12 -m venv venv

# Aktiviere die Umgebung
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

3. Abhängigkeiten installieren
Alle notwendigen Pakete sind in der requirements.txt aufgelistet.

pip install -r requirements.txt

4. Umgebungsvariablen
Erstelle eine Datei namens .env im Hauptverzeichnis des Projekts. Dort werden die Umgebungsvariablen gespeichert.

# Füge folgende Zeilen ein:
ADMIN_PASSWORD=<PASSWORT>
ADMIN_USERNAME=<NAME>
DATABASE_URL=sqlite:///quiz.db
FLASK_ENV=development
SECRET_KEY=<SICHERER_KEY>
SESSION_COOKIE_SECURE=false

# Du solltest die Werte hinter dem "=" für den Namen, das Passwort und den Key anpassen! 
# Der Name darf maximal 12 Zeichen lang sein und das Passwort muss mindestens 5 Zeichen lang sein.
# Der Admin hat zusätzlich ein Admin Panel zur Verfügung. 
# Für einen sicheren SECRET_KEY kannst du folgenden Befehl ausführen: python -c "import secrets; print(secrets.token_hex(24))"

5. Anwendung starten
Sobald die Abhängigkeiten installiert sind, kannst du die Anwendung starten:

python main.py

6. Zugriff
Die Website ist jetzt lokal auf deinem Computer erreichbar. Der Standard-Port ist 5000.

Öffne deinen Browser und gehe zu: http://localhost:5000

Ausführen der Tests
Um die Tests auszuführen, müssen zuerst die Test-Pakete installiert werden.

1. Test-Abhängigkeiten installieren

pip install pytest
pip install Flask-Testing

2. Tests starten
Du kannst entweder alle Tests auf einmal oder nur bestimmte Testdateien ausführen.

# Alle Tests ausführen (ausführlicher Modus)
python -m pytest -v

# Nur eine bestimmte Testdatei ausführen (Beispiel)
python -m pytest tests/test_index.py -v

Wichtige Hinweise
Datenbank-Initialisierung: Beim ersten Start (oder wenn quiz.db nicht existiert) erstellt main.py automatisch die Datenbank und importiert alle Fragen aus den .csv-Dateien.