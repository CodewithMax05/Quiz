import pytest
import tempfile
import os
from flask import get_flashed_messages
from main import app, db, User, bcrypt # Importieren Sie die notwendigen Komponenten aus Ihrer App

# ====================================================================
# FIXTURE: Vorbereitung der Testumgebung (Cleanup, Datenbank, Client)
# ====================================================================

@pytest.fixture
def client():
    """
    Erstellt einen Flask-Test-Client und initialisiert eine temporäre
    Datenbank für jeden Test. Dies stellt sicher, dass jeder Test
    in einer sauberen Umgebung startet und endet.

    - Temporäre Datenbank wird erstellt und nach dem Test gelöscht.
    - CSRF ist deaktiviert, um POST-Requests ohne Token zu ermöglichen.
    """
    # 1. Temporäre Datenbank-Datei erstellen (im Dateisystem)
    db_fd, db_path = tempfile.mkstemp()
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    app.config['TESTING'] = True 
    app.config['WTF_CSRF_ENABLED'] = False 
    
    # 2. Anwendungskontext herstellen und DB-Tabellen initialisieren
    with app.app_context():
        db.create_all()
    
    # 3. Test-Client bereitstellen
    with app.test_client() as client:
        yield client # Übergibt den Client an die Testfunktionen
    
    # 4. Aufräumen: Datei-Deskriptor und Datenbank-Datei löschen
    os.close(db_fd)
    os.unlink(db_path)

# ====================================================================
# TESTKLASSE: Testet den gesamten Authentifizierungs-Flow
# ====================================================================

class TestAuthFlow:
    
    @pytest.fixture(autouse=True)
    def setup_and_teardown(self, client):
        """
        Setup-Fixture: Wird vor JEDEM Test automatisch ausgeführt.
        Erstellt die notwendigen Testbenutzer in der Datenbank.
        """
        # Testdaten zur besseren Lesbarkeit definieren
        self.username_agb_accepted = "UserMitAGB"
        self.username_agb_pending = "UserOhneAGB"
        self.username_admin = "AdminZugang"
        self.password = "SicheresPasswort123"
        
        with app.app_context():
            # DB bereinigen, falls Reste vorhanden sind
            User.query.delete()
            
            # --- ERSTELLUNG DER TESTBENUTZER ---
            
            # 1. Normaler User, der AGB bereits akzeptiert hat
            user_agb_accepted = User(username=self.username_agb_accepted, agb_accepted=True)
            user_agb_accepted.set_password(self.password)
            db.session.add(user_agb_accepted)

            # 2. User, der die AGB noch akzeptieren MUSS (für den neuen Flow-Test)
            user_agb_needed = User(username=self.username_agb_pending, agb_accepted=False)
            user_agb_needed.set_password(self.password)
            db.session.add(user_agb_needed)
            
            # 3. Admin-User
            admin_user = User(username=self.username_admin, is_admin=True, agb_accepted=True)
            admin_user.set_password(self.password)
            db.session.add(admin_user)
            
            db.session.commit()
        
        yield # Hier laufen die eigentlichen Tests
        
        # Teardown: Datenbank-Cleanup
        with app.app_context():
            User.query.delete()
            db.session.commit()


    # ====================================================================
    # --- 1. REGISTRIERUNG TESTS (INKL. AGB-FLOW) ---
    # ====================================================================

    def test_registration_success_new_user_and_agb_accept(self, client):
        """
        ✅ Test: Erfolgreicher Registrierungs-Flow.
        (1) Registrieren, (2) Redirect zum AGB-Modal, (3) AGB annehmen, (4) zur playermenu.
        """
        new_user = "NewTestUser"
        new_password = "SecurePass123"
        
        # SCHRITT 1: Registrierungs-Request senden
        response_reg = client.post('/register', data={
            'username': new_user,
            'password': new_password
        }, follow_redirects=False)

        # PRÜFUNG 1: Muss zum Index mit AGB-Modal-Parameter weiterleiten
        assert response_reg.status_code == 302
        assert '/?show_agb_modal=true' in response_reg.headers['Location']
        
        # SCHRITT 2: Index-Seite aufrufen (simuliert den Browser-Redirect)
        index_response = client.get('/', follow_redirects=True)
        # Überprüfen, ob das AGB-Modal-Markup auf der Seite vorhanden ist
        assert b'AGB & Datenschutz' in index_response.data 
        
        # SCHRITT 3: AGB akzeptieren (Post zur /accept_agb Route)
        agb_response = client.post('/accept_agb', data={
            'agb_accepted_checkbox': 'true',
            'action': 'register' # Sagt der Logik, dass es um eine Registrierung geht
        }, follow_redirects=True)
        
        # PRÜFUNG 2: Erfolgreiche AGB-Annahme führt zur playermenu
        assert agb_response.status_code == 200
        assert b'Player Menu' in agb_response.data 
        
        # PRÜFUNG 3: Datenbank-Check
        with app.app_context():
            user = User.query.filter_by(username=new_user).first()
            assert user is not None
            assert user.agb_accepted == True


    def test_registration_fail_user_exists(self, client):
        """❌ Test: Registrierung mit bereits existierendem Benutzernamen."""
        client.post('/register', data={
            'username': self.username_agb_accepted, # Existierender User
            'password': 'SomePassword123'
        }, follow_redirects=True)
        
        # 1. Flash-Nachrichten abrufen
        flashed_messages = get_flashed_messages(with_categories=False)
        expected_message = "Benutzername bereits vergeben"

        # 2. Prüfen, ob die erwartete Fehlermeldung enthalten ist
        assert any(expected_message in msg for msg in flashed_messages), \
            f"FEHLER: '{expected_message}' nicht gefunden. Gefunden: {flashed_messages}"
        

    def test_registration_fail_validation_username_too_long(self, client):
        """❌ Test: Registrierung - Benutzername zu lang (> 12 Zeichen)."""
        client.post('/register', data={
            'username': 'DiesIstZuLangFuer12', 
            'password': 'GutesPasswort123'
        }, follow_redirects=True)
        
        flashed_messages = get_flashed_messages(with_categories=False)
        expected_message = "Benutzername darf maximal 12 Zeichen haben."
        
        assert any(expected_message in msg for msg in flashed_messages), \
            f"FEHLER: '{expected_message}' nicht gefunden. Gefunden: {flashed_messages}"

    def test_registration_fail_validation_password_too_short(self, client):
        """❌ Test: Registrierung - Passwort zu kurz (< 8 Zeichen)."""
        client.post('/register', data={
            'username': 'ShortPWTest',
            'password': 'short' # < 8 Zeichen
        }, follow_redirects=True)
        
        flashed_messages = get_flashed_messages(with_categories=False)
        expected_message = "Passwort muss mindestens 8 Zeichen lang sein."

        assert any(expected_message in msg for msg in flashed_messages), \
            f"FEHLER: '{expected_message}' nicht gefunden. Gefunden: {flashed_messages}"

    def test_registration_fail_empty_fields(self, client):
        """❌ Test: Fehlende Felder bei der Registrierung."""
        client.post('/register', data={
            'username': '',
            'password': ''
        }, follow_redirects=True)
        
        flashed_messages = get_flashed_messages(with_categories=False)
        expected_message = "Um einen Account anzulegen bitte Usernamen und Passwort wählen!"

        assert any(expected_message in msg for msg in flashed_messages), \
            f"FEHLER: '{expected_message}' nicht gefunden. Gefunden: {flashed_messages}"


    # ====================================================================
    # --- 2. LOGIN TESTS (INKL. AGB-FLOW) ---
    # ====================================================================

    def test_login_success_agb_already_accepted(self, client):
        """✅ Test: Erfolgreicher Login für User, der AGB bereits akzeptiert hat (Normaler Flow)."""
        response = client.post('/login', data={
            'username': self.username_agb_accepted,
            'password': self.password
        }, follow_redirects=True)
        
        # Erwartung: Direkte Weiterleitung zur playermenu und keine Flash Messages
        assert response.status_code == 200
        assert b'Player Menu' in response.data 
        assert get_flashed_messages() == []


    def test_login_success_agb_not_accepted_and_accept_agb(self, client):
        """
        ✅ Test: Erfolgreicher Login-Flow inklusive notwendiger AGB-Akzeptanz.
        User wird nach Login zum Modal geleitet und akzeptiert dort die AGBs.
        """
        
        # SCHRITT 1: Login senden (muss zu index mit AGB-Modal führen, da agb_accepted=False)
        response_login = client.post('/login', data={
            'username': self.username_agb_pending,
            'password': self.password
        }, follow_redirects=False)

        # PRÜFUNG 1: Erfolgreicher Login leitet auf den Index mit Query-Parameter
        assert response_login.status_code == 302
        assert '/?show_agb_modal=true' in response_login.headers['Location']
        
        # SCHRITT 2: AGB akzeptieren (Post zur /accept_agb Route)
        agb_response = client.post('/accept_agb', data={
            'agb_accepted_checkbox': 'true',
            'action': 'login' # Signalisiert der Logik, dass der Login abgeschlossen werden soll
        }, follow_redirects=True)
        
        # PRÜFUNG 2: Erfolgreiche AGB-Annahme führt zur playermenu
        assert agb_response.status_code == 200
        assert b'Player Menu' in agb_response.data
        
        # PRÜFUNG 3: Datenbank-Check - agb_accepted muss nun True sein
        with app.app_context():
            user = User.query.filter_by(username=self.username_agb_pending).first()
            assert user.agb_accepted == True
            
    
    def test_login_fail_invalid_credentials(self, client):
        """❌ Test: Login mit ungültigen Anmeldedaten."""
        client.post('/login', data={
            'username': self.username_agb_accepted,
            'password': 'WrongPassword' # Falsches Passwort
        }, follow_redirects=True)
        
        flashed_messages = get_flashed_messages(with_categories=False)
        expected_message = "Ungültige Anmeldedaten"
        
        assert any(expected_message in msg for msg in flashed_messages), \
            f"FEHLER: '{expected_message}' nicht gefunden. Gefunden: {flashed_messages}"
        
    def test_login_fail_empty_fields(self, client):
        """❌ Test: Fehlende Felder beim Login."""
        client.post('/login', data={
            'username': '',
            'password': ''
        }, follow_redirects=True)
        
        flashed_messages = get_flashed_messages(with_categories=False)
        expected_message = "Um einen Account anzulegen bitte Usernamen und Passwort wählen!"

        assert any(expected_message in msg for msg in flashed_messages), \
            f"FEHLER: '{expected_message}' nicht gefunden. Gefunden: {flashed_messages}"

    # ====================================================================
    # --- 3. AGB ABLEHNEN TESTS (/reject_agb) ---
    # ====================================================================
    
    def test_agb_reject_from_login_flow(self, client):
        """
        ❌ Test: AGB-Ablehnung, wenn der User nach dem Login zum Akzeptieren gezwungen wird.
        Erwartung: User wird ausgeloggt, AGB bleibt False, Flash Message.
        """
        
        # SCHRITT 1: Login triggert AGB-Modal
        client.post('/login', data={
            'username': self.username_agb_pending,
            'password': self.password
        }, follow_redirects=False)

        # SCHRITT 2: AGB ablehnen (/reject_agb Route)
        reject_response = client.post('/reject_agb', data={
            'confirm_reject': 'true'
        }, follow_redirects=True)
        
        # PRÜFUNG 1: Weiterleitung zum Index
        assert reject_response.status_code == 200 
        
        # PRÜFUNG 2: Flash Message gesetzt
        flashed_messages = get_flashed_messages(with_categories=False)
        expected_message = "AGBs abgelehnt. Du wurdest abgemeldet."
        assert any(expected_message in msg for msg in flashed_messages), \
            f"FEHLER: '{expected_message}' nicht gefunden. Gefunden: {flashed_messages}"

        # PRÜFUNG 3: Datenbank-Check - agb_accepted ist unverändert False
        with app.app_context():
            user = User.query.filter_by(username=self.username_agb_pending).first()
            assert user.agb_accepted == False 
    
    def test_agb_reject_from_settings_menu(self, client):
        """
        ❌ Test: AGB-Ablehnung durch einen bereits eingeloggten User (aus den Einstellungen).
        Erwartung: User wird ausgeloggt, agb_accepted wird in der DB auf False gesetzt.
        """
        
        # SCHRITT 1: User manuell in die Session einloggen
        with client.session_transaction() as sess:
            sess['username'] = self.username_agb_accepted
            
        # SCHRITT 2: AGB ablehnen (/reject_agb Route)
        client.post('/reject_agb', data={
            'confirm_reject': 'true'
        }, follow_redirects=True)
        
        # PRÜFUNG 1: Datenbank-Check - agb_accepted MUSS auf False gesetzt werden
        with app.app_context():
            user = User.query.filter_by(username=self.username_agb_accepted).first()
            assert user.agb_accepted == False
            
        # PRÜFUNG 2: Session-Check - User MUSS ausgeloggt sein
        with client.session_transaction() as sess:
            assert 'username' not in sess


    # ====================================================================
    # --- 4. DECORATOR TESTS (@logout_required, @login_required) ---
    # ====================================================================

    def test_logout_required_redirects_logged_in_user_from_index(self, client):
        """
        ✅ Test: Prüft den @logout_required Decorator auf '/'.
        Ein eingeloggter User sollte von der Startseite zur playermenu umgeleitet werden (302).
        """
        # User manuell in Session einloggen
        with client.session_transaction() as sess:
            sess['username'] = self.username_agb_accepted
            
        response = client.get('/', follow_redirects=False)
        
        # Erwartung: 302 Redirect zur playermenu
        assert response.status_code == 302
        assert response.headers['Location'] == '/playermenu'
        
    def test_login_required_protects_playermenu_logged_out(self, client):
        """
        ❌ Test: Prüft den @login_required Decorator (z.B. auf '/playermenu').
        Ein ausgeloggter User sollte zur Anmeldeseite ('/') umgeleitet werden.
        """
        # Annahme: '/playermenu' erfordert Login (standard Flask-Muster)
        response = client.get('/playermenu', follow_redirects=False)
        
        # Erwartung: 302 Redirect zur Index/Login-Seite
        assert response.status_code == 302
        assert response.headers['Location'] == '/' # Oder die exakte Login-Route, falls abweichend
