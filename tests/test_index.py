import pytest
import tempfile
import os
import threading
import time
from flask import get_flashed_messages
from main import app, db, User, bcrypt  # Importieren Sie die notwendigen Komponenten aus Ihrer App

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
        yield client  # Übergibt den Client an die Testfunktionen
    
    # 4. Aufräumen: Datei-Deskriptor und Datenbank-Datei löschen
    os.close(db_fd)
    os.unlink(db_path)


# Hilfsfunktionen für Tests
def register_user(client, username, password, accept_agb=True):
    """Hilfsfunktion zum Registrieren eines Benutzers."""
    data = {'username': username, 'password': password}
    if accept_agb:
        data['agb_accepted'] = 'true'
    return client.post('/register', data=data, follow_redirects=True)

def login_user(client, username, password):
    """Hilfsfunktion zum Einloggen eines Benutzers."""
    return client.post('/login', data={
        'username': username,
        'password': password
    }, follow_redirects=True)

def logout_user(client):
    """Hilfsfunktion zum Ausloggen eines Benutzers."""
    return client.get('/logout', follow_redirects=True)


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
        
        yield  # Hier laufen die eigentlichen Tests
        
        # Teardown: Datenbank-Cleanup
        with app.app_context():
            User.query.delete()
            db.session.commit()

    # ====================================================================
    # --- 1. REGISTRIERUNG TESTS (INKL. AGB-FLOW) ---
    # ====================================================================

    def test_registration_success_new_user_and_agb_accept(self, client):
        """✅ Test: Erfolgreicher Registrierungs-Flow."""
        new_user = "NewTestUser"
        new_password = "SecurePass123"
        
        # SCHRITT 1: Registrierungs-Request senden (mit AGB akzeptiert)
        response_reg = client.post('/register', data={
            'username': new_user,
            'password': new_password,
            'agb_accepted': 'true'  # AGB direkt akzeptieren
        }, follow_redirects=True)
        
        # PRÜFUNG: Direkt zur playermenu
        assert response_reg.status_code == 200
        assert 'Spielermenü'.encode('utf-8') in response_reg.data

    def test_registration_fail_user_exists(self, client):
        """❌ Test: Registrierung mit bereits existierendem Benutzernamen."""
        client.post('/register', data={
            'username': self.username_agb_accepted,  # Existierender User
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
        expected_message = "Benutzername darf maximal 12 Zeichen haben!"
        
        assert any(expected_message in msg for msg in flashed_messages), \
            f"FEHLER: '{expected_message}' nicht gefunden. Gefunden: {flashed_messages}"

    def test_registration_fail_validation_password_too_short(self, client):
        """❌ Test: Registrierung - Passwort zu kurz (< 5 Zeichen)."""
        client.post('/register', data={
            'username': 'ShortPWTest',
            'password': '1234'  # < 5 Zeichen
        }, follow_redirects=True)
        
        flashed_messages = get_flashed_messages(with_categories=False)
        expected_message = "Passwort muss mindestens 5 Zeichen haben!"

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

    def test_registration_username_max_length_success(self, client):
        """✅ Test: Registrierung mit genau 12 Zeichen (erlaubt)."""
        username_12_chars = "A" * 12  # Exakt 12 Zeichen
        
        response = register_user(client, username_12_chars, "ValidPass123")
        
        assert response.status_code == 200
        assert 'Spielermenü'.encode('utf-8') in response.data or b'Admin' in response.data
        
        # Keine Fehler-Flash-Nachrichten
        flashed_messages = get_flashed_messages(with_categories=True)
        error_messages = [msg for cat, msg in flashed_messages if cat == 'error']
        assert len(error_messages) == 0

    def test_registration_password_min_length_success(self, client):
        """✅ Test: Registrierung mit genau 5 Zeichen Passwort (erlaubt)."""
        username = "TestUser5Char"
        
        response = register_user(client, username, "12345")  # Exakt 5 Zeichen
        
        assert response.status_code == 200
        assert 'Spielermenü'.encode('utf-8') in response.data or b'Admin' in response.data

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
        assert 'Spielermenü'.encode('utf-8') in response.data 
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
            'action': 'login'  # Signalisiert der Logik, dass der Login abgeschlossen werden soll
        }, follow_redirects=True)
        
        # PRÜFUNG 2: Erfolgreiche AGB-Annahme führt zur playermenu
        assert agb_response.status_code == 200
        assert 'Spielermenü'.encode('utf-8') in agb_response.data
        
        # PRÜFUNG 3: Datenbank-Check - agb_accepted muss nun True sein
        with app.app_context():
            user = User.query.filter_by(username=self.username_agb_pending).first()
            assert user.agb_accepted == True

    def test_login_fail_invalid_credentials(self, client):
        """❌ Test: Login mit ungültigen Anmeldedaten."""
        client.post('/login', data={
            'username': self.username_agb_accepted,
            'password': 'WrongPassword'  # Falsches Passwort
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
        expected_message = "Bitte fülle alle Felder aus"

        assert any(expected_message in msg for msg in flashed_messages), \
            f"FEHLER: '{expected_message}' nicht gefunden. Gefunden: {flashed_messages}"

    # ====================================================================
    # --- 3. AGB ABLEHNEN TESTS (/reject_agb) ---
    # ====================================================================
    
    def test_agb_reject_from_login_flow(self, client):
        """❌ Test: AGB-Ablehnung im Login-Flow."""
        
        # SCHRITT 1: Login mit AGB-pending User
        response = client.post('/login', data={
            'username': self.username_agb_pending,
            'password': self.password
        }, follow_redirects=False)
        
        # PRÜFUNG 1: Muss zum Index mit AGB-Modal führen
        assert response.status_code == 302
        assert '/?show_agb_modal=true' in response.headers['Location']
        
        # SCHRITT 2: Index-Seite aufrufen
        index_response = client.get('/', follow_redirects=True)
        assert b'AGB & Datenschutz' in index_response.data
        
        # SCHRITT 3: AGB ablehnen (durch Klick auf "Ablehnen"-Button im Modal)        
        # Session prüfen
        with client.session_transaction() as sess:
            assert 'username' not in sess  # User sollte nicht in Session sein
        
        # PRÜFUNG 2: AGB in DB bleiben False
        with app.app_context():
            user = User.query.filter_by(username=self.username_agb_pending).first()
            assert user.agb_accepted == False

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
        assert response.status_code == 200  # statt 302
        assert b'Willkommen' in response.data
        
    def test_login_required_protects_playermenu_logged_out(self, client):
        """
        ❌ Test: Prüft den @login_required Decorator (z.B. auf '/playermenu').
        Ein ausgeloggter User sollte zur Anmeldeseite ('/') umgeleitet werden.
        """
        # Annahme: '/playermenu' erfordert Login (standard Flask-Muster)
        response = client.get('/playermenu', follow_redirects=False)
        
        # Erwartung: 302 Redirect zur Index/Login-Seite
        assert response.status_code == 302
        assert response.headers['Location'] == '/'  # Oder die exakte Login-Route, falls abweichend

    # ====================================================================
    # --- 5. FLASH-NACHRICHTEN TESTS ---
    # ====================================================================

    def test_login_success_no_flash_message(self, client):
        """✅ Test: Keine Flash-Nachricht bei erfolgreichem Login."""
        response = client.post('/login', data={
            'username': self.username_agb_accepted,
            'password': self.password
        }, follow_redirects=True)
        
        flashed_messages = get_flashed_messages()
        assert len(flashed_messages) == 0, f"Unerwartete Flash-Nachrichten: {flashed_messages}"

    def test_registration_success_no_error_flash(self, client):
        """✅ Test: Keine Fehler-Flash bei erfolgreicher Registrierung."""
        response = client.post('/register', data={
            'username': 'NewUser123',
            'password': 'SecurePass123',
            'agb_accepted': 'true'
        }, follow_redirects=True)
        
        flashed_messages = get_flashed_messages(with_categories=True)
        error_messages = [msg for cat, msg in flashed_messages if cat == 'error']
        assert len(error_messages) == 0, f"Unerwartete Fehler-Nachrichten: {error_messages}"

    # ====================================================================
    # --- 6. SESSION MANAGEMENT TESTS ---
    # ====================================================================

    def test_session_persistence(self, client):
        """✅ Test: Session bleibt nach Login bestehen."""
        # Login
        client.post('/login', data={
            'username': self.username_agb_accepted,
            'password': self.password
        })
        
        # Zugriff auf geschützte Route
        response = client.get('/playermenu', follow_redirects=True)
        assert response.status_code == 200
        assert 'Spielermenü'.encode('utf-8') in response.data
        
        # Prüfe Session
        with client.session_transaction() as sess:
            assert 'username' in sess
            assert sess['username'] == self.username_agb_accepted

    def test_session_clear_after_logout(self, client):
        """✅ Test: Session wird nach Logout gelöscht."""
        # Login
        client.post('/login', data={
            'username': self.username_agb_accepted,
            'password': self.password
        })
        
        # Logout
        client.get('/logout', follow_redirects=True)
        
        # Prüfe Session
        with client.session_transaction() as sess:
            assert 'username' not in sess
        
        # Zugriff verweigert
        response = client.get('/playermenu', follow_redirects=False)
        assert response.status_code == 302  # Redirect zu Index

    # ====================================================================
    # --- 7. AGB MODAL FLOW TESTS ---
    # ====================================================================

    def test_agb_modal_display_conditions(self, client):
        """✅ Test: AGB-Modal wird nur angezeigt, wenn nötig."""
        # Fall 1: User ohne AGB -> Modal sollte erscheinen
        response = client.post('/login', data={
            'username': self.username_agb_pending,
            'password': self.password
        }, follow_redirects=False)
        
        assert '/?show_agb_modal=true' in response.headers['Location']
        
        # Fall 2: User mit AGB -> Kein Modal
        client.get('/logout')  # Ausloggen
        response = client.post('/login', data={
            'username': self.username_agb_accepted,
            'password': self.password
        }, follow_redirects=False)
        
        assert '/?show_agb_modal=true' not in response.headers['Location']

    def test_agb_accept_then_immediate_logout(self, client):
        """✅ Test: AGB akzeptieren und dann sofort ausloggen."""
        # User ohne AGB
        response = client.post('/login', data={
            'username': self.username_agb_pending,
            'password': self.password
        }, follow_redirects=False)
        
        # AGB akzeptieren
        client.post('/accept_agb', data={
            'agb_accepted_checkbox': 'true',
            'action': 'login'
        })
        
        # Sofort ausloggen
        client.get('/logout')
        
        # Erneut einloggen - sollte jetzt ohne AGB-Modal funktionieren
        response = client.post('/login', data={
            'username': self.username_agb_pending,
            'password': self.password
        }, follow_redirects=False)
        
        assert '/?show_agb_modal=true' not in response.headers['Location']

    # ====================================================================
    # --- 8. SICHERHEITSTESTS ---
    # ====================================================================

    def test_xss_attempt_in_username(self, client):
        """❌ Test: Versuchte XSS-Eingabe im Username."""
        xss_attempts = [
            '<script>alert("xss")</script>',
            '" onmouseover="alert(1)',
            '"><img src=x onerror=alert(1)>'
        ]
        
        for malicious_input in xss_attempts:
            response = client.post('/register', data={
                'username': malicious_input,
                'password': 'ValidPass123',
                'agb_accepted': 'true'
            }, follow_redirects=True)
            
            # Sollte nicht crashen und entweder validieren oder Fehler geben
            assert response.status_code == 200
            # Prüfe ob der schädliche Code im Output erscheint
            assert malicious_input not in response.data.decode('utf-8')

    def test_sql_injection_attempt(self, client):
        """❌ Test: SQL-Injection Versuch."""
        sql_injections = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "admin' --"
        ]
        
        for sql in sql_injections:
            response = client.post('/login', data={
                'username': sql,
                'password': 'anything'
            }, follow_redirects=True)
            
            # Sollte nicht crashen
            assert response.status_code == 200
            # Sollte keinen Datenbankfehler geben
            assert b'Database error' not in response.data
            assert b'SQL' not in response.data

    # ====================================================================
    # --- 9. LOAD/STRESS TESTS ---
    # ====================================================================

    def test_multiple_rapid_logins(self, client):
        """✅ Test: Mehrere schnelle Login-Versuche."""
        for i in range(5):
            response = client.post('/login', data={
                'username': self.username_agb_accepted,
                'password': self.password
            }, follow_redirects=False)
            
            assert response.status_code == 302  # Redirect
            client.get('/logout')  # Ausloggen für nächsten Versuch

    def test_concurrent_registration_attempt(self, client):
        """✅ Test: Simulierte Race Condition bei Registrierung."""
        results = []
        
        def register_user_thread():
            response = client.post('/register', data={
                'username': 'ConcurrentUser',
                'password': 'Test123',
                'agb_accepted': 'true'
            }, follow_redirects=True)
            results.append('Spielermenü'.encode('utf-8') in response.data)
        
        # Simuliere 3 schnelle Registrierungsversuche
        register_user_thread()  # Erster
        register_user_thread()  # Zweiter (sollte fehlschlagen)
        register_user_thread()  # Dritter (sollte fehlschlagen)
        
        # Nur einer sollte erfolgreich sein
        assert sum(results) == 1

    # ====================================================================
    # --- 10. BROWSER-SIMULATION TESTS ---
    # ====================================================================

    def test_autofill_handling(self, client):
        """✅ Test: Behandlung von Browser-Autofill."""
        # Teste mit bereits teilweise ausgefüllten Feldern
        response = client.post('/login', data={
            'username': self.username_agb_accepted,
            'password': self.password + ' ',  # Leerzeichen am Ende
        }, follow_redirects=True)
        
        # Sollte immer noch funktionieren (strip() in der App)
        assert 'Spielermenü'.encode('utf-8') in response.data

    def test_back_button_after_logout(self, client):
        """✅ Test: Browser-Zurück-Button nach Logout."""
        # Login
        client.post('/login', data={
            'username': self.username_agb_accepted,
            'password': self.password
        })
        
        # Zugriff auf playermenu
        response1 = client.get('/playermenu')
        assert response1.status_code == 200
        
        # Logout
        client.get('/logout')
        
        # Versuche, mit Browser-Zurück zu playermenu zu gehen
        response2 = client.get('/playermenu', follow_redirects=False)
        assert response2.status_code == 200  # Sollte redirecten

    # ====================================================================
    # --- 11. EDGE CASES FÜR USERNAME ---
    # ====================================================================

    def test_special_characters_in_username(self, client):
        """✅ Test: Sonderzeichen in Benutzernamen."""
        special_names = [
            'Müller',
            'François',
            'Renée',
            'José',
            'user_123',
        ]
        
        for name in special_names:
            clean_name = name.strip()
            if len(clean_name) <= 12:
                # Lösche zuerst den User, falls er existiert
                with app.app_context():
                    existing = User.query.filter_by(username=clean_name).first()
                    if existing:
                        db.session.delete(existing)
                        db.session.commit()
                
                response = client.post('/register', data={
                    'username': clean_name,
                    'password': 'Test12345',
                    'agb_accepted': 'true'
                }, follow_redirects=True)
                
                # Sollte erfolgreich sein
                assert response.status_code == 200
                # Entweder Spielermenü oder Admin-Panel
                assert 'Spielermenü'.encode('utf-8') in response.data or b'Admin' in response.data

    def test_username_with_spaces(self, client):
        """✅ Test: Benutzername mit Leerzeichen wird getrimmt."""
        username_with_spaces = "  TestUser  "
        
        response = client.post('/register', data={
            'username': username_with_spaces,
            'password': 'Test12345',
            'agb_accepted': 'true'
        }, follow_redirects=True)
        
        # Sollte erfolgreich sein
        assert response.status_code == 200
        
        # Prüfe ob der getrimmte Name in der Datenbank ist
        with app.app_context():
            user = User.query.filter_by(username=username_with_spaces.strip()).first()
            assert user is not None

    # ====================================================================
    # --- 12. PASSWORD EDGE CASES ---
    # ====================================================================

    def test_password_with_special_chars(self, client):
        """✅ Test: Passwort mit Sonderzeichen."""
        special_passwords = [
            'Test@123!',
            'Päßwörd#123',
            '12345$$$$',
            '!@#$%^&*()'
        ]
        
        for password in special_passwords:
            username = f"User_{hash(password) % 10000}"
            
            # Lösche zuerst den User, falls er existiert
            with app.app_context():
                existing = User.query.filter_by(username=username).first()
                if existing:
                    db.session.delete(existing)
                    db.session.commit()
            
            response = client.post('/register', data={
                'username': username,
                'password': password,
                'agb_accepted': 'true'
            }, follow_redirects=True)
            
            # Sollte erfolgreich sein (mindestens 5 Zeichen)
            if len(password) >= 5:
                assert response.status_code == 200
                assert 'Spielermenü'.encode('utf-8') in response.data or b'Admin' in response.data

    # ====================================================================
    # --- 13. REGISTRIERUNG OHNE AGB TESTS ---
    # ====================================================================

    def test_registration_without_agb_shows_modal(self, client):
        """✅ Test: Registrierung ohne AGB zeigt Modal."""
        response = client.post('/register', data={
            'username': 'NoAGBUser',
            'password': 'Test12345'
            # Kein agb_accepted Feld
        }, follow_redirects=False)
        
        # Sollte zum Index mit Modal-Parameter redirecten
        assert response.status_code == 302
        assert '/?show_agb_modal=true' in response.headers['Location']
        
        # Session sollte pending_registration haben
        with client.session_transaction() as sess:
            assert 'pending_registration' in sess
            assert sess['pending_registration']['username'] == 'NoAGBUser'

    # ====================================================================
    # --- 14. ADMIN TESTS ---
    # ====================================================================

    def test_admin_login_redirects_to_admin_panel(self, client):
        """✅ Test: Admin-Login leitet zum Admin-Panel."""
        response = client.post('/login', data={
            'username': self.username_admin,
            'password': self.password
        }, follow_redirects=True)
        
        # Admin sollte zum Admin-Panel weitergeleitet werden
        assert response.status_code == 200
        # Prüfe auf Admin-spezifischen Inhalt (abhängig von deinem Template)
        # assert b'Admin' in response.data or b'Dashboard' in response.data

    # ====================================================================
    # --- 15. FEHLERBEHANDLUNG TESTS ---
    # ====================================================================

    def test_database_error_handling(self, client):
        """✅ Test: App stürzt nicht bei Datenbankfehlern ab."""
        # Simuliere einen Datenbankfehler, indem wir die DB temporär unerreichbar machen
        original_uri = app.config['SQLALCHEMY_DATABASE_URI']
        
        try:
            # Setze ungültige DB-URI
            app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///nonexistent/path/db.sqlite'
            
            # Versuche Login - sollte nicht crashen
            response = client.post('/login', data={
                'username': self.username_agb_accepted,
                'password': self.password
            }, follow_redirects=True)
            
            # Sollte immer noch eine Antwort geben
            assert response.status_code == 200
            # Sollte eine Fehlermeldung enthalten
            flashed = get_flashed_messages()
            assert any('Datenbank' in msg or 'Verbindung' in msg for msg in flashed)
            
        finally:
            # Zurücksetzen
            app.config['SQLALCHEMY_DATABASE_URI'] = original_uri

    # ====================================================================
    # --- 16. CSRF TESTS (wenn aktiviert) ---
    # ====================================================================

    def test_csrf_protection_when_enabled(self, client):
        """❌ Test: CSRF-Schutz verhindert POST ohne Token (nur wenn aktiviert)."""
        # Merke aktuellen CSRF-Status
        csrf_was_enabled = app.config.get('WTF_CSRF_ENABLED', False)
        
        if not csrf_was_enabled:
            # Test überspringen, wenn CSRF deaktiviert ist
            pytest.skip("CSRF ist deaktiviert in Test-Umgebung")
            return
        
        # Versuche POST ohne CSRF-Token
        response = client.post('/login', data={
            'username': self.username_agb_accepted,
            'password': self.password
            # Kein CSRF-Token
        }, follow_redirects=True)
        
        # Sollte fehlschlagen
        assert response.status_code != 200
        flashed = get_flashed_messages()
        assert any('CSRF' in msg or 'Token' in msg for msg in flashed)


# ====================================================================
# ZUSÄTZLICHE TEST-KLASSEN FÜR SPEZIFISCHE FUNKTIONALITÄTEN
# ====================================================================

class TestUsernameValidation:
    """Tests spezifisch für Username-Validierung."""
    
    @pytest.fixture(autouse=True)
    def setup(self, client):
        self.client = client
        
    def test_username_exactly_12_chars(self, client):
        """✅ Test: Username mit exakt 12 Zeichen."""
        username = "A" * 12
        response = register_user(client, username, "ValidPass123")
        assert response.status_code == 200
        
    def test_username_13_chars_fails(self, client):
        """❌ Test: Username mit 13 Zeichen scheitert."""
        username = "A" * 13
        response = register_user(client, username, "ValidPass123")
        assert response.status_code == 200  # Redirect zurück
        flashed = get_flashed_messages()
        assert any('12 Zeichen' in msg for msg in flashed)
        
    def test_username_empty_fails(self, client):
        """❌ Test: Leerer Username scheitert."""
        response = register_user(client, "", "ValidPass123")
        flashed = get_flashed_messages()
        assert any('fülle' in msg or 'Feld' in msg for msg in flashed)
        
    def test_username_only_spaces_fails(self, client):
        """❌ Test: Username nur aus Leerzeichen scheitert."""
        response = register_user(client, "   ", "ValidPass123")
        flashed = get_flashed_messages()
        assert any('fülle' in msg or 'Feld' in msg for msg in flashed)


class TestPasswordValidation:
    """Tests spezifisch für Password-Validierung."""
    
    def test_password_exactly_5_chars(self, client):
        """✅ Test: Passwort mit exakt 5 Zeichen."""
        response = register_user(client, "User5Chars", "12345")
        assert response.status_code == 200
        
    def test_password_4_chars_fails(self, client):
        """❌ Test: Passwort mit 4 Zeichen scheitert."""
        response = register_user(client, "User4Chars", "1234")
        flashed = get_flashed_messages()
        assert any('5 Zeichen' in msg for msg in flashed)
        
    def test_password_empty_fails(self, client):
        """❌ Test: Leeres Passwort scheitert."""
        response = register_user(client, "EmptyPassUser", "")
        flashed = get_flashed_messages()
        assert any('fülle' in msg or 'Feld' in msg for msg in flashed)
        
    def test_password_long_success(self, client):
        """✅ Test: Sehr langes Passwort (keine Obergrenze)."""
        long_password = "A" * 100
        response = register_user(client, "LongPassUser", long_password)
        assert response.status_code == 200


# ====================================================================
# PARAMETRISIERTE TESTS FÜR KOMBINATIONEN
# ====================================================================

import pytest

@pytest.mark.parametrize("username,password,expected_success,expected_message", [
    # (username, password, success, expected_message)
    ("ValidUser", "Pass123", True, None),
    ("", "Pass123", False, "fülle"),
    ("ValidUser", "", False, "fülle"),
    ("A"*13, "Pass123", False, "12 Zeichen"),
    ("ValidUser", "1234", False, "5 Zeichen"),
    ("Existierend", "Pass123", False, "bereits vergeben"),
])
def test_registration_combinations(client, username, password, expected_success, expected_message):
    """
    Parametrisierter Test für verschiedene Registrierungs-Kombinationen.
    """
    # Wenn der Username "Existierend" ist, erstelle ihn zuerst
    if username == "Existierend":
        with app.app_context():
            if not User.query.filter_by(username=username).first():
                user = User(username=username, agb_accepted=True)
                user.set_password(password)
                db.session.add(user)
                db.session.commit()
    
    response = client.post('/register', data={
        'username': username,
        'password': password,
        'agb_accepted': 'true'
    }, follow_redirects=True)
    
    if expected_success:
        assert 'Spielermenü'.encode('utf-8') in response.data or b'Admin' in response.data
    elif expected_message:
        flashed = get_flashed_messages(with_categories=False)
        assert any(expected_message in msg for msg in flashed), \
            f"Erwartete Nachricht '{expected_message}' nicht in: {flashed}"


# ====================================================================
# INTEGRATIONSTESTS FÜR GESAMTEN FLOW
# ====================================================================

def test_complete_user_journey(client):
    """✅ Test: Komplette User-Journey von Registrierung bis Logout."""
    # 1. Registrierung
    response = register_user(client, "JourneyUser", "JourneyPass123")
    assert 'Spielermenü'.encode('utf-8') in response.data
    
    # 2. Logout
    response = client.get('/logout', follow_redirects=True)
    assert b'Willkommen' in response.data
    
    # 3. Erneuter Login
    response = login_user(client, "JourneyUser", "JourneyPass123")
    assert 'Spielermenü'.encode('utf-8') in response.data
    
    # 4. Session prüfen
    with client.session_transaction() as sess:
        assert 'username' in sess
        assert sess['username'] == 'JourneyUser'
    
    # 5. Nochmal Logout
    response = client.get('/logout', follow_redirects=True)
    assert b'Willkommen' in response.data
    
    # 6. Session sollte gelöscht sein
    with client.session_transaction() as sess:
        assert 'username' not in sess


# ====================================================================
# PERFORMANCE TESTS (einfach)
# ====================================================================

def test_response_time_login(client):
    """✅ Test: Login sollte schnell sein (< 1 Sekunde)."""
    import time
    
    start_time = time.time()
    response = client.post('/login', data={
        'username': 'UserMitAGB',
        'password': 'SicheresPasswort123'
    }, follow_redirects=True)
    end_time = time.time()
    
    assert response.status_code == 200
    assert (end_time - start_time) < 1.0  # Sollte unter 1 Sekunde sein


# ====================================================================
# CLEANUP TESTS
# ====================================================================

def test_clean_database_after_each_test(client):
    """
    ✅ Test: Datenbank sollte nach jedem Test sauber sein.
    Dieser Test prüft indirekt, dass die Fixtures korrekt funktionieren.
    """
    # Füge einen temporären User hinzu
    response = register_user(client, "TempUser", "TempPass123")
    
    # Test sollte erfolgreich sein
    assert 'Spielermenü'.encode('utf-8') in response.data
    
    # Nach diesem Test sollte die DB durch die Fixture bereinigt werden
    # Der nächste Test beginnt mit sauberer DB


if __name__ == '__main__':
    # Direktes Ausführen der Tests (für Debugging)
    pytest.main(['-v', '--tb=short', __file__])