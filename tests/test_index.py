import pytest
from main import app, db, User
import tempfile
import os

from flask import get_flashed_messages

@pytest.fixture
def client():
    # Temporäre Datenbank für Tests erstellen
    db_fd, db_path = tempfile.mkstemp()
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    
    with app.app_context():
        db.create_all()
    
    with app.test_client() as client:
        yield client
    
    # Aufräumen nach den Tests
    os.close(db_fd)
    os.unlink(db_path)

class TestLoginMenu:
    @pytest.fixture(autouse=True)
    def setup_and_teardown(self, client):
        """Wird vor jedem Test ausgeführt"""
        self.username = "ExistingUser"
        self.password = "TestPass123"
        
        with app.app_context():
            # Testbenutzer erstellen
            User.query.delete()
            user = User(username=self.username)
            user.set_password(self.password)
            db.session.add(user)
            db.session.commit()
        
        yield
        
        with app.app_context():
            # Aufräumen
            User.query.delete()
            db.session.commit()

    def test_create_new_user_success(self, client):
        """✅ Test: Neuen User erfolgreich erstellen"""
        response = client.post('/register', data={
            'username': 'NewUser',
            'password': 'NewPass123'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        # Überprüfe auf Weiterleitung zur Homepage
        assert b'homepage' in response.data.lower()
        
        # Überprüfe ob User in DB ist
        with app.app_context():
            user = User.query.filter_by(username='NewUser').first()
            assert user is not None

    def test_create_user_fail_duplicate(self, client):
        """❌ Test: Fehlschlag beim Erstellen - Username bereits vergeben"""
        response = client.post('/register', data={
            'username': self.username,  # Bereits existierender User
            'password': 'DifferentPass123'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        # Überprüfe auf die exakte Flash-Nachricht aus Ihrer App
        assert b'Benutzername bereits vergeben' in response.data

    def test_login_success(self, client):
        """✅ Test: User erfolgreich einloggen mit richtigen Daten"""
        response = client.post('/login', data={
            'username': self.username,
            'password': self.password
        }, follow_redirects=True)
        
        assert response.status_code == 200
        # Überprüfe auf Weiterleitung zur Homepage
        assert b'homepage' in response.data.lower()

    def test_login_fail_wrong_password(self, client):
        """❌ Test: Fehlschlag beim Einloggen - falsches Passwort"""
        response = client.post('/login', data={
            'username': self.username,
            'password': 'FalschesPasswort'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        # Überprüfe auf die exakte Flash-Nachricht aus Ihrer App
        assert b'Ung\xc3\xbcltige Anmeldedaten' in response.data

    '''def test_login_fail_short_password(self, client):
        """❌ Test: Fehlschlag beim Registrieren - Passwort zu kurz"""
        response = client.post('/register', data={
            'username': 'ShortPassUser',
            'password': '123'  # Zu kurz (min. 5 Zeichen)
        }, follow_redirects=True)
        
        assert response.status_code == 200
        # Genauer String-Vergleich mit der bekannten Fehlermeldung
        assert b'Passwort muss mindestens 5 Zeichen haben' in response.data'''
    
    '''def test_login_fail_short_password(self, client):
        """❌ Test: Fehlschlag beim Registrieren - Passwort zu kurz"""
        client.post('/register', data={
            'username': 'ShortPassUser',
            'password': '123'  # Zu kurz (min. 5 Zeichen)
        }, follow_redirects=True)
        
        messages = [msg for msg in get_flashed_messages()]
        assert any("Passwort muss mindestens 5 Zeichen haben" in msg for msg in messages)'''

    def test_login_fail_long_username(self, client):
        """❌ Test: Fehlschlag beim Registrieren - Username zu lang"""
        response = client.post('/register', data={
            'username': 'DieserBenutzernameIstVielZuLange',  # > 12 Zeichen
            'password': 'GutesPasswort123'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        # Überprüfe auf die exakte Flash-Nachricht aus Ihrer App
        assert b'Benutzername darf maximal 12 Zeichen haben' in response.data

    def test_empty_username_with_flash(self, client):
        """❌ Test: Fehlender Benutzername (Flash Message)"""
        client.post('/register', data={
            'username': '',
            'password': 'ValidPass123'
        }, follow_redirects=True)
        
        messages = [msg for msg in get_flashed_messages()]
        assert any("Bitte fülle alle Felder aus" in msg for msg in messages)

    '''def test_empty_password_with_flash(self, client):
        """❌ Test: Fehlendes Passwort (Flash Message)"""
        client.post('/register', data={
            'username': 'TestUser',
            'password': ''
        }, follow_redirects=True)
        
        messages = [msg for msg in get_flashed_messages()]
        assert any("Bitte fülle alle Felder aus" in msg for msg in messages)

    def test_empty_both_fields_with_flash(self, client):
        """❌ Test: Beide Felder leer (Flash Message)"""
        client.post('/register', data={
            'username': '',
            'password': ''
        }, follow_redirects=True)
        
        messages = [msg for msg in get_flashed_messages()]
        assert any("Bitte fülle alle Felder aus" in msg for msg in messages)
        assert len(messages) == 1  # Nur eine Fehlermeldung'''