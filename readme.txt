Betriebsanleitung von Clash under Minds

Wichtig für die Inbetriebnahme!
 - Alle Packete müssen installiert werden, geben Sie dafür in die Konsole ein:  
    > pip install -r requirements.txt

Ausführen der Tests:
 - Vor dem Ausführen der Tests müssen 2 weitere Packete installiert werden, die Befehle dafür sind:
    > pip install pytest
    > pip install Flask-Testing
 - Die Tests können in 2 Varianten gestartet werden
    > alle Tests ausführen:
        python -m pytest -v
    > nur eine bestimmte Testdatei
        python -m pytest tests/test_index.py -v
     