    let timerInterval;
    let timeLeft = 30;

    const timerText = document.querySelector('.timer-text');
    const timerProgress = document.querySelector('.timer-progress');
    const timerContainer = document.querySelector('.timer-container');
    const scoreDisplay = document.querySelector('.score-display');

    document.addEventListener('DOMContentLoaded', () => {
    startTimer();
    });

    function startTimer() {
    timerText.textContent = timeLeft;
    updateTimerProgress();
    timerInterval = setInterval(() => {
        timeLeft--;
        timerText.textContent = timeLeft;
        updateTimerProgress();
        if (timeLeft <= 10) {
        timerContainer.style.animation = 'pulse 0.5s infinite alternate';
        }
        if (timeLeft <= 0) {
        handleAnswerEnd(); // Timeout case
        }
    }, 1000);
    }

    function updateTimerProgress() {
    const progress = (timeLeft / 30) * 283;
    timerProgress.style.strokeDashoffset = 283 - progress;
    const ratio = timeLeft / 30;
    const red = Math.floor(255 * (1 - ratio));
    const green = Math.floor(255 * ratio);
    timerProgress.style.stroke = `rgb(${red},${green},0)`;
    }

    function selectOption(elem) {
    handleAnswerEnd(elem.textContent.trim());
    }

    function handleAnswerEnd(selected = '') {
    clearInterval(timerInterval);
    timerContainer.style.animation = 'none';

    // Highlight all options neon-style
    document.querySelectorAll('.option').forEach(opt => {
        if (opt.dataset.correct === "true") {
        opt.classList.add('correct');
        } else {
        opt.classList.add('wrong');
        }
    });

    // Immediate score update if correct
    if (selected) {
        const correctText = document.querySelector('.option[data-correct="true"]').textContent.trim();
        if (selected === correctText) {
        let current = parseInt(scoreDisplay.textContent.replace(/\D/g, ''));
        let updated = current + 1;
        scoreDisplay.textContent = 'Score: ' + updated;
        // Score-Animation hier behalten
        scoreDisplay.classList.add('score-update');
        }
    }

    // Prepare form submission
    document.getElementById('selected-answer').value = selected;
    setTimeout(() => document.getElementById('next-form').submit(), 1000);
    }

    function confirmCancel() {
    if (confirm("Möchtest du das Quiz wirklich abbrechen?\nDein aktueller Fortschritt geht verloren.")) {
        fetch("{{ url_for('cancel_quiz') }}", { method: 'POST' })
        .then(() => window.location.href = "{{ url_for('homepage') }}")
        .catch(() => window.location.href = "{{ url_for('homepage') }}");
    }
    }