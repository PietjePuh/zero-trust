document.addEventListener('DOMContentLoaded', () => {
    const options = document.querySelectorAll('.option');

    function selectOption(optionEl) {
        const parent = optionEl.parentElement;
        // Deselect others in the same card
        parent.querySelectorAll('.option').forEach(o => {
            o.classList.remove('selected');
            o.setAttribute('aria-checked', 'false');
            o.setAttribute('tabindex', '-1');
        });
        // Select this one
        optionEl.classList.add('selected');
        optionEl.setAttribute('aria-checked', 'true');
        optionEl.setAttribute('tabindex', '0');
    }

    options.forEach(option => {
        option.addEventListener('click', function() {
            selectOption(this);
        });

        option.addEventListener('keydown', function(e) {
            if (e.key === ' ' || e.key === 'Enter') {
                e.preventDefault();
                selectOption(this);
            }

            // Arrow key navigation within the radiogroup
            const parent = this.parentElement;
            const siblings = Array.from(parent.querySelectorAll('.option'));
            const currentIndex = siblings.indexOf(this);

            let nextIndex = null;
            if (e.key === 'ArrowDown' || e.key === 'ArrowRight') {
                nextIndex = (currentIndex + 1) % siblings.length;
            } else if (e.key === 'ArrowUp' || e.key === 'ArrowLeft') {
                nextIndex = (currentIndex - 1 + siblings.length) % siblings.length;
            }

            if (nextIndex !== null) {
                e.preventDefault();
                const nextOption = siblings[nextIndex];
                selectOption(nextOption);
                nextOption.focus();
            }
        });
    });

    const calculateBtn = document.getElementById('calculate-btn');
    if (calculateBtn) {
        calculateBtn.addEventListener('click', () => {
            const selected = document.querySelectorAll('.option.selected');
            if (selected.length < 3) {
                alert('Please answer all questions.');
                return;
            }

            let totalScore = 0;
            selected.forEach(s => totalScore += parseInt(s.dataset.score));
            const average = totalScore / 3;

            document.getElementById('quiz').style.display = 'none';
            document.getElementById('result-container').style.display = 'block';

            const badge = document.getElementById('maturity-badge');
            const desc = document.getElementById('maturity-desc');

            if (average <= 1.5) {
                badge.textContent = 'Traditional';
                badge.className = 'maturity-badge badge-hard';
                desc.textContent = 'You are relying on perimeter defenses. You are highly vulnerable to lateral movement.';
            } else if (average <= 2.5) {
                badge.textContent = 'Initial';
                badge.className = 'maturity-badge badge-medium';
                desc.textContent = 'You have started the journey. Basic MFA and segmentation are in place, but lack automation.';
            } else if (average <= 3.5) {
                badge.textContent = 'Advanced';
                badge.className = 'maturity-badge badge-easy';
                desc.textContent = 'Strong Zero Trust foundations. Most access is context-based and logged.';
            } else {
                badge.textContent = 'Optimal';
                badge.style.backgroundColor = 'var(--success-color)';
                badge.style.color = 'white';
                desc.textContent = 'You have achieved a fully dynamic, identity-centric environment with continuous validation.';
            }

            document.getElementById('result-container').focus();
        });
    }
});
