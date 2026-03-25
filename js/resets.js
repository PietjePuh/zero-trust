function handleFeedback(response) {
    const feedbackControls = document.getElementById('feedback-controls');
    if (feedbackControls) {
        feedbackControls.classList.add('hidden');
    }
    const thanksMessage = document.getElementById('feedback-thanks');
    if (thanksMessage) {
        thanksMessage.classList.remove('hidden');
        thanksMessage.focus();
    }
    // In a real application, you would send this response to a server
    console.log('User feedback received:', response);
}

document.addEventListener('DOMContentLoaded', () => {
    const yesBtn = document.getElementById('feedback-yes');
    const noBtn = document.getElementById('feedback-no');

    if (yesBtn) {
        yesBtn.addEventListener('click', () => handleFeedback('yes'));
    }
    if (noBtn) {
        noBtn.addEventListener('click', () => handleFeedback('no'));
    }
});
