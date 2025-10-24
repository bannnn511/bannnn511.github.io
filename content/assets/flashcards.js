(function () {
  'use strict';

  let currentCardIndex = 0;
  const cards = Array.from(document.querySelectorAll('.flashcard'));
  const prevButton = document.getElementById('prev-card');
  const nextButton = document.getElementById('next-card');
  const counter = document.getElementById('card-counter');
  const totalCards = cards.length;

  // Shuffle the cards array using Fisher-Yates algorithm for better randomness
  function shuffleArray(array) {
    const shuffled = [...array];
    for (let i = shuffled.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }
    return shuffled;
  }

  // Shuffle cards on page load
  const shuffledCards = shuffleArray(cards);
  const wrapper = document.querySelector('.flashcard-wrapper');

  // Re-append cards in shuffled order
  shuffledCards.forEach(card => {
    wrapper.appendChild(card);
  });

  function updateCard() {
    // Hide all cards
    shuffledCards.forEach((card, index) => {
      if (index === currentCardIndex) {
        card.classList.add('active');
      } else {
        card.classList.remove('active');
      }
      // Reset flip state when switching cards
      card.classList.remove('flipped');
    });

    // Update counter
    counter.textContent = `${currentCardIndex + 1} / ${totalCards}`;

    // Update button states
    prevButton.disabled = currentCardIndex === 0;
    nextButton.disabled = currentCardIndex === totalCards - 1;
  }

  function nextCard() {
    if (currentCardIndex < totalCards - 1) {
      currentCardIndex++;
      updateCard();
    }
  }

  function prevCard() {
    if (currentCardIndex > 0) {
      currentCardIndex--;
      updateCard();
    }
  }

  // Add click event to flip cards
  shuffledCards.forEach(card => {
    card.addEventListener('click', function () {
      this.classList.toggle('flipped');
    });
  });

  // Add keyboard navigation
  document.addEventListener('keydown', function (e) {
    if (e.key === 'ArrowLeft') {
      prevCard();
    } else if (e.key === 'ArrowRight') {
      nextCard();
    } else if (e.key === ' ' || e.key === 'Enter') {
      e.preventDefault();
      const activeCard = shuffledCards[currentCardIndex];
      if (activeCard) {
        activeCard.classList.toggle('flipped');
      }
    }
  });

  // Button event listeners
  prevButton.addEventListener('click', prevCard);
  nextButton.addEventListener('click', nextCard);

  // Initialize
  updateCard();
})();
