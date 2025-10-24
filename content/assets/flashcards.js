(function() {
  'use strict';

  let currentCardIndex = 0;
  const cards = document.querySelectorAll('.flashcard');
  const prevButton = document.getElementById('prev-card');
  const nextButton = document.getElementById('next-card');
  const counter = document.getElementById('card-counter');
  const totalCards = cards.length;

  function updateCard() {
    // Hide all cards
    cards.forEach((card, index) => {
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
  cards.forEach(card => {
    card.addEventListener('click', function() {
      this.classList.toggle('flipped');
    });
  });

  // Add keyboard navigation
  document.addEventListener('keydown', function(e) {
    if (e.key === 'ArrowLeft') {
      prevCard();
    } else if (e.key === 'ArrowRight') {
      nextCard();
    } else if (e.key === ' ' || e.key === 'Enter') {
      e.preventDefault();
      const activeCard = cards[currentCardIndex];
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
