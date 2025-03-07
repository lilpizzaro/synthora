// DOM Elements
const menuButton = document.querySelector('.menu-button');
const slideMenu = document.querySelector('.slide-menu');
const menuOverlay = document.querySelector('.slide-menu-overlay');
const accountModal = document.querySelector('.account-modal');
const memoriesModal = document.querySelector('.memories-modal');
const menuAccountButton = document.querySelector('.menu-account');
const menuUsername = document.querySelector('#menuUsername');
const menuAvatarImage = document.querySelector('#menuAvatarImage');
const avatarPreview = document.querySelector('#avatarPreview');
const avatarUpload = document.querySelector('#avatarUpload');
const themeToggle = document.querySelector('#themeToggle');

// Theme handling
function setTheme(isDark) {
    document.body.classList.toggle('dark-mode', isDark);
    localStorage.setItem('darkMode', isDark);
    
    // Update all themed elements
    const themedElements = document.querySelectorAll('[data-theme]');
    themedElements.forEach(element => {
        element.classList.toggle('dark', isDark);
    });
}

// Initialize theme
const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
const savedTheme = localStorage.getItem('darkMode');
const isDark = savedTheme !== null ? savedTheme === 'true' : prefersDark;
setTheme(isDark);

// Theme toggle event listener
themeToggle?.addEventListener('change', (e) => {
    setTheme(e.target.checked);
});

// Menu handling
function toggleMenu() {
    const menu = document.getElementById('menu');
    menu.classList.toggle('open');
}

menuButton?.addEventListener('click', toggleMenu);
menuOverlay?.addEventListener('click', toggleMenu);

// Account modal handling
function showAccountModal() {
    accountModal.classList.add('show');
    slideMenu.classList.remove('active');
    menuOverlay.classList.remove('active');
}

function hideAccountModal() {
    accountModal.classList.remove('show');
}

menuAccountButton?.addEventListener('click', showAccountModal);

document.querySelectorAll('.close-button').forEach(button => {
    button.addEventListener('click', (e) => {
        const modal = e.target.closest('.account-modal, .memories-modal');
        if (modal) {
            modal.classList.remove('show');
        }
    });
});

// Avatar handling
avatarUpload?.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
        const reader = new FileReader();
        reader.onload = (e) => {
            const imageUrl = e.target.result;
            avatarPreview.src = imageUrl;
            menuAvatarImage.src = imageUrl;
            // Save avatar to localStorage or server
            localStorage.setItem('userAvatar', imageUrl);
        };
        reader.readAsDataURL(file);
    }
});

// Initialize avatar from storage
const savedAvatar = localStorage.getItem('userAvatar');
if (savedAvatar) {
    avatarPreview.src = savedAvatar;
    menuAvatarImage.src = savedAvatar;
}

// Update menu username
function updateMenuUsername(username) {
    if (menuUsername && username) {
        menuUsername.textContent = username;
    }
}

// Initialize username from storage or session
const savedUsername = localStorage.getItem('username') || sessionStorage.getItem('username');
if (savedUsername) {
    updateMenuUsername(savedUsername);
}

// Close modals when clicking outside
window.addEventListener('click', (e) => {
    if (e.target === accountModal) {
        hideAccountModal();
    } else if (e.target === memoriesModal) {
        memoriesModal.classList.remove('show');
    }
});

// Prevent modals from showing on startup
document.addEventListener('DOMContentLoaded', () => {
    accountModal.style.display = 'none';
    memoriesModal.style.display = 'none';
    
    // After a brief delay, reset the display property to allow the modals to be shown later
    setTimeout(() => {
        accountModal.style.display = '';
        memoriesModal.style.display = '';
    }, 100);
    handleMobileKeyboard();
    initTouchScrolling();
});

// Handle escape key to close modals
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        hideAccountModal();
        memoriesModal.classList.remove('show');
        slideMenu.classList.remove('active');
        menuOverlay.classList.remove('active');
    }
});

// Handle mobile keyboard visibility
function handleMobileKeyboard() {
    const header = document.querySelector('.chat-header');
    const visualViewport = window.visualViewport;

    if (!visualViewport || !header) return;

    let lastHeight = visualViewport.height;

    visualViewport.addEventListener('resize', () => {
        // If the height decreased significantly, keyboard is likely shown
        const heightDifference = Math.abs(lastHeight - visualViewport.height);
        const isKeyboardVisible = visualViewport.height < lastHeight && heightDifference > 150;
        
        header.classList.toggle('keyboard-visible', isKeyboardVisible);
        lastHeight = visualViewport.height;
    });
}

// Add touch scrolling handlers
function initTouchScrolling() {
    const accountBody = document.querySelector('.account-body');
    const authContainer = document.querySelector('.auth-container');
    
    // Enable smooth scrolling on iOS
    if (accountBody) {
        accountBody.style.WebkitOverflowScrolling = 'touch';
        
        // Prevent body scroll when modal is open
        accountBody.addEventListener('touchmove', (e) => {
            if (accountBody.scrollHeight > accountBody.clientHeight) {
                e.stopPropagation();
            }
        }, { passive: true });
    }
    
    if (authContainer) {
        authContainer.style.WebkitOverflowScrolling = 'touch';
        
        // Prevent body scroll when auth container is scrollable
        authContainer.addEventListener('touchmove', (e) => {
            if (authContainer.scrollHeight > authContainer.clientHeight) {
                e.stopPropagation();
            }
        }, { passive: true });
    }
} 