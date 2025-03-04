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
    slideMenu.classList.toggle('active');
    menuOverlay.classList.toggle('active');
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