// Firebase configuration
const firebaseConfig = {
    apiKey: "AIzaSyD8eJncAhmEfUz-pYbYBljTCl70QclJ-Fo",
    authDomain: "safe-code-e4295.firebaseapp.com",
    projectId: "safe-code-e4295",
    storageBucket: "safe-code-e4295.firebasestorage.app",
    messagingSenderId: "167858818384",
    appId: "1:167858818384:web:bf641149e8d41ae548b055",
    measurementId: "G-JXED6SXPPL"
};

// Initialize Firebase
firebase.initializeApp(firebaseConfig);

// Initialize Firebase Authentication
const auth = firebase.auth();
const provider = new firebase.auth.GoogleAuthProvider();

// Configure Google provider
provider.setCustomParameters({
    prompt: 'select_account'
});

// Initialize Analytics (optional)
let analytics;
try {
    analytics = firebase.analytics();
} catch (error) {
    console.log('Analytics not available:', error);
}

// Make auth and provider globally available
window.auth = auth;
window.provider = provider;
window.analytics = analytics;
