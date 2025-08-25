// Firebase configuration
const firebaseConfig = {
    apiKey: "AIzaSyD8eJncAhmEfUz-pYbYBljTCl70QclJ-Fo",
    authDomain: "safe-code-e4295.firebaseapp.com",
    projectId: "safe-code-e4295",
    storageBucket: "safe-code-e4295.appspot.com",
    messagingSenderId: "167858818384",
    appId: "1:167858818384:web:YOUR_APP_ID"
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
