// Import the functions you need from the SDKs you need
import { initializeApp } from "firebase/app";
import { getAuth, GoogleAuthProvider } from "firebase/auth";
import { getAnalytics } from "firebase/analytics";

// Your web app's Firebase configuration
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
const app = initializeApp(firebaseConfig);

// Initialize Firebase Authentication
const auth = getAuth(app);
const provider = new GoogleAuthProvider();

// Configure Google provider
provider.setCustomParameters({
    prompt: 'select_account'
});

// Initialize Analytics (optional)
let analytics;
try {
    analytics = getAnalytics(app);
} catch (error) {
    console.log('Analytics not available:', error);
}

// Export for use in other files
export { auth, provider, analytics };
