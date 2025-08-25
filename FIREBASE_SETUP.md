# Firebase Setup for SAFECode Authentication

## 🔥 **Step 1: Create Firebase Project**

1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Click **"Create a project"**
3. Enter project name: `safecode-auth` (or your preferred name)
4. Enable Google Analytics (optional)
5. Click **"Create project"**

## 🔥 **Step 2: Enable Authentication**

1. In Firebase Console, go to **"Authentication"**
2. Click **"Get started"**
3. Go to **"Sign-in method"** tab
4. Click **"Google"** provider
5. Enable Google authentication
6. Add your authorized domain (your Railway domain)
7. Click **"Save"**

## 🔥 **Step 3: Get Firebase Config**

1. In Firebase Console, go to **"Project settings"** (gear icon)
2. Scroll down to **"Your apps"** section
3. Click **"Add app"** → **"Web"**
4. Register app with name: `SAFECode Web`
5. Copy the Firebase config object

## 🔥 **Step 4: Update Firebase Config**

Replace the placeholder config in `public/firebase-config.js`:

```javascript
const firebaseConfig = {
    apiKey: "YOUR_ACTUAL_API_KEY",
    authDomain: "YOUR_PROJECT_ID.firebaseapp.com",
    projectId: "YOUR_PROJECT_ID",
    storageBucket: "YOUR_PROJECT_ID.appspot.com",
    messagingSenderId: "YOUR_SENDER_ID",
    appId: "YOUR_APP_ID"
};
```

## 🔥 **Step 5: Add Authorized Domains**

1. In Firebase Console → Authentication → Settings
2. Add your Railway domain to **"Authorized domains"**
3. Example: `your-app-name.railway.app`

## 🔥 **Step 6: Deploy**

1. Commit your changes
2. Push to GitHub
3. Railway will auto-deploy with Firebase authentication

## ✅ **Features Added:**

- ✅ Google Sign-in button in navigation
- ✅ User profile display when signed in
- ✅ Sign-out functionality
- ✅ Authentication state management
- ✅ Welcome notifications
- ✅ Secure Firebase integration

## 🚀 **Next Steps:**

1. Set up Firebase project
2. Update `firebase-config.js` with your config
3. Deploy to Railway
4. Test Google authentication

Your SAFECode app will now have professional Google authentication! 🎉
