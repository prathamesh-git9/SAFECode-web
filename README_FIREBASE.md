# 🚀 SAFECode-Web Firebase Deployment Guide

This guide will help you deploy your SAFECode-Web application to Firebase Hosting with Cloud Functions.

## 📋 Prerequisites

1. **Node.js** (v16 or higher)
2. **Firebase CLI** 
3. **Google Account** with Firebase access
4. **OpenAI API Key**

## 🔧 Setup Steps

### 1. Install Firebase CLI
```bash
npm install -g firebase-tools
```

### 2. Login to Firebase
```bash
firebase login
```

### 3. Create Firebase Project
1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Click "Add project"
3. Name it `safecode-web` (or your preferred name)
4. Follow the setup wizard

### 4. Initialize Firebase in Your Project
```bash
firebase init
```

Select the following options:
- ✅ **Hosting**: Configure files for Firebase Hosting
- ✅ **Functions**: Configure a Cloud Functions directory and its files
- Choose your project: `safecode-web`
- Public directory: `public`
- Configure as single-page app: `No`
- Set up automatic builds: `No`
- Functions language: `Python`
- ESLint: `No`
- Install dependencies: `Yes`

### 5. Set Environment Variables
```bash
firebase functions:config:set openai.api_key="your-openai-api-key-here"
```

### 6. Deploy to Firebase
```bash
firebase deploy
```

## 🌐 Access Your App

After deployment, your app will be available at:
- **Main App**: `https://safecode-web.web.app`
- **Functions**: `https://us-central1-safecode-web.cloudfunctions.net/app`

## 📁 Project Structure

```
safecode-web/
├── public/                 # Static files (HTML, CSS, JS)
│   ├── index.html         # Main app page
│   ├── styles.css         # Styling
│   └── script.js          # Frontend logic
├── functions/             # Cloud Functions (Backend)
│   ├── main.py           # API endpoints
│   └── requirements.txt  # Python dependencies
├── firebase.json         # Firebase configuration
├── .firebaserc          # Project settings
└── package.json         # Node.js dependencies
```

## 🔄 Development Workflow

### Local Development
```bash
# Start local development server
firebase serve

# Test functions locally
firebase functions:shell
```

### Deploy Updates
```bash
# Deploy everything
firebase deploy

# Deploy only hosting
firebase deploy --only hosting

# Deploy only functions
firebase deploy --only functions
```

## 💰 Costs

**Firebase Hosting**: 
- Free tier: 10GB storage, 360MB/day transfer
- Perfect for most projects

**Cloud Functions**:
- Free tier: 2 million invocations/month
- $0.40 per million after that

## 🛠️ Troubleshooting

### Common Issues

1. **Functions not deploying**:
   ```bash
   cd functions
   pip install -r requirements.txt
   firebase deploy --only functions
   ```

2. **CORS errors**:
   - Check that CORS headers are set in `functions/main.py`

3. **API key not working**:
   ```bash
   firebase functions:config:get
   ```

### Logs
```bash
# View function logs
firebase functions:log

# View hosting logs
firebase hosting:log
```

## 🔒 Security Notes

1. **API Keys**: Never commit API keys to Git
2. **Environment Variables**: Use Firebase Functions config
3. **CORS**: Configure properly for your domain

## 📈 Monitoring

- **Analytics**: Firebase Analytics (free)
- **Performance**: Firebase Performance Monitoring
- **Crash Reporting**: Firebase Crashlytics

## 🎉 Success!

Your SAFECode-Web app is now live on Firebase! 

**Next Steps**:
1. Test all functionality
2. Set up custom domain (optional)
3. Configure monitoring
4. Share your app URL

---

**Need Help?** Check the [Firebase Documentation](https://firebase.google.com/docs) or create an issue in your repository.
