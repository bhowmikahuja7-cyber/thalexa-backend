// index.js

// --- Imports ---
require('dotenv').config(); // Loads environment variables from .env file
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { Pool } = require('pg'); // PostgreSQL client
const path = require('path');

// --- App & Port Setup ---
const app = express();
const PORT = process.env.PORT || 3000;

// --- Database Connection ---
// Creates a pool of connections to your PostgreSQL database
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false // Necessary for some cloud providers
    },
    family: 4, // Force IPv4 to bypass potential network/DNS issues
});

// --- Middleware ---
// Setup for managing user login sessions
app.use(session({
    secret: 'a_very_secret_key_for_thalexa', // Replace with a long random string in production
    resave: false,
    saveUninitialized: true,
}));

// Initialize Passport for authentication
app.use(passport.initialize());
app.use(passport.session());

// --- Passport Strategy (Google OAuth 2.0) ---
// This is the core of the Google Sign-In logic
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback" // Must match the one in your Google Cloud Console
  },
  async (accessToken, refreshToken, profile, done) => {
    // This function is called after Google successfully authenticates the user
    const { id, displayName, emails, photos } = profile;
    const email = emails[0].value;
    const profile_picture_url = photos[0].value;

    try {
        // Check if the user already exists in our database
        const result = await pool.query('SELECT * FROM Users WHERE google_id = $1', [id]);
        
        if (result.rows.length > 0) {
            // User exists, log them in
            console.log('User already exists:', result.rows[0]);
            return done(null, result.rows[0]);
        } else {
            // User is new, create a new entry in our database
            const newUserResult = await pool.query(
                'INSERT INTO Users (google_id, email, name, profile_picture_url) VALUES ($1, $2, $3, $4) RETURNING *',
                [id, email, displayName, profile_picture_url]
            );
            console.log('New user created:', newUserResult.rows[0]);
            return done(null, newUserResult.rows[0]);
        }
    } catch (err) {
        console.error('Database error:', err);
        return done(err, null);
    }
  }
));

// --- Session Management ---
// Saves user information (just the user_id) into the session cookie
passport.serializeUser((user, done) => {
    done(null, user.user_id);
});

// Retrieves user information from the database using the id from the session cookie
passport.deserializeUser(async (id, done) => {
    try {
        const result = await pool.query('SELECT * FROM Users WHERE user_id = $1', [id]);
        done(null, result.rows[0]);
    } catch (err) {
        done(err, null);
    }
});


// --- Routes ---
// The route for the homepage, serves the login page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

// 1. The route the user clicks to initiate Google Sign-In
app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] }) // Asks Google for profile and email
);

// 2. The callback route Google redirects to after authentication
app.get('/auth/google/callback', 
    passport.authenticate('google', { failureRedirect: '/' }), // If login fails, redirect to home
    (req, res) => {
        // Successful authentication, redirect to the dashboard.
        res.redirect('/dashboard');
    }
);

// 3. The protected dashboard route, only accessible after login
app.get('/dashboard', (req, res) => {
    if (req.isAuthenticated()) {
        // User is logged in, send them their name
        res.send(`<h1>Welcome to your dashboard, ${req.user.name}!</h1> <a href="/logout">Logout</a>`);
    } else {
        // User is not logged in, redirect to login page
        res.redirect('/');
    }
});

// 4. Logout route
app.get('/logout', (req, res, next) => {
    req.logout(function(err) {
      if (err) { return next(err); }
      res.redirect('/');
    });
});


// --- Start Server ---
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});