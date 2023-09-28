const express = require('express');
const app = express();
const port = 4000;

const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');
const session = require('express-session');
const crypto = require('crypto');
const serviceAccount = require('./Key.json');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');


initializeApp({
  credential: cert(serviceAccount),
});

const db = getFirestore();


const secretKey = crypto.randomBytes(32).toString('hex');


app.use(
  session({
    secret: secretKey,
    resave: false,
    saveUninitialized: true,
  })
);


app.use(bodyParser.urlencoded({ extended: true }));

app.set('view engine', 'ejs');
app.use(express.static('public'));

app.get('/', (req, res) => {
  
  const user = req.session.user;
  if (user) {
    res.render('pages/home', { user });
  } else {
    res.redirect('/login');
  }
});

app.get('/signup', (req, res) => {
  res.render('pages/signup');
});

app.post('/signupsubmit', async (req, res) => {
    const FullName = req.body.FullName;
    const Email = req.body.Email;
    const Password = req.body.Password;
  
    try {
      
      const emailExists = await checkEmailExists(Email);
  
      if (emailExists) {
        
        return res.send('Signup Failed: Email address already in use.');
      }
  
      
      const hashedPassword = await hashPassword(Password);
  
      
      const user = {
        FullName: FullName,
        Email: Email,
        Password: hashedPassword,
        
      };
  
    
      await addUserToDatabase(user);
  
      
      req.session.user = user;
      res.redirect('/');
    } catch (error) {
      console.error('Error during signup:', error);
      res.send('An error occurred during signup.');
    }
  });
  
  // Function to check if an email exists in the database
  async function checkEmailExists(Email) {
    const snapshot = await db.collection('userDetails').where('Email', '==', Email).get();
    return !snapshot.empty;
  }
  
  // Function to hash a password using bcrypt
  async function hashPassword(password) {
    const saltRounds = 10; 
    return bcrypt.hash(password, saltRounds);
  }
  
  // Function to add a user to the database
  async function addUserToDatabase(user) {
    await db.collection('userDetails').add(user);
  }
  
  

app.get('/login', (req, res) => {

  const user = req.session.user;
  if (user) {
    res.redirect('/');
  } else {
    res.render('pages/login');
  }
});

app.post('/loginsubmit', async (req, res) => {
    const Email = req.body.Email;
    const Password = req.body.Password;
  
    try {

      const userSnapshot = await db.collection('userDetails').where('Email', '==', Email).get();
  
      if (userSnapshot.empty) {
        
        return res.send('Login Failed: User not found.');
      }
  
      
      let userData;
      userSnapshot.forEach((doc) => {
        userData = doc.data();
      });
  
      const hashedPassword = userData.Password;
  
      
      const passwordMatch = await comparePasswords(Password, hashedPassword);
  
      if (passwordMatch) {
        
        req.session.user = userData;
        return res.redirect('/');
      } else {
        
        return res.send('Login Failed: Incorrect password.');
      }
    } catch (error) {
      console.error('Error during login:', error);
      res.send('An error occurred during login.');
    }
  });
  
  
  async function comparePasswords(enteredPassword, hashedPassword) {
    return bcrypt.compare(enteredPassword, hashedPassword);
  }
  
  

app.get('/profile', (req, res) => {
  const user = req.session.user;

  if (!user) {
    return res.redirect('/login');
  }

  res.render('pages/profile', { user });
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error(err);
    }
    res.redirect('/login');
  });
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
