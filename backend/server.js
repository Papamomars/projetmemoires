const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');

// Initialize the app
const app = express();
app.use(bodyParser.json());
app.use(cors());

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/bro', { useNewUrlParser: true, useUnifiedTopology: true });

// Define User Schema
const UserSchema = new mongoose.Schema({
  prenom: String,
  nom: String,
  niveau: String,
  email: { type: String, unique: true },
  password: String
});

const User = mongoose.model('User', UserSchema);

// Routes
const bcrypt = require('bcrypt');

const jwt = require('jsonwebtoken');
app.post('/api/register', async (req, res) => {
    const { prenom, nom, niveau, email, password } = req.body;
  
    // Vérifier si l'utilisateur existe déjà dans la base de données
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).send('L\'utilisateur existe déjà');
    }
  
    // Hasher le mot de passe avant de le stocker dans la base de données
    const hashedPassword = await bcrypt.hash(password, 10);
  
    // Créer un nouvel utilisateur avec les données fournies
    const newUser = new User({ prenom, nom, niveau, email, password: hashedPassword });
  
    try {
      // Enregistrer le nouvel utilisateur dans la base de données
      await newUser.save();
      res.status(201).send('Inscription réussie');
    } catch (error) {
      res.status(500).send('Une erreur est survenue lors de l\'enregistrement de l\'utilisateur');
    }
  });

const secretKey = 'your_secret_key'; // Change this to a strong secret and store it in an environment variable

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
  
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).send('Invalid email or password');
    }
  
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).send('Invalid email or password');
    }
  
    const token = jwt.sign({ id: user._id, niveau: user.niveau }, secretKey, { expiresIn: '1h' });
    res.send({ token, niveau: user.niveau, prenom: user.prenom, nom: user.nom }); // Inclure le prénom et le nom dans la réponse
  });    

const authMiddleware = (req, res, next) => {
  const token = req.header('Authorization').replace('Bearer ', '');
  try {
    const decoded = jwt.verify(token, secretKey);
    req.user = decoded;
    next();
  } catch (e) {
    res.status(401).send('Please authenticate');
  }
};

// Use the middleware for protected routes
app.get('/api/protected', authMiddleware, (req, res) => {
  res.send('This is a protected route');
});
mongoose.connection.on('connected', () => {
    console.log('Connected to MongoDB');
  });  

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});