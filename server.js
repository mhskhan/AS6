const express = require('express');
const app = express();
const cors = require('cors');
const dotenv = require('dotenv');
const passport = require('passport');
const passportJWT = require('passport-jwt');
const jwt = require('jsonwebtoken');
// Ensure this filename matches the actual file:
const userService = require('./user-service.js');

dotenv.config();
const HTTP_PORT = process.env.PORT || 8080;

// JWT Strategy configuration
const ExtractJwt = passportJWT.ExtractJwt;
const JwtStrategy = passportJWT.Strategy;

const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderWithScheme('jwt'), // Authorization: "JWT <token>"
  secretOrKey: process.env.JWT_SECRET,
};

const strategy = new JwtStrategy(jwtOptions, (jwt_payload, next) => {
  next(null, { _id: jwt_payload._id, userName: jwt_payload.userName });
});

passport.use(strategy);
app.use(passport.initialize());

app.use(express.json());
app.use(cors());

// ----- Public Routes -----
app.post('/api/user/register', (req, res) => {
  userService
    .registerUser(req.body)
    .then((msg) => res.json({ message: msg }))
    .catch((msg) => res.status(422).json({ message: msg }));
});

app.post('/api/user/login', (req, res) => {
  userService
    .checkUser(req.body)
    .then((user) => {
      const payload = { _id: user._id, userName: user.userName };
      const token = jwt.sign(payload, process.env.JWT_SECRET);
      res.json({ message: 'login successful', token });
    })
    .catch((msg) => {
      // Use 401 to indicate auth failure
      res.status(401).json({ message: msg });
    });
});

// ----- Protected Routes -----
const auth = passport.authenticate('jwt', { session: false });

app.get('/api/user/favourites', auth, (req, res) => {
  userService
    .getFavourites(req.user._id)
    .then((data) => res.json(data))
    .catch((msg) => res.status(422).json({ error: msg }));
});

app.put('/api/user/favourites/:id', auth, (req, res) => {
  userService
    .addFavourite(req.user._id, req.params.id)
    .then((data) => res.json(data))
    .catch((msg) => res.status(422).json({ error: msg }));
});

app.delete('/api/user/favourites/:id', auth, (req, res) => {
  userService
    .removeFavourite(req.user._id, req.params.id)
    .then((data) => res.json(data))
    .catch((msg) => res.status(422).json({ error: msg }));
});

app.get('/api/user/history', auth, (req, res) => {
  userService
    .getHistory(req.user._id)
    .then((data) => res.json(data))
    .catch((msg) => res.status(422).json({ error: msg }));
});

app.put('/api/user/history/:id', auth, (req, res) => {
  userService
    .addHistory(req.user._id, req.params.id)
    .then((data) => res.json(data))
    .catch((msg) => res.status(422).json({ error: msg }));
});

app.delete('/api/user/history/:id', auth, (req, res) => {
  userService
    .removeHistory(req.user._id, req.params.id)
    .then((data) => res.json(data))
    .catch((msg) => res.status(422).json({ error: msg }));
});

// ----- Startup -----
userService
  .connect()
  .then(() => {
    app.listen(HTTP_PORT, () => {
      console.log('API listening on: ' + HTTP_PORT);
    });
  })
  .catch((err) => {
    console.log('unable to start the server: ' + err);
    process.exit();
  });
