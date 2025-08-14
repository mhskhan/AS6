require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const passportJWT = require("passport-jwt");
const UserService = require("./user-service"); // from starter
const app = express();

app.use(cors());
app.use(express.json());
app.use(passport.initialize());

const ExtractJwt = passportJWT.ExtractJwt;
const JwtStrategy = passportJWT.Strategy;

// --- Passport JWT Strategy ---
passport.use(
  new JwtStrategy(
    {
      jwtFromRequest: ExtractJwt.fromAuthHeaderWithScheme("JWT"),
      secretOrKey: process.env.JWT_SECRET,
    },
    async (jwt_payload, done) => {
      try {
        // Our payload contains {_id, userName}; find by id or username
        const user = await UserService.getUserById(jwt_payload._id);
        if (user) return done(null, user);
        return done(null, false);
      } catch (err) {
        return done(err);
      }
    }
  )
);

const auth = passport.authenticate("jwt", { session: false });

// ---- Routes ----
app.get("/", (req, res) => res.json({ status: "User API up" }));

// Register
app.post("/api/user/register", async (req, res) => {
  try {
    const { userName, password, password2 } = req.body;
    if (!userName || !password || !password2)
      return res.status(400).json({ message: "Missing fields" });
    if (password !== password2)
      return res.status(400).json({ message: "Passwords do not match" });

    await UserService.registerUser(userName, password);
    return res.json({ message: "User registered" });
  } catch (err) {
    return res.status(400).json({ message: err.message || "Register failed" });
  }
});

// Login (must sign and return token)
app.post("/api/user/login", async (req, res) => {
  try {
    const { userName, password } = req.body;
    const user = await UserService.checkUser(userName, password); // returns user object
    // payload MUST be only {_id, userName}
    const payload = { _id: user._id, userName: user.userName };
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "7d" });
    return res.json({ message: "login successful", token });
  } catch (err) {
    return res.status(400).json({ message: err.message || "Login failed" });
  }
});

// Protected favourites
app.get("/api/user/favourites", auth, async (req, res) => {
  const data = await UserService.getFavourites(req.user._id);
  res.json(data);
});
app.put("/api/user/favourites/:id", auth, async (req, res) => {
  const data = await UserService.addFavourite(req.user._id, req.params.id);
  res.json(data);
});
app.delete("/api/user/favourites/:id", auth, async (req, res) => {
  const data = await UserService.removeFavourite(req.user._id, req.params.id);
  res.json(data);
});

// Protected history
app.get("/api/user/history", auth, async (req, res) => {
  const data = await UserService.getHistory(req.user._id);
  res.json(data);
});
app.put("/api/user/history/:id", auth, async (req, res) => {
  const data = await UserService.addHistory(req.user._id, req.params.id);
  res.json(data);
});
app.delete("/api/user/history/:id", auth, async (req, res) => {
  const data = await UserService.removeHistory(req.user._id, req.params.id);
  res.json(data);
});

// Startup
const PORT = process.env.PORT || 8080;
UserService.connect(process.env.MONGO_URL).then(() => {
  app.listen(PORT, () => console.log(`User API listening on ${PORT}`));
});
