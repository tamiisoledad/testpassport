const express = require("express");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const TwitterStrategy = require('passport-twitter').Strategy;
const jwt = require('jsonwebtoken');

const PRIVATE_KEY = 'myprivatekey';

const Usuarios = require("./models/usuarios");

const bcrypt = require("bcrypt");
const routes = require("./routes");
const mongoose = require("mongoose");
const { engine } = require("express-handlebars");

const redis = require("redis");
const client = redis.createClient({
  legacyMode: true,
});
client
  .connect()
  .then(() => console.log("Connected to REDIS"))
  .catch((e) => {
    console.error(e);
    throw "can not connect to Redis!";
  });
const RedisStore = require("connect-redis")(session);

mongoose
  .connect("mongodb://127.0.0.1:27017/ecommerce")
  .then(() => console.log("Connected to Mongo"))
  .catch((e) => {
    console.error(e);
    throw "can not connect to the mongo!";
  });

function isValidPassword(user, password) {
  return bcrypt.compareSync(password, user.password);
}

function createHash(password) {
  return bcrypt.hashSync(password, bcrypt.genSaltSync(10), null);
}

function generateToken(user) {
  const token = jwt.sign({ data: user }, PRIVATE_KEY, { expiresIn: '24h' });
  return token;
}

const usuarios = [];

passport.use(new TwitterStrategy({
  consumerKey: 'YEEd9FbtQFqrNrCjZQGBS4Lwn',
  consumerSecret: 'lnATOmsldStuuiKkpUi8kmFu4XiKf4MVCnwagp7lZ6TurPmOXs',
  callbackURL: 'http://localhost:8000/auth/twitter/callback'
},
  function(token, tokenSecret, profile, done) {
    Usuarios.findOrCreate({
      twitterId: profile.id,
      username: profile.username
    }, (err, user) => {
      if (err) return done(err);
      return done(null, user);
    })
  }
))

passport.use(
  "login",
  new LocalStrategy((username, password, done) => {
    Usuarios.findOne({ username }, (err, user) => {
      if (err) return done(err);

      if (!user) {
        console.log("User Not Found with username " + username);
        return done(null, false);
      }

      if (!isValidPassword(user, password)) {
        console.log("Invalid Password");
        return done(null, false);
      }

      return done(null, user);
    });
  })
);

passport.use(
  "signup",
  new LocalStrategy(
    {
      passReqToCallback: true,
    },
    (req, username, password, done) => {
      Usuarios.findOne({ username: username }, function (err, user) {
        if (err) {
          console.log("Error in SignUp: " + err);
          return done(err);
        }

        if (user) {
          console.log("User already exists");
          return done(null, false);
        }

        const newUser = {
          username: username,
          password: createHash(password),
        };
        Usuarios.create(newUser, (err, userWithId) => {
          if (err) {
            console.log("Error in Saving user: " + err);
            return done(err);
          }
          console.log(user);
          console.log("User Registration succesful");
          return done(null, userWithId);
        });
      });
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user._id);
});

passport.deserializeUser((id, done) => {
  Usuarios.findById(id, done);
});

const app = express();

app.use(
  session({
    store: new RedisStore({ host: "localhost", port: 6379, client, ttl: 300 }),
    secret: "keyboard cat",
    cookie: {
      httpOnly: false,
      secure: false,
      maxAge: 86400000, // 1 dia
    },
    rolling: true,
    resave: true,
    saveUninitialized: false,
  })
);

app.use("/public", express.static(__dirname + "/public"));
app.set("view engine", "hbs");
app.set("views", "./views");
app.engine(
  "hbs",
  engine({
    extname: ".hbs",
    defaultLayout: "index.hbs",
    layoutsDir: __dirname + "/views/layouts",
    partialsDir: __dirname + "/views/partials",
  })
);

app.use(passport.initialize());
app.use(passport.session());

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.listen(8000, () => {
  console.log(`Example app listening on port http://localhost:8000`);
});

app.get('/auth/twitter', passport.authenticate('twitter'));
app.get('auth/twitter/callback', passport.authenticate('twitter', {
  successRedirect: '/',
  failureRedirect: '/login'
}))

app.get("/", routes.getRoot);
app.get("/login", routes.getLogin);
app.post(
  "/login",
  passport.authenticate("login", { failureRedirect: "/faillogin" }),
  routes.postLogin
);
app.get("/faillogin", routes.getFaillogin);
app.get("/signup", routes.getSignup);
app.post(
  "/signup",
  passport.authenticate("signup", { failureRedirect: "/failsignup" }),
  routes.postSignup
);
app.get("/failsignup", routes.getFailsignup);
app.get("/logout", routes.getLogout);

function checkAuthentication(req, res, next) {
  if (req.isAuthenticated()) {
    next();
  } else {
    res.redirect("/login");
  }
}

function auth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({
      error: 'not authenticated'
    });
  }

  const token = authHeader.split(' ')[1];

  jwt.verify(token, PRIVATE_KEY, (err, decoded) => {
    if (err) {
      return res.status(403).json({
        error: 'not authorized'
      });
    }

    req.user = decoded.data;
    next();
  });
 };


app.get("/ruta-protegida", checkAuthentication, (req, res) => {
  const { username, password } = req.user;
  const user = { username, password };
  res.send("<h1>Ruta ok!</h1>");
});

app.post('/register', (req, res) => {

  const { nombre, password, direccion } = req.body

  const yaExiste = usuarios.find(usuario => usuario.nombre == nombre)
  if (yaExiste) {
    return res.json({ error: 'ya existe ese usuario' });
  }

  const usuario = { nombre, password, direccion }

  usuarios.push(usuario)

  const access_token = generateToken(usuario)

  res.json({ access_token })
 })

 app.post('/login/jwt', (req, res) => {

  const { nombre, password } = req.body

  const usuario = usuarios.find(u => u.nombre == nombre && u.password == password)
  if (!usuario) {
    return res.json({ error: 'credenciales invalidas' });
  }

  const access_token = generateToken(usuario)

  res.json({ access_token })
 })

 app.get("/ruta-protegida-jwt", auth, (req, res) => {
  res.json({ ok: true });
});


app.get("*", routes.failRoute);
