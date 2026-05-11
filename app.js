require("dotenv").config();

const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const Joi = require("joi");
const { MongoClient } = require("mongodb");

const app = express();

const saltRounds = 12;
const PORT = process.env.PORT || 3000;
// expire time set at 1 hour calculated in milliseconds
const expireTime = 60 * 60 * 1000;

// secret information section
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const session_secret = process.env.NODE_SESSION_SECRET;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const mongoUrl =
  `mongodb+srv://${mongodb_user}:${mongodb_password}` +
  `@${mongodb_host}/${mongodb_database}` +
  `?retryWrites=true&w=majority`;

const client = new MongoClient(mongoUrl);

let userCollection;

// ejs setup and middleware
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false }));
app.use(express.static(__dirname + "/public"));

var mongoStore = MongoStore.create({
  mongoUrl: mongoUrl,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret: session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
  }),
);

// middleware authen to check if user is logged in  
function requireLogin(req, res, next) {
  if (!req.session.authenticated) {
    return res.redirect("/login");
  }
  next();
}

// middleware authen to check if user is admin
function requireAdmin(req, res, next) {
  if (!req.session.authenticated) {
    return res.redirect("/login");
  }
  if (req.session.user_type !== "admin") {
    return res.status(403).render("403");
  }
  next();
}

app.get("/", (req, res) => {
  res.render("index", {
    authenticated: req.session.authenticated || false,
    name: req.session.name || "",
  });
});

app.get("/signup", (req, res) => {
  res.render("signup", { error: null });
});

app.post("/signupSubmit", async (req, res) => {
  var name = req.body.name;
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.object({
    name: Joi.string().max(50).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(50).required(),
  });

  const validationResult = schema.validate({ name, email, password });

  if (validationResult.error != null) {
    return res.render("signup", {
      error: validationResult.error.details[0].message,
    });
  }

  const existingUser = await userCollection.findOne({ email: email });

  if (existingUser) {
    return res.render("signup", { error: "Email already exists." });
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);

  await userCollection.insertOne({
    name: name,
    email: email,
    password: hashedPassword,
    user_type: "user",
  });

  req.session.authenticated = true;
  req.session.name = name;
  req.session.user_type = "user";
  req.session.cookie.maxAge = expireTime;

  req.session.save(() => {
    res.redirect("/members");
  });
});

app.get("/login", (req, res) => {
  res.render("login", { error: null });
});

app.post("/loginSubmit", async (req, res) => {
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().max(50).required(),
  });

  const validationResult = schema.validate({ email, password });

  if (validationResult.error != null) {
    return res.render("login", {
      error: validationResult.error.details[0].message,
    });
  }

  const user = await userCollection.findOne({ email: email });

  if (!user) {
    return res.render("login", { error: "User not found." });
  }

  if (await bcrypt.compare(password, user.password)) {
    req.session.authenticated = true;
    req.session.name = user.name;
    req.session.user_type = user.user_type || "user";
    req.session.cookie.maxAge = expireTime;

    req.session.save(() => {
      res.redirect("/members");
    });
  } else {
    return res.render("login", { error: "Invalid password." });
  }
});

app.get("/members", requireLogin, (req, res) => {
  const images = [
    "/Darth_umanaga.png",
    "/sebastionhohoho.png",
    "/the_filalfel_castro.png",
  ];
  res.render("members", { name: req.session.name, images: images });
});

app.get("/admin", requireAdmin, async (req, res) => {
  const users = await userCollection.find().toArray();
  res.render("admin", { users: users });
});

app.get("/promoteUser", requireAdmin, async (req, res) => {
  const schema = Joi.object({ email: Joi.string().email().required() });
  const { error } = schema.validate({ email: req.query.email });
  if (error) return res.status(400).send("Invalid email.");

  await userCollection.updateOne(
    { email: req.query.email },
    { $set: { user_type: "admin" } },
  );
  res.redirect("/admin");
});

app.get("/demoteUser", requireAdmin, async (req, res) => {
  const schema = Joi.object({ email: Joi.string().email().required() });
  const { error } = schema.validate({ email: req.query.email });
  if (error) return res.status(400).send("Invalid email.");

  await userCollection.updateOne(
    { email: req.query.email },
    { $set: { user_type: "user" } },
  );
  res.redirect("/admin");
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

app.use((req, res) => {
  res.status(404).render("404");
});

async function connectDatabase() {
  await client.connect();
  const db = client.db(mongodb_database);
  userCollection = db.collection("users");
}

connectDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });
});
