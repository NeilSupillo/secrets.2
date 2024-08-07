import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

let account_message = "";
let register_message = "";
let login_message = "";

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
//app.use(express.static("public"));
app.use(express.static(path.join(__dirname, "public")));
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});

db.connect();

app.get("/", async (req, res) => {
  try {
    const result = await db.query(
      `SELECT secret FROM secrets ORDER BY updated_at DESC`
    );

    const secrets = result.rows.map((row) => row.secret);
    //console.log(secrets);
    let authBool;
    if (req.isAuthenticated()) {
      authBool = true;
    } else {
      authBool = false;
    }
    res.render("secrets.ejs", { secrets: secrets, isAuth: authBool });
  } catch (err) {
    res.render("home.ejs");
    console.log(err);
    res.status(500).send("Internal Server Error");
  }
});

app.get("/login", (req, res) => {
  res.render("login.ejs", { login_message: login_message });
  login_message = "";
});

app.get("/register", (req, res) => {
  res.render("register", { register_message: register_message });
  register_message = "";
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

// app.get("/secrets", async (req, res) => {
//   console.log(req.user);

//   if (req.isAuthenticated()) {
//     try {
//       const result = await db.query(
//         `SELECT secret FROM secrets ORDER BY updated_at DESC`
//       );
//       console.log(result);
//       const secrets = result.rows.map((row) => row.secret);
//       res.render("secrets.ejs", { secrets: secrets });
//     } catch (err) {
//       console.log(err);
//       res.status(500).send("Internal Server Error");
//     }
//   } else {
//     res.redirect("/login");
//   }
// });

//account
app.get("/account", async function (req, res) {
  if (req.isAuthenticated()) {
    try {
      console.log(req.user);
      // Fetch the user's secrets
      const secretsResult = await db.query(
        `SELECT secret FROM secrets WHERE user_id = $1 ORDER BY updated_at DESC`,
        [req.user.id]
      );
      const secrets = secretsResult.rows.map((row) => row.secret);
      console.log(secrets);
      res.render("account.ejs", {
        user: req.user,
        secrets: secrets,
        account_message: "",
      });
    } catch (err) {
      console.log(err);
      res.status(500).send("Internal Server Error");
    }
  } else {
    res.redirect("/login");
  }
});

////////////////SUBMIT GET ROUTE/////////////////
app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit.ejs");
  } else {
    res.redirect("/login");
  }
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/account",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query(
      "SELECT * FROM people WHERE email = $1",
      [email]
    );
    if (checkResult.rows.length > 0) {
      login_message = "already registered";
      res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO people (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/account");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

////////////////SUBMIT POST ROUTE/////////////////
app.post("/submit", async function (req, res) {
  const submittedSecret = req.body.secret;
  console.log(req.user);

  if (req.isAuthenticated()) {
    try {
      // Insert the new secret into the secrets table using the user ID from req.user
      await db.query(
        `INSERT INTO secrets (user_id, secret, created_at, updated_at) 
         VALUES ($1, $2, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
        [req.user.id, submittedSecret]
      );

      res.redirect("/secrets");
    } catch (err) {
      console.log(err);
      res.status(500).send("Internal Server Error");
    }
  } else {
    res.redirect("/login");
  }
});

passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM people WHERE email = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        const result = await db.query("SELECT * FROM people WHERE email = $1", [
          profile.email,
        ]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO people (email, password) VALUES ($1, $2)",
            [profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);
passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
