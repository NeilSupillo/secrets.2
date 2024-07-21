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

class MessageHandler {
  constructor() {
    this.message = "";
  }
  getMessage() {
    return this.message;
  }
  clearMessage() {
    this.message = "";
  }
  setMessage(newMessage) {
    this.message = newMessage;
  }
}
const messageHandler = new MessageHandler();

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

const { Pool } = pg;

// const db = new Pool({
//   connectionString: process.env.POSTGRES_URL,
// });

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

app.get("/", async (req, res) => {
  let authBool;
  if (req.isAuthenticated()) {
    authBool = true;
  } else {
    authBool = false;
  }
  try {
    const result = await db.query(
      `SELECT secret FROM secrets ORDER BY updated_at DESC`
    );

    const secrets = result.rows.map((row) => row.secret);
    //console.log(secrets);

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
    console.log(req.user);
    try {
      // Fetch the user's secrets including their IDs
      const secretsResult = await db.query(
        `SELECT id, secret FROM secrets WHERE user_id = $1 ORDER BY updated_at DESC`,
        [req.user.id]
      );

      const secrets = secretsResult.rows.map((row) => ({
        id: row.id,
        secret: row.secret,
      }));
      //console.log(secrets);
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
    successRedirect: "/account",
    failureRedirect: "/login",
  })
);
// ----------------------- post request under----------------------->
app.post("/account/secret-edit", async function (req, res) {
  console.log(req.body);
  if (req.isAuthenticated()) {
    const newSecret = req.body.secret;
    const secretId = req.body.del;

    try {
      // Update the secret in the secrets table
      await db.query(
        `UPDATE secrets SET secret = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 AND user_id = $3`,
        [newSecret, secretId, req.user.id]
      );

      res.redirect("/account");
    } catch (err) {
      console.log(err);
      res.status(500).send("Internal Server Error");
    }
  } else {
    res.redirect("/login");
  }
});

app.post("/account/secret-delete", async function (req, res) {
  console.log(req.body);
  if (req.isAuthenticated()) {
    const secretId = req.body.del;
    console.log(req.body);
    try {
      // Delete the secret from the secrets table
      await db.query(`DELETE FROM secrets WHERE id = $1 AND user_id = $2`, [
        secretId,
        req.user.id,
      ]);

      res.redirect("/account");
    } catch (err) {
      console.log(err);
      res.status(500).send("Internal Server Error");
    }
  } else {
    res.redirect("/login");
  }
});

app.post("/account/delete-account", async function (req, res) {
  if (req.isAuthenticated()) {
    try {
      // Start a transaction
      await db.query("BEGIN");

      // Delete the user from the people table
      await db.query(`DELETE FROM people WHERE id = $1`, [req.user.id]);

      // Commit the transaction
      await db.query("COMMIT");

      // Log the user out after account deletion
      req.logout((err) => {
        if (err) {
          return next(err);
        }
        res.redirect("/login");
      });
    } catch (err) {
      console.log(err);
      // Rollback the transaction in case of an error
      await db.query("ROLLBACK");
      res.status(500).send("Internal Server Error");
    }
  } else {
    res.redirect("/login");
  }
});
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
      "SELECT * FROM people WHERE email = $1 OR gmail = $2",
      [email, email]
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

      res.redirect("/");
    } catch (err) {
      console.log(err);
      res.status(500).send("Internal Server Error");
    }
  } else {
    res.redirect("/login");
  }
});

// passport ---------
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
        login_message = "email";
        return cb(null, false);
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
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        //console.log(profile.email);
        // Check if a user with the given email or gmail exists
        const gmail = await db.query("SELECT * FROM people WHERE gmail = $1", [
          profile.email,
        ]);
        const email = await db.query("SELECT * FROM people WHERE email = $1", [
          profile.email,
        ]);
        if (gmail.rows.length === 0 && email.rows.length === 0) {
          // If no user exists, insert a new user with Gmail address
          const newUser = await db.query(
            "INSERT INTO people (gmail) VALUES ($1) RETURNING *",
            [profile.email]
          );
          return cb(null, newUser.rows[0]);
        } else {
          if (gmail.rows.length !== 0) {
            return cb(null, gmail.rows[0]);
          }

          // If user exists, return the existing user

          return cb(null, false);
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
