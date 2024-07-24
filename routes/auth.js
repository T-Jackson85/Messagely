const jwt = require("jsonwebtoken");
const Router = require("express").Router;
const router = new Router();

const User = require("../models/user");
const {SECRET_KEY, BCRYPT_WORK_FACTOR} = require("../config");
const ExpressError = require("../expressError");
const db = require("../db");
const bcrypt = require("bcrypt");
/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/
router.post("/login", async function (req, res, next) {
    try {
      const { username, password } = req.body;
      const result = await db.query(
        `SELECT password FROM users WHERE username = $1`,
        [username]);
      const user = result.rows[0];
  
      if (user) {
        if (await bcrypt.compare(password, user.password) === true) {
          return res.json({ message: "Logged in!" });
        }
      }
      throw new ExpressError("Invalid user/password", 400);
    } catch (err) {
      return next(err);
    }
  });

/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */
router.post("/register", async function (req, res, next) {
    try {
      const { username,first_name, last_name, phone, password } = req.body;
      const join_at = new Date()
      const hashedPassword = await bcrypt.hash(
        password, BCRYPT_WORK_FACTOR);
      const result = await db.query(
        `INSERT INTO users (username, first_name, last_name, phone, password, join_at)
               VALUES ($1, $2, $3, $4, $5, $6)
               RETURNING username`,
        [username,first_name, last_name, phone, hashedPassword, join_at]);
  
      return res.json(result.rows[0]);
    } catch (err) {
        
      return next(err);
    }
  });

  module.exports = router; 