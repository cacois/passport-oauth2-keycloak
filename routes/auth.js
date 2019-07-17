const express = require('express');
const passport = require('passport');
const logger = require('winston');

const router = express.Router();

router.get('/login', passport.authenticate('oauth2'));

router.get('/callback',
  passport.authenticate('oauth2', { failureRedirect: '/login' }),
  (req, res) => {
    // Successful authentication, redirect home.
    logger.info('Successful auth, redirecting...');
    res.redirect('/');
  });

module.exports = router;
