const express = require('express');

const router = express.Router();

/* GET home page. */
router.get('/', (req, res) => {
  res.render('index', { title: 'Passport OAuth2/Keycloak Example App' });
});

module.exports = router;
