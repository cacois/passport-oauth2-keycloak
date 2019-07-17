const createError = require('http-errors');
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const middlewareLogger = require('morgan');
const logger = require('winston');
const passport = require('passport');
const OAuth2Strategy = require('passport-oauth2').Strategy;
const jwt = require('jsonwebtoken');
const indexRouter = require('./routes/index');
const authRouter = require('./routes/auth');

const app = express();

logger.add(new logger.transports.Console({
  format: logger.format.combine(
    logger.format.colorize(),
    logger.format.simple(),
  ),
}));

passport.use(
  new OAuth2Strategy(
    {
      authorizationURL: 'http://localhost:8080/auth/realms/demo/protocol/openid-connect/auth',
      tokenURL:
        'http://localhost:8080/auth/realms/demo/protocol/openid-connect/token',
      clientID: 'passport-oauth2-keycloak',
      clientSecret: '2ebceb1e-91b0-49f7-9001-db5e6b7b2c63',
      callbackURL: 'http://localhost:3000/auth/callback',
    },
    (accessToken, refreshToken, profile, cb) => {
      logger.info('In passport strategy callback');
      logger.info(`accessToken: ${JSON.stringify(accessToken)}`);
      const decoded = jwt.decode(accessToken);
      logger.error(`Successfully logged in as user: ${decoded.preferred_username}`);
      // NOTE: could parse accessToken JWT to get username
      logger.info(`refreshToken: ${JSON.stringify(refreshToken)}`);
      logger.info(`Profile: ${JSON.stringify(profile)}`);
      return cb(null, profile);
    },
  ),
);

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(middlewareLogger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(passport.initialize());
app.use(passport.session());

app.use('/', indexRouter);
app.use('/auth', authRouter);

// catch 404 and forward to error handler
app.use((req, res, next) => {
  next(createError(404));
});

// error handler
app.use((err, req, res) => {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
