const express = require("express");
const router = express.Router();
const config = require("../../../config.json");
const Joi = require("joi");
const fs = require("fs");
const privateKey = fs.readFileSync(process.env.JWT_KEY_FILE).toString();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const axios = require("axios");
const LoginWithTwitter = require("login-with-twitter");

const schema = Joi.object({
  username: Joi.string().required(),
  password: Joi.string().required(),
});

const verifyRootLogin = async ({ username, password }) => (
    username.toLowerCase() === "root" &&
    await bcrypt.compare(password, config.rootLogin.passwordHash)
);

router.post("/authentication", async (request, response) => {
  const { error } = schema.validate(request.body);

  if (error != null) {
    response.status(400);
    response.send(error);
    return;
  }
  
  if (!(await verifyRootLogin(request.body))) {
    response.status(401);
    response.send({ error: "invalid login" });
    return;
  }
  
  const payload = {
    username: request.body.username.toLowerCase()
  };
  
  const token = jwt.sign(payload, privateKey);
  
  response.send({
    token
  });
});

router.get("/authentitcaion/twitter", async (request, response) => {
  const tw = new LoginWithTwitter({
    consumerKey: process.env.TWITTER_ACCESS_TOKEN,
    consumerSecret: process.env.TWITTER_TOKEN_SECRET,
    callbackUrl: 'https://example.com/twitter/callback'
  });

  tw.login((err, tokenSecret, url) => {
    if (err) {
      // Handle the error your way
    }
    
    // Save the OAuth token secret for use in your /twitter/callback route
    request.session.tokenSecret = tokenSecret;
    
    // Redirect to the /twitter/callback route, with the OAuth responses as query params
    response.redirect(url);
  })
})

router.get("/twitter/callback", (request, response) => {
  tw.callback({
    oauth_token: request.query.oauth_token,
    oauth_verifier: request.query.oauth_verifier
  }, request.session.tokenSecret, (err, user) => {
    if (err) {
      // Handle the error your way
    }
    
    // Delete the tokenSecret securely
    delete request.session.tokenSecret;
    
    // The user object contains 4 key/value pairs, which
    // you should store and use as you need, e.g. with your
    // own calls to Twitter's API, or a Twitter API module
    // like `twitter` or `twit`.
    // user = {
    //   userId,
    //   userName,
    //   userToken,
    //   userTokenSecret
    // }
    request.session.user = user;
    
    // Redirect to whatever route that can handle your new Twitter login user details!
    response.redirect('/');
  });
});

// router.post("/authentication/twitter", async (request, response) => {
//   const { error } = schema.validate(request.body);

//   if (error != null) {
//     response.status(400);
//     response.send(error);
//     return;
//   }

//   const request = { url: `https://api.twitter.com/oauth/access_token?oauth_verifier`,
//       oauth: {
//         consumer_key: 'KEY',
//         consumer_secret: 'SECRET',
//         token: req.query.oauth_token
//       },
//       form: { oauth_verifier: req.query.oauth_verifier }
//     }

//   const result = await axios.post(request);
  
//   // if (!(await verifyRootLogin(request.body))) {
//   //   response.status(401);
//   //   response.send({ error: "invalid login" });
//   //   return;
//   // }
  
//   // const payload = {
//   //   username: request.body.username.toLowerCase()
//   // };
  
//   const token = jwt.sign(payload, privateKey);
  
//   response.send({
//     token
//   });
// });

module.exports = router;
