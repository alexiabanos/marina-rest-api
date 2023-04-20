'use strict';

const express = require('express');
const app = express();
app.enable('trust proxy');
app.use(express.json());


// load html view management
const handlebars = require('express-handlebars').create({defaultLayout:'main'});  // initializes handlebars handler
app.engine('handlebars', handlebars.engine);  // tells app to use the handlebars engine
app.set('view engine', 'handlebars');         // sets view to process through handlebars files

// load axios / request for making html requests
const axios = require('axios')
const request = require('request');

// load sessions for storing req state
var session = require('express-session');       // initialize sessions for user state storage
app.use(session({secret:'SuperSecretSessionsPassword'}));   // unique string for session secret (different from OAuth secret)

// load jwt verification
const jwt = require('express-jwt');
const jwksRsa = require('jwks-rsa');

// load jwt decoder
const jwt_decode = require('jwt-decode');

// load Passport
var passport = require('passport');
var Auth0Strategy = require('passport-auth0');

// load url and querystring modules for logout func
var url = require('url');
const querystring = require('querystring');


// By default, the client will authenticate using the service account file
// specified by the GOOGLE_APPLICATION_CREDENTIALS environment variable and use
// the project specified by the GOOGLE_CLOUD_PROJECT environment variable. See
// https://github.com/GoogleCloudPlatform/google-cloud-node/blob/master/docs/authentication.md
// These environment variables are set automatically on Google App Engine
const {Datastore} = require('@google-cloud/datastore');
const { send } = require('process');
const { get } = require('request');
const { errorMonitor } = require('events');
const datastore = new Datastore();    // Instantiate a datastore client

// declaring global variables
const CLIENT_ID = 'YOUR_CLIENT_ID_HERE';
const CLIENT_SECRET = 'YOUR_CLIENT_SECRET_HERE';
const DOMAIN = 'cs493-cloud-dev.us.auth0.com';
const redirect_uri = "https://dev-epsilon-309902.wl.r.appspot.com/auth/auth0";
const logout_redirect_uri = "https://dev-epsilon-309902.wl.r.appspot.com/auth/welcome";

// Configure Passport to use Auth0
var strategy = new Auth0Strategy(
  {
    domain: DOMAIN,
    clientID: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    callbackURL:
      redirect_uri || 'http://localhost:8080/auth/welcome' //'https://dev-epsilon-309902.wl.r.appspot.com/welcome'
  },
  function (accessToken, refreshToken, extraParams, profile, done) {
    // accessToken is the token to call Auth0 API (not needed in the most cases)
    // extraParams.id_token has the JSON Web Token
    // profile has all the information from the user
    return done(null, extraParams.id_token);
  }
);

passport.use(strategy);

app.use(passport.initialize());
app.use(passport.session());

// Functions for serializing and deserializing passport results from Auth0
passport.serializeUser(function (user, done) {
  done(null, user);
});

passport.deserializeUser(function (user, done) {
  done(null, user);
});

const auth = express.Router();
const marina = express.Router();

/* ------------- Begin Marina Model Functions ------------- */

/**
 * Insert a record into the database based on the provided type (either boat or slip).
 *
 * @param {object} type The boat record to insert.
 */
const insert_entity = (req, type, entity) => {
  var key = datastore.key(type);
  return datastore.save({
    key: key,
    data: entity
  }).then(() => {
    entity.id = key.id;
    entity.self = req.protocol + '://' + req.get('host') + req.originalUrl + "/" + entity.id;
    if (type == 'users') {
      entity.self = req.protocol + '://' + req.get('host') + "/marina/users/" + entity.id;
    }
    return entity
  });
};

/**
 * Retrieve list of all entity records from the database for a specificy type/kind.
 */
const get_entities = async (req, type) => {
  const query = datastore.createQuery(type);
  const apiResponse = await datastore.runQuery(query);
  var entities = apiResponse[0];

  // updates json attributes to include desired details (id)
  entities.forEach(function(entity) {
    entity.id = entity[datastore.KEY].id;
    entity.self = req.protocol + '://' + req.get('host') + req.originalUrl + '/' + entity.id;
    if (type == 'users'){
      entity.self = req.protocol + '://' + req.get('host') + "/marina/users/" + entity.id;
    }

    // for embedded json values (e.g. load.carrier or boat.loads), generates self values
    if (type == "boats"){
      if (entity.loads.length != 0){
        entity.loads.forEach(function(load) {
          load.self = req.protocol + '://' + req.get('host') + "/marina/loads/" + load.id;
        });
      }
    } else if (type == "loads"){
      if (entity.carrier != null){
        entity.carrier.self = req.protocol + '://' + req.get('host') +  "/marina/boats/" + entity.carrier.id;
      }
    } else if (type == "users"){
      if (entity.boats != null){
        entity.boats.forEach(function(boat) {
          boat.self = req.protocol + '://' + req.get('host') +  "/marina/boats/" + boat.id;
        });
      }
    }
  });
  return entities;
};

/**
 * Retrieve list of all entity records from the database for a specificy type/kind.
 * Implements pagination via cursor tracker to show only 5 records at a time and
 * provides a 'next' url to get the next page of results as well as total record count.
 */
const get_entities_pagination_public = async (req, type) => {
  var q = datastore.createQuery(type).limit(5);
  const results = {};

  // get total record count
  var count = datastore.createQuery(type);
  var countResponse = await datastore.runQuery(count);
  results.total_rows = countResponse[0].length;

  if(Object.keys(req.query).includes("cursor")){
      q = q.start(req.query.cursor);
  }

  return datastore.runQuery(q).then( (apiResponse) => {
    results.results = apiResponse[0];
    results.results.forEach(function(entity) {
      // generates id and self values for each entity to return
      entity.id = entity[datastore.KEY].id;
      entity.self = req.protocol + '://' + req.get('host') + req.originalUrl + "/" + entity.id;

      // for embedded json values (e.g. load.carrier or boat.loads), generates self values
      if (type == "boats"){
        if (entity.loads.length != 0){
          entity.loads.forEach(function(load) {
            load.self = req.protocol + '://' + req.get('host') + "/marina/loads/" + load.id;
          });
        }
      } else if (type == "loads"){
        if (entity.carrier != null){
          entity.carrier.self = req.protocol + '://' + req.get('host') +  "/marina/boats/" + entity.carrier.id;
        }
      } else if (type == "users"){
        if (entity.boats != null){
          entity.boats.forEach(function(boat) {
            boat.self = req.protocol + '://' + req.get('host') +  "/marina/boats/" + boat.id;
          });
        }
      }
    });

    // checks to see if there are more results, if not, will not populate 'next' attribute
    if(apiResponse[1].moreResults !== Datastore.NO_MORE_RESULTS ){
      results.next = req.protocol + "://" + req.get("host") + req.baseUrl + "/" + type + "?cursor=" + apiResponse[1].endCursor;
    }
    return results;
  });
}

/**
 * Retrieve list of all entity records from the database for a specific type/kind given a verified JWT.
 * Implements pagination via cursor tracker to show only 5 records at a time and
 * provides a 'next' url to get the next page of results as well as total record count.
 */
 const get_entities_pagination_jwt = async (req, type) => {
  var q = datastore.createQuery(type).filter('owner', '=', req.user.sub).limit(5);
  const results = {};

  // get total record count
  var count = datastore.createQuery(type).filter('owner', '=', req.user.sub);
  var countResponse = await datastore.runQuery(count);
  results.total_rows = countResponse[0].length;

  if(Object.keys(req.query).includes("cursor")){
      q = q.start(req.query.cursor);
  }
  results.total_rows = datastore.runQuery(count);

  return datastore.runQuery(q).then( (apiResponse) => {
    results.results = apiResponse[0];
    results.results.forEach(function(entity) {
      // generates id and self values for each entity to return
      entity.id = entity[datastore.KEY].id;
      entity.self = req.protocol + '://' + req.get('host') + req.originalUrl + "/" + entity.id;

      // for embedded json values (e.g. load.carrier or boat.loads), generates self values
      if (type == "boats"){
        if (entity.loads.length != 0){
          entity.loads.forEach(function(load) {
            load.self = req.protocol + '://' + req.get('host') + "/loads/" + load.id;
          });
        }
      } else if (type == "loads"){
        if (entity.carrier != null){
          entity.carrier.self = req.protocol + '://' + req.get('host') + "/boats/" + entity.carrier.id;
        }
      }
    });

    // checks to see if there are more results, if not, will not populate 'next' attribute
    if(apiResponse[1].moreResults !== Datastore.NO_MORE_RESULTS ){
      results.next = req.protocol + "://" + req.get("host") + req.baseUrl + "/" + type + "?cursor=" + apiResponse[1].endCursor;
    }
    return results;
  });
}

/**
 * Retrieve a single entity record from the database based on entity type/kind.
 */
const get_entity = async (req, type, entity_id) => {
  const key = datastore.key([type, parseInt(entity_id)]);
  const apiResponse = await datastore.get(key);
  var entity = apiResponse[0];
  entity.id = entity[datastore.KEY].id;
  entity.self = req.protocol + '://' + req.get('host') + req.originalUrl;

  // for embedded json values (e.g. load.carrier or boat.loads), generates self values
  if (type == "boats"){
    if (entity.loads.length != 0){
      entity.loads.forEach(function(load) {
        load.self = req.protocol + '://' + req.get('host') + "/marina/loads/" + load.id;
      });
    }
  } else if (type == "loads"){
    if (entity.carrier != null){
      entity.carrier.self = req.protocol + '://' + req.get('host') +  "/marina/boats/" + entity.carrier.id;
    }
  } else if (type == "users"){
    if (entity.boats != null){
      entity.boats.forEach(function(boat) {
        boat.self = req.protocol + '://' + req.get('host') +  "/marina/boats/" + boat.id;
      });
    }
  }

  return entity;
};

/**
 * Delete a single entity record from the database based on entity type/kind and id.
 */
const delete_entity = (type, entity_id) => {
  var key = datastore.key([type, parseInt(entity_id)]);
  return datastore.delete(key);
};

/**
 * Edits a single entity record from the database based on type/kind and id with updated params.
*/
const update_entity = (req, type, entity_id, entity) => {
  if (entity.hasOwnProperty("self")){
    delete entity["self"];
  }
  if (entity.hasOwnProperty("id")){
    delete entity["id"];
  }
  var key = datastore.key([type, parseInt(entity_id)]);
  return datastore.update({
    key: key,
    data: entity
  }).then(() => {
    entity.id = key.id;
    entity.self = req.protocol + '://' + req.get('host') + req.originalUrl;
    return entity
  });
};

/**
 * Function for simplifying response sends and messaging.
 */
const send_response = (res, status_code, json_data) => {
  res
  .status(status_code)
  .set('Content-Type', 'application/json')
  .send(json_data).
  end();
  return;
};

/**
 * Function for determining if post or put request object has needed attributes.
 * Returns true if it has all necessary attributes, false otherwise.
 */
const has_required_attributes = (req, type) => {
  if (type == "boats") {
    return (req.body.hasOwnProperty("name") && req.body.hasOwnProperty("type") && req.body.hasOwnProperty("length"));
  } else if (type == "loads") {
    return (req.body.hasOwnProperty("volume") && req.body.hasOwnProperty("content"));
  }
};

/**
 * Function for determining if patch request object has needed attributes.
 * Returns true if it has at least one of the necessary attributes, false otherwise.
 */
const has_attributes = (req, type) => {
  if (type == "boats") {
    return (req.body.hasOwnProperty("name") || req.body.hasOwnProperty("type") || req.body.hasOwnProperty("length"));
  } else if (type == "loads") {
    return (req.body.hasOwnProperty("volume") || req.body.hasOwnProperty("content"));
  }
};

/**
 * Function for determining if post/put/patch request object has valid attribute values.
 * Returns true if all input values are valid
 */
const has_valid_request_values = (entity, type) => {
  var boolean;
  
  // validations for boats
  if (type == "boats") {
    // What characters should be allowed in the name attribute?
    // If a request has extraneous attributes (e.g., color), what is the behavior of the application?
    boolean = ((typeof entity.name == "string" || typeof entity.name == 'undefined')
      && (typeof entity.type == "string" || typeof entity.type == 'undefined')
      && (typeof parseInt(entity.length) == "number" || typeof entity.length == 'undefined'));

    // checks that name attribute for data validation
    if (typeof entity.name != 'undefined'){
      // check length less  than 40 char
      boolean = (boolean && (entity.name.length < 40));
      // check alphanumeric or spaces
      const regex = /^[a-z0-9' ']+$/i;
      boolean = (boolean && regex.test(entity.name));
      // check that name is not just all spaces
      const space_regex = /^[ ']+$/i;
      boolean = (boolean && !space_regex.test(entity.name));
    }

    // checks that type attribute is less than 100 characters long
    if (typeof entity.type != 'undefined'){
      boolean = (boolean && (entity.type.length < 100));
    }

    // non-negativity check for length value
    if (typeof entity.length != 'undefined'){
      boolean = (boolean && (parseInt(entity.length) > 0));
    }
  } 
  // validations for loads
  else if (type == "loads") {
    // What characters should be allowed in the name attribute?
    // If a request has extraneous attributes (e.g., color), what is the behavior of the application?
    boolean = ((typeof entity.content == "string" || typeof entity.name == 'undefined')
      && (typeof parseInt(entity.volume) == "number" || typeof entity.length == 'undefined'));

    // checks that content attribute for data validation
    if (typeof entity.content != 'undefined'){
      // check length less  than 150 char
      boolean = (boolean && (entity.content.length < 150));
      // check alphanumeric or spaces
      const regex = /^[a-z0-9' ']+$/i;
      boolean = (boolean && regex.test(entity.content));
      // check that name is not just all spaces
      const space_regex = /^[ ']+$/i;
      boolean = (boolean && !space_regex.test(entity.content));
    }

    // non-negativity check for length value
    if (typeof entity.volume != 'undefined'){
      boolean = (boolean && (parseInt(entity.volume) > 0));
    }
  } 
  // validations for users
  else if (type == "user") {
    boolean = boolean + true;
  }

  return boolean;
};

/**
 * Function for determining if post/put/patch request object has a name attribute value
 * that is not unique to the existing dataset.  Returns true if name is duplicated, false otherwise.
 */
 const is_duplicate_user = async (req, type, entity) => {
  try {
    // querys datastore for desired entity results by type
    const entities = await get_entities(req, type);
    var dupe_bool = false;

    // checks if name matches and updates boolean
    entities.forEach(function(a) {
      if (a.auth0_id == entity.auth0_id){
        dupe_bool = true;
      }
    });
    return dupe_bool;

  // catch for if no entities exist yet
  } catch (error) {
    return false;
  }
};

/**
 * Function for formatting post/put/patch request object to ensure that we only track the name, type, 
 * and length attributes.  All extraneous attributes will be dropped prior to save into datastore.
 */
 const create_entity = (type, entity, existing_entity) => {
  var formatted_entity = {};
  
  if (typeof existing_entity == 'undefined'){
    existing_entity = {};
  }

  if (type == "boats") {
    if (typeof entity.name == 'undefined'){
      formatted_entity.name = existing_entity.name;
    } else {
      formatted_entity.name = entity.name;
    }
  
    if (typeof entity.type == 'undefined'){
      formatted_entity.type = existing_entity.type;
    } else {
      formatted_entity.type = entity.type;
    }
  
    if (typeof entity.length == 'undefined'){
      formatted_entity.length = existing_entity.length;
    } else {
      formatted_entity.length = entity.length;
    }

    formatted_entity.loads = existing_entity.loads;
    formatted_entity.owner = existing_entity.owner;
  
  } else if (type == "loads") {
    if (typeof entity.volume == 'undefined'){
      formatted_entity.volume = existing_entity.volume;
    } else {
      formatted_entity.volume = entity.volume;
    }
  
    if (typeof entity.content == 'undefined'){
      formatted_entity.content = existing_entity.content;
    } else {
      formatted_entity.content = entity.content;
    }
  
    if (typeof entity.creation_date == 'undefined'){
      formatted_entity.creation_date = existing_entity.creation_date;
    } else {
      formatted_entity.creation_date = entity.creation_date;
    }

    formatted_entity.carrier = existing_entity.carrier;
  }
  return formatted_entity;
};

/**
 * Function for generate date string for load creation_date attribute.
 */
const get_date = () => {
  var date = new Date();
  var dd = String(date.getDate()).padStart(2, '0');
  var mm = String(date.getMonth() + 1).padStart(2, '0'); //January is 01
  var yyyy = date.getFullYear();

  date = mm + '/' + dd + '/' + yyyy;
  return date;
}

/**
 * Function for simplifying the removal of a relationship between a load and a boat.
 */
 const remove_relationship = async (req, type, entity_id) => {
  if (type == 'loads'){
    var load = await get_entity(req, 'loads', entity_id);
    load.carrier = null;
    return await update_entity(req, 'loads', load.id, load);
  }
}

/**
 * Function for streamlining updating user entity of newly created boat entity they own
 */
const add_ownership = async (req, type, entity) => {
  var owner_id;
  var users = await get_entities(req, type);
  users.forEach(function(user) {
    if (user.auth0_id == req.user.sub) {
      owner_id = user.id;
    }
  });
  var owner = await get_entity(req, type, owner_id);
  owner.boats.push(entity);
  await update_entity(req, 'users', owner_id, owner);
}

/**
 * Function for validating a JWT.  If invalid or no JWT provided, throws a 401 unauthorized error
 */
const checkJwt = jwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `https://${DOMAIN}/.well-known/jwks.json`
  }),

  // Validate the audience and the issuer.
  issuer: `https://${DOMAIN}/`,
  algorithms: ['RS256']
});


/* ------------- End Model Functions ------------- */


/* ------------- Begin Controller Functions ------------- */

app.get('/', (req, res, next) => {
  try {
    res
      .status(200)
      .set('Content-Type', 'text/plain')
      .send(
        `Status: 200 OK\n\nHello World!  Live from Seattle!`
        )
      .end();
  } catch (error) {
    next(error);
  }
});

auth.get('/welcome', (req, res, next) => {
  try {
      var context = {};
      context.Auth0_Redirect = req.protocol + '://' + req.get('host') + "/auth/login";
      res.render('welcome', context);
  } catch (error) {
      next(error);
  }
});

// Perform the login, after login Auth0 will redirect to callback
auth.get('/login', passport.authenticate('auth0', {
  scope: 'openid email profile'
}), function (req, res) {
  res.redirect('/auth/welcome');
});

// Perform the final stage of authentication and redirect to previously requested URL or '/user'
auth.get('/auth0', function (req, res, next) {
  passport.authenticate('auth0', function (err, user, info) {
    if (err) { return next(err); }
    if (!user) { return res.redirect('/auth/login'); }
    req.logIn(user, function (err) {
      if (err) { return next(err); }
      res.redirect('/auth/user');
    });
  })(req, res, next);
});

// renders user details page once account creation / login complete with current active JWT
auth.get('/user', async (req, res, next) => {
  try {
      var context = {};
      context.user = req.session.passport.user;

      // adds user entity details to app datastore
      var decoded = jwt_decode(context.user);
      var user = {}
      user.nickname = decoded.nickname;
      user.name = decoded.name;
      user.email = decoded.email;
      user.auth0_id = decoded.sub;
      user.boats = [];

      var dupe = await is_duplicate_user(req, 'users', user);
      if (!dupe){
        const results = await insert_entity(req, 'users', user);
      }
      context.user_id = user.auth0_id;

      context.logout = req.protocol + '://' + req.get('host') + '/auth/logout';
      res.render('user_info', context);
      
  } catch (error) {
      next(error);
  }
});

// Perform session logout and redirect to homepage
auth.get('/logout', (req, res) => {
  try {
    req.logout();
    var returnTo = logout_redirect_uri;
    var logoutURL = new url.URL(
      `https://${DOMAIN}/v2/logout`
    );
    var searchString = querystring.stringify({
      client_id: CLIENT_ID,
      returnTo: returnTo
    });
    logoutURL.search = searchString;
  
    res.redirect(logoutURL);
  } catch (error) {
    next(error);
  }
});

marina.post('/boats', checkJwt, async (req, res) => {
  // Create an entity record to be stored in the database, entity kind dictated by path
  try {
    const type = 'boats';
    var entity = req.body;
    
    // check valid mime type
    if(req.get('Content-Type') !== 'application/json'){
      send_response(res, 415, {"Error":  "The request object contains data in an unsupported media type"});
      return;
    }

    // Check if any of the required inputs are missing or have invalid values
    if (!has_required_attributes(req, type) || !has_valid_request_values(entity, type)) {
      send_response(res, 400, {"Error": "The request object is missing at least one of the required attributes or provides an invalid attribute value."});
      return;
    }

    // Adds additional values to entities for data / relationship management
    entity.loads = [];
    entity.owner = req.user.sub;

    // Generate entity details and sends insert/save query to datastore
    entity = await insert_entity(req, type, entity);

    // for boats, also generate relationship with user entity to shown ownership
    var boat_data = {};
    boat_data.id = entity.id;
    boat_data.name = entity.name;
    add_ownership(req, 'users', boat_data);

    // Generates appropriate response type with formatted json objects
    send_response(res, 201, JSON.stringify(entity, ["id", "name", "type", "length", "loads", "owner", "self", ], 1));
    return;


  // error handling
  } catch (error) {
    send_response(res, 500, {"Error": "Could not process request"});
  }
}).use((err, req, res, next) => {
  // if no valid JWT present, calls next middleware function (second routing with mounted function for public boats)
  if (err.name === 'UnauthorizedError') {
    send_response(res, 401, {"Error": "Unauthorized Access error, no valid JWT was provided"});
  }
});

marina.post('/loads', async (req, res) => {
  // Create an entity record to be stored in the database, entity kind dictated by path
  try {
    const type = 'loads';
    var entity = req.body;
    
    // check valid mime type
    if(req.get('Content-Type') !== 'application/json'){
      send_response(res, 415, {"Error":  "The request object contains data in an unsupported media type"});
      return;
    }

    // Check if any of the required inputs are missing or have invalid values
    if (!has_required_attributes(req, type) || !has_valid_request_values(entity, type)) {
      send_response(res, 400, {"Error": "The request object is missing at least one of the required attributes or provides an invalid attribute value."});
      return;
    }

    // Adds additional values to entities for data / relationship management
    entity.carrier = null;
    entity.creation_date = get_date();

    // Generate entity details and sends insert/save query to datastore
    entity = await insert_entity(req, type, entity);

    // Generates appropriate response type with formatted json objects
    send_response(res, 201, JSON.stringify(entity, ["id", "volume", "content", "creation_date", "carrier", "self"], 1));
    return;

  // error handling
  } catch (error) {
    send_response(res, 500, {"Error": "Could not process request"});
  }
});

// get /boats collection route, requires valid JWT
marina.get('/boats', checkJwt, async (req, res, next) => {
  // returns a json array with all entities of a certain type/kind
  try {
    const type = 'boats';

    // querys datastore for desired entity results
    const entities = await get_entities_pagination_jwt(req, type);

    // Generate appropriate response based on content type with formatted json objects
    const accepts = req.accepts(['application/json']);

    if(!accepts){
      send_response(res, 406, {"Error": "API Endpoint does not support the requested response content type"});
    
    } else if(accepts === 'application/json'){
      // Generates appropriate response type with formatted json objects
      send_response(res, 200, JSON.stringify(entities, ["results", "id", "name", "type", "length", "loads", "id", "owner", "self", "next", "total_rows"], 1));
      return;
    } else {     
      throw new Error('Could not process request');
    }

  // error handling
  } catch (error) {
    res.status(500).end();
  }
}).use((err, req, res, next) => {
  // if no valid JWT present, calls next middleware function (second routing with mounted function for public boats)
  if (err.name === 'UnauthorizedError') {
    send_response(res, 401, {"Error": "Unauthorized Access error, no valid JWT was provided"});
  }
});

// get /users collection route, does not require jwt
marina.get('/users', async (req, res, next) => {
  // returns a json array with all entities of a certain type/kind
  try {
    const type = 'users';

    // querys datastore for desired entity results
    const entities = await get_entities_pagination_public(req, type);

    // Generate appropriate response based on content type with formatted json objects
    const accepts = req.accepts(['application/json']);

    if(!accepts){
      send_response(res, 406, {"Error": "API Endpoint does not support the requested response content type"});
    
    } else if(accepts === 'application/json'){
      // Generates appropriate response type with formatted json objects
      send_response(res, 200, JSON.stringify(entities, ["results", "id", "nickname", "name", "email", "auth0_id", "boats", "id", "name", "self", "self", "next", "total_rows"], 1));
      return;
    } else {     
      throw new Error('Could not process request');
    }

  // error handling
  } catch (error) {
    res.status(500).end();
  }
});

// get /loads collection route, does not require valid JWT
marina.get('/loads', async (req, res, next) => {
  // returns a json array with all entities of a certain type/kind
  try {
    const type = 'loads';

    // querys datastore for desired entity results
    const entities = await get_entities_pagination_public(req, type);

    // Generate appropriate response based on content type with formatted json objects
    const accepts = req.accepts(['application/json']);

    if(!accepts){
      send_response(res, 406, {"Error": "API Endpoint does not support the requested response content type"});
    
    } else if(accepts === 'application/json'){
      // Generates appropriate response type with formatted json objects
      send_response(res, 200, JSON.stringify(entities, ["results", "id", "volume", "content", "creation_date", "carrier", "id", "name", "self", "self", "next", "total_rows"], 1));
      return;
    } else {     
      throw new Error('Could not process request');
    }

  // error handling
  } catch (error) {
    res.status(500).end();
  }
});

marina.get('/boats/:entity_id', checkJwt, async (req, res, next) => {
  // return an entity record that isstored in the database based on type and id
  try {
    const type = 'boats';
    const entity_id = req.params.entity_id;
    // Query datastore to retrieve desired entity
    const entity = await get_entity(req, type, entity_id);

    // check that entity is owned by request bearer
    if (entity.owner != req.user.sub){
      throw new Error('Entity has a different owner than provided token_id');
    }

    // Checks accept headers for application/json
    const accepts = req.accepts(['application/json']);
    if(!accepts){
      send_response(res, 406, {"Unauthorized": "API Endpoint does not support the requested response content type"});
    
    } else if(accepts === 'application/json'){
      // Generates appropriate response type with formatted json objects
      send_response(res, 200, JSON.stringify(entity, ["id", "name", "type", "length", "loads", "id", "self", "owner", "self"], 1));
      return;   
    } else {     
      throw new Error('Could not process request');
    }

  // error handling
  } catch (error) {
    if (error.message == "Entity has a different owner than provided token_id"){
      send_response(res, 403, {"Error": "No entities with this entity_id exists or this entity is owned by someone else" });
    } else {
      send_response(res, 404, {"Error":  "No entity (e.g. user, boat, or load) with this id exists" });
    }
  }
}).use((err, req, res, next) => {
  // if no valid JWT present, calls next middleware function (second routing with mounted function for public boats)
  if (err.name === 'UnauthorizedError') {
    send_response(res, 401, {"Error": "Unauthorized Access error, no valid JWT was provided"});
  }
});

marina.get('/users/:entity_id', checkJwt, async (req, res, next) => {
  // return an entity record that isstored in the database based on type and id
  try {
    const type = 'users';
    const auth0_id = req.params.entity_id;
    
    // Query datastore to retrieve desired entity
    const entities = await get_entities(req, type);
    var user = null;

    entities.forEach(function(entity) {
      if (entity.auth0_id == auth0_id){
        user = entity;
      }
    })

    // check that entity is owned by request bearer
    if (user == null){
      throw new Error('Entity has a different owner than provided token_id');
    }

    // Checks accept headers for application/json
    const accepts = req.accepts(['application/json']);
    if(!accepts){
      send_response(res, 406, {"Error": "API Endpoint does not support the requested response content type"});
    
    } else if(accepts === 'application/json'){
      // Generates appropriate response type with formatted json objects
      send_response(res, 200, JSON.stringify(user, ["id", "nickname", "name", "email", "auth0_id", "boats", "id", "name", "self", "self"], 1));
      return;   
    } else {     
      throw new Error('Could not process request');
    }

  // error handling
  } catch (error) {
    if (error.message == "Entity has a different owner than provided token_id"){
      send_response(res, 403, {"Error": "No entities with this entity_id exists or this entity is owned by someone else" });
    } else {
      send_response(res, 404, {"Error":  "No entity (e.g. user, boat, or load) with this id exists" });
    }
  }
}).use((err, req, res, next) => {
  // if no valid JWT present, calls next middleware function (second routing with mounted function for public boats)
  if (err.name === 'UnauthorizedError') {
    send_response(res, 401, {"Error": "Unauthorized Access error, no valid JWT was provided"});
  }
});

marina.get('/loads/:entity_id', async (req, res, next) => {
  // return an entity record that isstored in the database based on type and id
  try {
    const type = 'loads';
    const entity_id = req.params.entity_id;
    // Query datastore to retrieve desired entity
    const entity = await get_entity(req, type, entity_id);

    // Generate appropriate response based on content type with formatted json objects
    const accepts = req.accepts(['application/json']);
    if(!accepts){
      send_response(res, 406, {"Error": "API Endpoint does not support the requested response content type"});
    
    } else if(accepts === 'application/json'){
      // Generates appropriate response type with formatted json objects
      send_response(res, 200, JSON.stringify(entity, ["id", "volume", "content", "creation_date", "carrier", "id", "name", "self", "self"], 1));
      return;       
    } else {     
      throw new Error('Could not process request');
    }

  // error handling
  } catch (error) {
    send_response(res, 404, {"Error":  "No entity (e.g. user, boat, or load) with this id exists" });
  }
});

marina.put('/boats/:entity_id', checkJwt, async (req, res, next) => {
  // Updates a specific entity record in datastore based on entity type/kind and id
  try {
    const type = 'boats';
    const entity_id = req.params.entity_id;
    var entity = req.body;

    // check that entity exists
    var existing_entity = await get_entity(req, type, entity_id);

    // check that entity is owned by request bearer
    if (existing_entity.owner != req.user.sub){
      throw new Error('Entity has a different owner than provided token_id');
    }

    // check valid mime type
    if(req.get('Content-Type') !== 'application/json'){
      send_response(res, 415, {"Error":  "The request object contains data in an unsupported media type"});
      return;
    }

    // Check if any of the required inputs are missing or have invalid values
    if (!has_required_attributes(req, type) || !has_valid_request_values(entity, type)) {
      send_response(res, 400, {"Error": "The request object is missing at least one of the required attributes or provides an invalid attribute value."});
      return;
    }

    // Ensures relationships maintained w/ owner and loads
    entity.loads = existing_entity.loads;
    entity.owner = existing_entity.owner;

    // Send update query to datastore and update json objects for desired attributes
    entity = await update_entity(req, type, entity_id, entity);

    // Handling 'side effects of editing aboat entity'
    if (existing_entity.name != entity.name) {
      // update all relevant loads with new boat name
      var loads = await get_entities(req, 'loads');
      loads.forEach(function(load) {
        if (load.carrier != null) {
          if (load.carrier.id == entity.id) {
            load.carrier.name = entity.name;
            update_entity(req, 'loads', load.id, load);
          }
        }
      });
        
      // update the owner's user entity with new boat name
      var users = await get_entities(req, 'users');
      users.forEach(function(user) {
        if (user.auth0_id == req.user.sub) {
          user.boats.forEach(function(boat) {
            if (boat.id == entity.id) {
              boat.name = entity.name;
              update_entity(req, 'users', user.id, user);
            }
          });
        }
      });
    }

    // Generate html response with formatted json objects
    res.location(entity.self);
    send_response(res, 303, JSON.stringify(entity, ["id", "name", "type", "length", "loads", "id", "self", "owner", "self"], 1));
  
  // error handling
  } catch (error) {
    if (error.message == "Entity has a different owner than provided token_id"){
      send_response(res, 403, {"Error": "No entities with this entity_id exists or this entity is owned by someone else" });
    } else {
      send_response(res, 404, {"Error":  "No entity (e.g. user, boat, or load) with this id exists" });
    }
  }
}).use((err, req, res, next) => {
  // if no valid JWT present, calls next middleware function (second routing with mounted function for public boats)
  if (err.name === 'UnauthorizedError') {
    send_response(res, 401, {"Error": "Unauthorized Access error, no valid JWT was provided"});
  }
});

marina.put('/loads/:entity_id', async (req, res, next) => {
  // Updates a specific entity record in datastore based on entity type/kind and id
  try {
    const type = 'loads';
    const entity_id = req.params.entity_id;
    var entity = req.body;

    // check that entity exists
    var existing_entity = await get_entity(req, type, entity_id);

    // check valid mime type
    if(req.get('Content-Type') !== 'application/json'){
      send_response(res, 415, {"Error":  "The request object contains data in an unsupported media type"});
      return;
    }

    // Check if any of the required inputs are missing or have invalid values
    if (!has_required_attributes(req, type) || !has_valid_request_values(entity, type)) {
      send_response(res, 400, {"Error": "The request object is missing at least one of the required attributes or provides an invalid attribute value."});
      return;
    }

    // Ensures relationships maintained with boats
    entity.creation_date = existing_entity.creation_date;
    entity.carrier = existing_entity.carrier;

    // Send update query to datastore and update json objects for desired attributes
    entity = await update_entity(req, type, entity_id, entity);

    // Generate html response with formatted json objects
    res.location(entity.self);
    send_response(res, 303, JSON.stringify(entity, ["id", "volume", "content", "creation_date", "carrier", "id", "name", "self", "self"], 1));
  
  // error handling
  } catch (error) {
    send_response(res, 404, {"Error": "No entity (e.g. user, boat, or load) with this id exists"});
  }
});

marina.patch('/boats/:entity_id', checkJwt, async (req, res, next) => {
  // Updates a specific entity record in datastore based on entity type/kind and id
  try {
    const type = 'boats';
    const entity_id = req.params.entity_id;
    var entity = req.body;

    // check that entity exists
    var existing_entity = await get_entity(req, type, entity_id);

    // check that entity is owned by request bearer
    if (existing_entity.owner != req.user.sub){
      throw new Error('Entity has a different owner than provided token_id');
    }

    // check valid mime type
    if(req.get('Content-Type') !== 'application/json'){
      send_response(res, 415, {"Error":  "The request object contains data in an unsupported media type"});
      return;
    }

    // Check if any of the required inputs are missing or have invalid values
    if (!has_attributes(req, type) || !has_valid_request_values(entity, type)) {
      send_response(res, 400, {"Error": "The request object is missing at least one of the required attributes or provides an invalid attribute value."});
      return;
    }

    // Ensures entity has all required parameters and maintains existing relationships
    entity = create_entity(type, entity, existing_entity);

    // Send update query to datastore and update json objects for desired attributes
    entity = await update_entity(req, type, entity_id, entity);

    // Handling 'side effects of editing aboat entity'
    if (existing_entity.name != entity.name) {
      // update all relevant loads with new boat name
      var loads = await get_entities(req, 'loads');
      loads.forEach(function(load) {
        if (load.carrier != null) {
          if (load.carrier.id == entity.id) {
            load.carrier.name = entity.name;
            update_entity(req, 'loads', load.id, load);
          }
        }
      });
        
      // update the owner's user entity with new boat name
      var users = await get_entities(req, 'users');
      users.forEach(function(user) {
        if (user.auth0_id == req.user.sub) {
          user.boats.forEach(function(boat) {
            if (boat.id == entity.id) {
              boat.name = entity.name;
              update_entity(req, 'users', user.id, user);
            }
          });
        }
      });
    }

    // Generate html response with formatted json objects
    send_response(res, 200, JSON.stringify(entity, ["id", "name", "type", "length", "loads", "id", "self", "owner", "self"], 1));
  
  // error handling
  } catch (error) {
    if (error.message == "Entity has a different owner than provided token_id"){
      send_response(res, 403, {"Error": "No entities with this entity_id exists or this entity is owned by someone else" });
    } else {
      send_response(res, 404, {"Error":  "No entity (e.g. user, boat, or load) with this id exists" });
    }
  }
}).use((err, req, res, next) => {
  // if no valid JWT present, calls next middleware function (second routing with mounted function for public boats)
  if (err.name === 'UnauthorizedError') {
    send_response(res, 401, {"Error": "Unauthorized Access error, no valid JWT was provided"});
  }
});

marina.patch('/loads/:entity_id', async (req, res, next) => {
  // Updates a specific entity record in datastore based on entity type/kind and id
  try {
    const type = 'loads';
    const entity_id = req.params.entity_id;
    var entity = req.body;

    // check that entity exists
    var existing_entity = await get_entity(req, type, entity_id);

    // check valid mime type
    if(req.get('Content-Type') !== 'application/json'){
      send_response(res, 415, {"Error":  "The request object contains data in an unsupported media type"});
      return;
    }

    // Check if any of the required inputs are missing or have invalid values
    if (!has_attributes(req, type) || !has_valid_request_values(entity, type)) {
      send_response(res, 400, {"Error": "The request object is missing at least one of the required attributes or provides an invalid attribute value."});
      return;
    }

    // Ensures entity has all required parameters and maintains existing relationships
    entity = create_entity(type, entity, existing_entity);

    // Send update query to datastore and update json objects for desired attributes
    entity = await update_entity(req, type, entity_id, entity);

    // Generate html response with formatted json objects
    res.location(entity.self);
    send_response(res, 200, JSON.stringify(entity, ["id", "volume", "content", "creation_date", "carrier", "id", "name", "self", "self"], 1));
  
  // error handling
  } catch (error) {
    send_response(res, 404, {"Error": "No entity (e.g. user, boat, or load) with this id exists"});
  }
});

marina.delete('/boats/:entity_id', checkJwt, async (req, res, next) => {
  const type = 'boats';
  const entity_id = req.params.entity_id

  // Delete an entity record that is stored in the database based on type and id
  try {
    const entity = await get_entity(req, type, req.params.entity_id);

    // check that entity is owned by request bearer
    if (entity.owner != req.user.sub){
      throw new Error('Entity has a different owner than provided token_id');
    }

    // specific case for deleting boat entities - removes all loads from boat
    // for each load on a boat, get load, update carrier to null
    var boat = await get_entity(req, 'boats', entity_id);

    boat.loads.forEach(function(boat_load) {
      var key = remove_relationship(req, 'loads', boat_load.id);
    });

    // find owner's user entity and remove boat from their list
    var users = await get_entities(req, 'users');
    users.forEach(function(user) {
      if (user.auth0_id == req.user.sub){
        var index = user.boats.findIndex(user_boat => user_boat.id==boat.id);
        user.boats.splice(index, 1);
        var key = update_entity(req, 'users', user.id, user);
      }
    });

    // send delete query to datastore and responds if no records are deleted
    var apiResponse = await delete_entity(type, req.params.entity_id);
    
    // check if boat was deleted (or if any indexes were updated)
    if (apiResponse[0].indexUpdates == 0) {
      throw new Error('No entities found with that entity ID');
    }
    res.status(204).end();

  // error handling
  } catch (error) {
    send_response(res, 403, {"Error": "No entities with this entity_id exists or this entity is owned by someone else"});
  }
}).use((err, req, res, next) => {
  // if no valid JWT present, calls next middleware function (second routing with mounted function for public boats)
  if (err.name === 'UnauthorizedError') {
    send_response(res, 401, {"Error": "Unauthorized Access error, no valid JWT was provided"});
  }
});

marina.delete('/loads/:entity_id', async (req, res, next) => {
  const type = 'loads';
  const entity_id = req.params.entity_id

  // Delete an entity record that is stored in the database based on type and id
  try {
    const entity = await get_entity(req, type, req.params.entity_id);

    // specific case for deleting load entities - removes from carrier boats
    var load = await get_entity(req, 'loads', entity_id);
    if (load.carrier != null){
      var boat = await get_entity(req, 'boats', load.carrier.id);
      // update boat of the removal of load
      var index = boat.loads.findIndex(boat_load => boat_load.id==load.id);
      boat.loads.splice(index, 1);
      var key = update_entity(req, 'boats', boat.id, boat);
    }

    // send delete query to datastore and responds if no records are deleted
    var apiResponse = await delete_entity(type, req.params.entity_id);
    
    // check if boat was deleted (or if any indexes were updated)
    if (apiResponse[0].indexUpdates == 0) {
      throw new Error('No entities found with that entity ID');
    }
    res.status(204).end();

  // error handling
  } catch (error) {
    send_response(res, 403, {"Error": "No entities with this entity_id exists or this entity is owned by someone else"});
  }
})

// manage relationships between loads and boats (e.g. create(put) or delete relationship)
marina.put('/boats/:boat_id/loads/:load_id', async (req, res, next) => {
  // Adds a boat entity to a slip, essentially docking a boat to a slip
  try {
    var load_id = req.params.load_id;
    var boat_id = req.params.boat_id;

    // check if provided boat_id exist and create boat_data object to store in load
    var boat = await get_entity(req, "boats", boat_id);
    var boat_data = {};
    boat_data.id = boat[datastore.KEY].id;
    boat_data.name = boat.name;

    // check if provided load_id exist and create load_data object to store in boat
    var load = await get_entity(req, 'loads', load_id);
    var load_data = { "id" : load.id };

    // check if load has a carrier value
    if (load.carrier != null){
      send_response(res, 403, {"Error": "The load is already on another boat"});
      return;
    // update load and boat entities with the new relationship (adds load to boat and carrier to load)
    } else {
      load.carrier = boat_data;
      await update_entity(req, 'loads', load_id, load);
      boat.loads.push(load_data);
      await update_entity(req, 'boats', boat_id, boat);
      res.status(204).end();
    }
  
  // error handling
  } catch (error) {
    send_response(res, 404, {"Error": "The specified boat and/or load does not exist"});
  }
});

marina.delete('/boats/:boat_id/loads/:load_id', async (req, res, next) => {  
  // Removes a boat entity from a slip entity, undocking the boat from the slip
  try {
    var load_id = req.params.load_id;
    var boat_id = req.params.boat_id;

    // check if provided boat_id exist
    var boat = await get_entity(req, "boats", boat_id);

    // check if provided slip_id exist
    var load = await get_entity(req, "loads", load_id);

    // check if the provided load is on the provided boat
    if (load.carrier.id == boat.id){
      // check if boat has a load with matching id
      boat.loads.forEach(function(boat_load) {
        if (boat_load.id == load.id){
          // update load current carrier to null value
          load.carrier = null;
          update_entity(req, 'loads', load_id, load);

          // update boat of the removal of load
          var index = boat.loads.findIndex(boat_load => boat_load.id==load_id);
          boat.loads.splice(index, 1);
          update_entity(req, 'boats', boat_id, boat);          
          res.status(204).end();
        }
      });

    // if false, return failure message
    } else {
      send_response(res, 404, {"Error": "No load with this load_id is on the boat with this boat_id" });
      return;
    }
  
  // error handling
  } catch (error) {
    send_response(res, 404, {"Error": "No load with this load_id is on the boat with this boat_id"});
  }
});

// Handling invalid requests to root folder / address - Sends 405 with list of accepted requests
marina.delete('/:type', function (req, res){
  res.set('Accept', 'GET, POST');
  res.status(405).end();
});
marina.put('/:type', function (req, res){
  res.set('Accept', 'GET, POST');
  res.status(405).end();
});

/* ------------- End Controller Functions ------------- */

app.use('/auth', auth);
app.use('/marina', marina);


const PORT = process.env.PORT || 8080;
app.listen(process.env.PORT || 8080, () => {
  console.log(`App listening on port ${PORT}`);
  console.log('Press Ctrl+C to quit.');
});