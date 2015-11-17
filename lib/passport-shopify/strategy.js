/**
 * Module dependencies.
 */

var _ = require('lodash');
var querystring = require('querystring');
var uid = require('uid2');
var url = require('url');
var util = require('util');
var utils = require('./utils');
var OAuth2 = require('oauth').OAuth2;
var OAuth2Strategy = require('passport-oauth').OAuth2Strategy;
var AuthorizationError = require('passport-oauth').AuthorizationError;
var InternalOAuthError = require('passport-oauth').InternalOAuthError;

function Strategy(options, verify) {

  options = options || {}

  options.subdomain = options.shop || 'www';

  _.defaults(options, {
    authorizationURL: 'https://' + options.subdomain + '.myshopify.com/admin/oauth/authorize',
    tokenURL: 'https://' + options.subdomain + '.myshopify.com/admin/oauth/access_token',
    userAgent: 'passport-shopify',
    customHeaders: {},
    scopeSeparator: ','
  });
  _.defaults(options.customHeaders, {
    'User-Agent': options.userAgent
  });

  OAuth2Strategy.call(this, options, verify);
  this._options = options;
  this.name = 'shopify';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

/**
 * Cache a separate OAuth2 client for each zendesk subdomain
 */
Strategy.prototype._oauth2Map = {};
Strategy.prototype._createOauth2 = function(clientId, clientSecret, baseSite, authorizePath, accessTokenPath, customHeaders) {
  return new OAuth2(clientId, clientSecret, baseSite, authorizePath, accessTokenPath, customHeaders);
};
Strategy.prototype._oauth2ForSubdomain = function(subdomain) {
  var options = this._options;
  var baseUrl = '';
  var authorizationURL = 'https://' + subdomain + '.myshopify.com/admin/oauth/authorize';
  var tokenURL = 'https://' + subdomain + '.myshopify.com/admin/oauth/access_token';

  if (!this._oauth2Map[subdomain]) {
    this._oauth2Map[subdomain] = this._createOauth2(
      options.clientID,
      options.clientSecret,
      baseUrl,
      authorizationURL,
      tokenURL,
      options.customHeaders);
  }

  return this._oauth2Map[subdomain];
};

/**
 * Authenticate request by delegating to Shopify using OAuth 2.0.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  if (req.query && req.query.error) {
    if (req.query.error === 'access_denied') {
      return this.fail({ message: req.query.error_description });
    } else {
      return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
    }
  }

  options = options || {};
  var self = this;
  var bodyObj = req.body && querystring.parse(req.body);

  // Look for the subdomain to be specified in (in order of priority):
  //   1. authenticate options
  //   2. query string
  //   3. post body
  //   4. saved in the req.session from a previous request
  //   5. specified in strategy options
  // Additionally, cases 1,2,3 override 4 and 5
  var subdomain = options.subdomain ||
                  (req.query && req.query.subdomain) ||
                  (bodyObj && bodyObj.subdomain);

  if (subdomain) {
    if (req.session) {
      req.session.subdomain = subdomain;
    }
  } else {
    if (req.session && req.session.subdomain) {
      subdomain = req.session.subdomain;
    } else {
      subdomain = this._options.subdomain;
    }
  }

  if (!subdomain) {
    return this.error(
      new Error('A Shopify subdomain was not specified in options and was not found in request parameters')
    );
  }

  var oauth2 = this._oauth2ForSubdomain(subdomain);

  var callbackURL = options.callbackURL || this._callbackURL;
  if (callbackURL) {
    var parsed = url.parse(callbackURL);
    if (!parsed.protocol) {
      // The callback URL is relative, resolve a fully qualified URL from the
      // URL of the originating request.
      callbackURL = url.resolve(utils.originalURL(req, { proxy: this._trustProxy }), callbackURL);
    }
  }

  if (req.query && req.query.code) {
    var code = req.query.code;

    if (this._state) {
      if (!req.session) {
        return this.error(new Error('OAuth2Strategy requires session support when using state.' +
                                    ' Did you forget app.use(express.session(...))?'));
      }

      var key = this._key;
      if (!req.session[key]) {
        return this.fail({ message: 'Unable to verify authorization request state.' }, 403);
      }
      var state = req.session[key].state;
      if (!state) {
        return this.fail({ message: 'Unable to verify authorization request state.' }, 403);
      }

      delete req.session[key].state;
      if (Object.keys(req.session[key]).length === 0) {
        delete req.session[key];
      }

      if (state !== req.query.state) {
        return this.fail({ message: 'Invalid authorization request state.' }, 403);
      }
    }

    var params = this.tokenParams(options);
    params.grant_type = 'authorization_code';
    params.redirect_uri = callbackURL;

    oauth2.getOAuthAccessToken(code, params,
      function(err, accessToken, refreshToken, params) {
        if (err) { return self.error(self._createOAuthError('Failed to obtain access token', err)); }

        self._loadUserProfile(accessToken, subdomain, function(err, profile) {
          if (err) { return self.error(err); }

          function verified(err, user, info) {
            if (err) { return self.error(err); }
            if (!user) { return self.fail(info); }
            self.success(user, info);
          }

          try {
            if (self._passReqToCallback) {
              var arity = self._verify.length;
              if (arity === 6) {
                self._verify(req, accessToken, refreshToken, params, profile, verified);
              } else { // arity == 5
                self._verify(req, accessToken, refreshToken, profile, verified);
              }
            } else {
              var arity = self._verify.length;
              if (arity === 5) {
                self._verify(accessToken, refreshToken, params, profile, verified);
              } else { // arity == 4
                self._verify(accessToken, refreshToken, profile, verified);
              }
            }
          } catch (ex) {
            return self.error(ex);
          }
        });
      }
    );
  } else {
    var params = this.authorizationParams(options);
    params.response_type = 'code';
    params.redirect_uri = callbackURL;
    var scope = options.scope || this._scope;
    if (scope) {
      if (Array.isArray(scope)) { scope = scope.join(this._scopeSeparator); }
      params.scope = scope;
    }
    var state = options.state;
    if (state) {
      params.state = state;
    } else if (this._state) {
      if (!req.session) {
        return this.error(new Error('OAuth2Strategy requires session support when using state.' +
                                    ' Did you forget app.use(express.session(...))?'));
      }

      var key = this._key;
      state = uid(24);
      if (!req.session[key]) { req.session[key] = {}; }
      req.session[key].state = state;
      params.state = state;
    }

    var location = oauth2.getAuthorizeUrl(params);
    this.redirect(location);
  }
};

/**
 * Load user profile, contingent upon options.
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api private
 */
Strategy.prototype._loadUserProfile = function(accessToken, subdomain, done) {
  var self = this;

  function loadIt() {
    return self.userProfile(accessToken, subdomain, done);
  }
  function skipIt() {
    return done(null);
  }

  if (_.isFunction(this._skipUserProfile) && this._skipUserProfile.length > 1) {
    // async
    this._skipUserProfile(accessToken, function(err, skip) {
      if (err) { return done(err); }
      if (!skip) { return loadIt(); }
      return skipIt();
    });
  } else {
    var skip = _.isFunction(this._skipUserProfile) ? this._skipUserProfile() : this._skipUserProfile;
    if (!skip) { return loadIt(); }
    return skipIt();
  }
};

/**
 * Retrieve user profile from Shopify.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `shopify`
 *   - `id`               the user's Shopify ID
 *   - `username`         the user's Shopify store name
 *   - `displayName`      the user's full name
 *   - `profileUrl`       the URL of the profile for the user on Shopify
 *   - `emails`           the user's email address, only returns emails[0]
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, subdomain, done) {
  this._oauth2.get('https://' + subdomain + '.myshopify.com/admin/shop.json', accessToken, function (err, body, res) {
    if (err)
      return done(new InternalOAuthError('failed to fetch user profile', err));
    try {
      var json = JSON.parse(body);
      var profile = { provider: 'shopify' };
      profile.id = json.shop.id;
      profile.displayName = json.shop.shop_owner;
      profile.username = json.shop.name;
      profile.profileUrl = json.shop.domain;
      profile.emails = [
        {
          value: json.shop.email
        }
      ];
      profile._raw = body;
      profile._json = json;
      done(null, profile);
    } catch(e) {
      done(e);
    }
  });
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
