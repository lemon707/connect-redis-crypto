/*!
 * Connect - Redis
 * Copyright(c) 2012 TJ Holowaychuk <tj@vision-media.ca>
 * MIT Licensed
 */

/**
 * Module dependencies.
 */

var debug = require('debug')('connect:redis');
var crypto = require('crypto');
var debug = require('debug')('connect:redis');
var redis = require('redis');
var default_port = 6379;
var default_host = '127.0.0.1';
var noop = function(){};

/**
 * One day in seconds.
 */

var oneDay = 86400;

/**
 * Return the `RedisStore` extending `express`'s session Store.
 *
 * @param {object} express session
 * @return {Function}
 * @api public
 */

module.exports = function (session) {

  /**
   * Express's session Store.
   */

  var Store = session.Store;

  crypto.DEFAULT_ENCODING = 'hex';

  /**
   * Initialize RedisStore with the given `options`.
   *
   * @param {Object} options
   * @api public
   */

  function RedisStore (options) {
    var self = this;

    options = options || {};
    Store.call(this, options);
    this.prefix = options.prefix == null
      ? 'sess:'
      : options.prefix;

    /* istanbul ignore next */
    if (options.url) {
      console.error('Warning: "url" param is deprecated and will be removed in a later release: use redis-url module instead');
      var url = require('url').parse(options.url);
      if (url.protocol === 'redis:') {
        if (url.auth) {
          var userparts = url.auth.split(':');
          options.user = userparts[0];
          if (userparts.length === 2) {
            options.pass = userparts[1];
          }
        }
        options.host = url.hostname;
        options.port = url.port;
        if (url.pathname) {
          options.db = url.pathname.replace('/', '', 1);
        }
      }
    }

    // convert to redis connect params
    if (options.client) {
      this.client = options.client;
    }
    else if (options.socket) {
      this.client = redis.createClient(options.socket, options);
    }
    else if (options.port || options.host) {
      this.client = redis.createClient(
        options.port || default_port,
        options.host || default_host,
        options
      );
    }
    else {
      this.client = redis.createClient(options);
    }

    if (options.pass) {
      this.client.auth(options.pass, function (err) {
        if (err) {
          throw err;
        }
      });
    }

    this.ttl = options.ttl;
    this.disableTTL = options.disableTTL;

    this.secret = options.secret || false;
    this.algorithm = options.algorithm || false;

    if (options.unref) this.client.unref();

    if ('db' in options) {
      if (typeof options.db !== 'number') {
        console.error('Warning: connect-redis expects a number for the "db" option');
      }

      self.client.select(options.db);
      self.client.on('connect', function () {
        self.client.send_anyways = true;
        self.client.select(options.db);
        self.client.send_anyways = false;
      });
    }

    self.client.on('error', function () {
      self.emit('disconnect');
    });

    self.client.on('connect', function () {
      self.emit('connect');
    });
  }

  /**
   * Wrapper to create cipher text, digest & encoded payload
   *
   * @param {String} payload
   * @api private
   */

  function encryptData(plaintext){
    var pt = encrypt(this.secret, plaintext, this.algo)
      , hmac = digest(this.secret, pt)

    return {
      ct: pt,
      mac: hmac
    };
  }

  /**
   * Wrapper to extract digest, verify digest & decrypt cipher text
   *
   * @param {String} payload
   * @api private
   */

  function decryptData(ciphertext){
    ciphertext = JSON.parse(ciphertext)
    var hmac = digest(this.secret, ciphertext.ct);

    if (hmac != ciphertext.mac) {
      throw 'Encrypted session was tampered with!';
    }

    return decrypt(this.secret, ciphertext.ct, this.algo);
  }

    /**
   * Generates HMAC as digest of cipher text
   *
   * @param {String} key
   * @param {String} obj
   * @param {String} algo
   * @api private
   */

  function digest(key, obj) {
    var hmac = crypto.createHmac('sha1', key);
    hmac.setEncoding('hex');
    hmac.write(obj);
    hmac.end();
    return hmac.read();
  }

  /**
   * Creates cipher text from plain text
   *
   * @param {String} key
   * @param {String} pt
   * @param {String} algo
   * @api private
   */

  function encrypt(key, pt, algo) {
    algo = algo || 'aes-256-ctr';
    pt = (Buffer.isBuffer(pt)) ? pt : new Buffer(pt);

    var cipher = crypto.createCipher(algo, key)
      , ct = [];

    ct.push(cipher.update(pt));
    ct.push(cipher.final('hex'));

    return ct.join('');
  }

  /**
   * Creates plain text from cipher text
   *
   * @param {String} key
   * @param {String} pt
   * @param {String} algo
   * @api private
   */

  function decrypt(key, ct, algo) {
    algo = algo || 'aes-256-ctr';
    var cipher = crypto.createDecipher(algo, key)
      , pt = [];

    pt.push(cipher.update(ct, 'hex', 'utf8'));
    pt.push(cipher.final('utf8'));

    return pt.join('');
  }

  /**
   * Inherit from `Store`.
   */

  RedisStore.prototype.__proto__ = Store.prototype;

  /**
   * Attempt to fetch session by the given `sid`.
   *
   * @param {String} sid
   * @param {Function} fn
   * @api public
   */

  RedisStore.prototype.get = function (sid, fn) {
    var store = this;
    var psid = store.prefix + sid;
    if (!fn) fn = noop;
    debug('GET "%s"', sid);
    secret = this.secret || false;

    store.client.get(psid, function (er, data) {
      if (!data) return fn();

      var result;
      data = (secret) ? decryptData.call(this, data) : data.toString();
      debug('GOT %s', data);

      try {
        result = JSON.parse(data);
      }
      catch (er) {
        return fn(er);
      }
      return fn(null, result);
    });
  };

  /**
   * Commit the given `sess` object associated with the given `sid`.
   *
   * @param {String} sid
   * @param {Session} sess
   * @param {Function} fn
   * @api public
   */

  RedisStore.prototype.set = function (sid, sess, fn) {
    var store = this;
    var psid = store.prefix + sid;
    if (!fn) fn = noop;

    try {
      jsess = JSON.stringify(
        (this.secret)
        ? encryptData.call(this, JSON.stringify(sess), this.secret, this.algorithm)
        : sess);
    }
    catch (er) {
      return fn(er);
    }

    if (store.disableTTL) {
      debug('SET "%s" %s', sid, jsess);
      store.client.set(psid, jsess, function (er) {
        debug('SET complete');
        fn.apply(null, arguments);
      });
      return;
    }

    var maxAge = sess.cookie.maxAge;
    var ttl = store.ttl || (typeof maxAge === 'number'
      ? maxAge / 1000 | 0
      : oneDay);

    debug('SETEX "%s" ttl:%s %s', sid, ttl, jsess);
    store.client.setex(psid, ttl, jsess, function (er) {
      debug('SETEX complete');
      fn.apply(this, arguments);
    });
  };

  /**
   * Destroy the session associated with the given `sid`.
   *
   * @param {String} sid
   * @api public
   */

  RedisStore.prototype.destroy = function (sid, fn) {
    sid = this.prefix + sid;
    debug('DEL "%s"', sid);
    this.client.del(sid, fn);
  };

  return RedisStore;
};
