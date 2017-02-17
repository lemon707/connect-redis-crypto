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
var redis = require('redis');
var util = require('util');
var noop = function(){};

/**
 * One day in seconds.
 */

var oneDay = 86400;

function getTTL(store, sess) {
  var maxAge = sess.cookie.maxAge;
  return store.ttl || (typeof maxAge === 'number'
    ? Math.floor(maxAge / 1000)
    : oneDay);
}

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
    if (!(this instanceof RedisStore)) {
      throw new TypeError('Cannot call RedisStore constructor as a function');
    }

    var self = this;

    options = options || {};
    Store.call(this, options);
    this.prefix = options.prefix == null
      ? 'sess:'
      : options.prefix;

    delete options.prefix;

    this.serializer = options.serializer || JSON;

    if (options.url) {
      options.socket = options.url;
    }

    // convert to redis connect params
    if (options.client) {
      this.client = options.client;
    }
    else if (options.socket) {
      this.client = redis.createClient(options.socket, options);
    }
    else {
      this.client = redis.createClient(options);
    }

    // logErrors
    if(options.logErrors){
      // if options.logErrors is function, allow it to override. else provide default logger. useful for large scale deployment
      // which may need to write to a distributed log
      if(typeof options.logErrors != 'function'){
        options.logErrors = function (err) {
  			  console.error('Warning: connect-redis reported a client error: ' + err);
  		  };
      }
  		this.client.on('error', options.logErrors);
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
    this.algorithm = options.algorithm || 'aes-256-ctr';
    this.hashing = options.hashing || 'sha512';
    this.encodeas = options.encodeas || 'hex';

    if (options.unref) this.client.unref();

    if ('db' in options) {
      if (typeof options.db !== 'number') {
        console.error('Warning: connect-redis expects a number for the "db" option');
      }
    }

    if (options.db) {
      self.client.select(options.db);
      self.client.on('connect', function () {
        self.client.select(options.db);
      });
    }

    self.client.on('error', function (er) {
      debug('Redis returned err', er);
      self.emit('disconnect', er);
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
    var pt = encrypt(this.secret, plaintext, this.algorithm, this.encodeas)
      , hmac = digest(this.secret, pt, this.hashing, this.encodeas);

    return {
      ct: pt,
      mac: hmac
    };
  }

  /**
   * Wrapper to extract digest, verify digest & decrypt cipher text
   *
   * @param {String} payload

   */

  function decryptData(ciphertext){
    ciphertext = JSON.parse(ciphertext)
    var hmac = digest(this.secret, ciphertext.ct, this.hashing, this.encodeas);

    if (hmac != ciphertext.mac) {
      throw 'Encrypted session was tampered with!';
    }

    return decrypt(this.secret, ciphertext.ct, this.algorithm, this.encodeas);
  }

    /**
   * Generates HMAC as digest of cipher text
   *
   * @param {String} key
   * @param {String} obj
   * @param {String} algo
   * @api private
   */

  function digest(key, obj, hashing, encodeas) {
    var hmac = crypto.createHmac(hashing, key);
    hmac.setEncoding(encodeas);
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

  function encrypt(key, pt, algo, encodeas) {
    pt = (Buffer.isBuffer(pt)) ? pt : new Buffer(pt);

    var cipher = crypto.createCipher(algo, key)
      , ct = [];

    ct.push(cipher.update(pt));
    ct.push(cipher.final(encodeas));

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

  function decrypt(key, ct, algo, encodeas) {
    var cipher = crypto.createDecipher(algo, key)
      , pt = [];

    pt.push(cipher.update(ct, encodeas, 'utf8'));
    pt.push(cipher.final('utf8'));

    return pt.join('');
  }

  /**
   * Inherit from `Store`.
   */

  util.inherits(RedisStore, Store);

  /**
   * Attempt to fetch session by the given `sid`.
   *
   * @param {String} sid
   * @param {Function} fn
   */

  RedisStore.prototype.get = function (sid, fn) {
    var store = this;
    var psid = store.prefix + sid;

    if (!fn) fn = noop;
    debug('GET "%s"', sid);

    store.client.get(psid, function (er, data) {
      if (er) return fn(er);
      if (!data) return fn();

      var result;
      data = (store.secret) ? decryptData.call(store, data) : data.toString();
      debug('GOT %s', data);

      try {
        result = store.serializer.parse(data);
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
    var args = [store.prefix + sid];
    if (!fn) fn = noop;

    try {
      var jsess = store.serializer.stringify((store.secret) ?
        encryptData.call(store, store.serializer.stringify(sess)) : sess);
    }
    catch (er) {
      return fn(er);
    }

    if (this.secret)
      jsess = encryptData.call(this, jsess, this.secret, this.algorithm);

    args.push(jsess);

    if (!store.disableTTL) {
      var ttl = getTTL(store, sess);
      args.push('EX', ttl);
      debug('SET "%s" %s ttl:%s', sid, jsess, ttl);
    } else {
      debug('SET "%s" %s', sid, jsess);
    }

    store.client.set(args, function (er) {
      if (er) return fn(er);
      debug('SET complete');
      fn.apply(null, arguments);
    });
  };

  /**
   * Destroy the session associated with the given `sid`.
   *
   * @param {String} sid
   * @api public
   */

  RedisStore.prototype.destroy = function (sid, fn) {
    debug('DEL "%s"', sid);
    if (Array.isArray(sid)) {
      var multi = this.client.multi();
      var prefix = this.prefix;
      sid.forEach(function (s) {
        multi.del(prefix + s);
      });
      multi.exec(fn);
    } else {
      sid = this.prefix + sid;
      this.client.del(sid, fn);
    }
  };

  /**
   * Refresh the time-to-live for the session with the given `sid`.
   *
   * @param {String} sid
   * @param {Session} sess
   * @param {Function} fn
   * @api public
   */

  RedisStore.prototype.touch = function (sid, sess, fn) {
    var store = this;
    var psid = store.prefix + sid;
    if (!fn) fn = noop;
    if (store.disableTTL) return fn();

    var ttl = getTTL(store, sess);

    debug('EXPIRE "%s" ttl:%s', sid, ttl);
    store.client.expire(psid, ttl, function (er) {
      if (er) return fn(er);
      debug('EXPIRE complete');
      fn.apply(this, arguments);
    });
  };

  /**
   * Fetch all sessions' ids
   *
   * @param {Function} fn
   * @api public
   */

  RedisStore.prototype.ids = function (fn) {
    var store = this;
    var pattern = store.prefix + '*';
    var prefixLength = store.prefix.length;
    if (!fn) fn = noop;

    debug('KEYS "%s"', pattern);
    store.client.keys(pattern, function (er, keys) {
      if (er) return fn(er);
      debug('KEYS complete');
      keys = keys.map(function (key) {
        return key.substr(prefixLength);
      });
      return fn(null, keys);
    });
  };


  /**
   * Fetch all sessions
   *
   * @param {Function} fn
   * @api public
   */

  RedisStore.prototype.all = function (fn) {
    var store = this;
    var pattern = store.prefix + '*';
    var prefixLength = store.prefix.length;
    if (!fn) fn = noop;

    debug('KEYS "%s"', pattern);
    store.client.keys(pattern, function (er, keys) {
      if (er) return fn(er);
      debug('KEYS complete');

      var multi = store.client.multi();

      keys.forEach(function (key) {
        multi.get(key);
      });

      multi.exec(function (er, sessions) {
        if (er) return fn(er);

        var result;
        try {
          result = sessions.map(function (data, index) {
            data = data.toString();
            data = store.serializer.parse(data);
            data.id = keys[index].substr(prefixLength);
            return data;
          });
        } catch (er) {
          return fn(er);
        }
        return fn(null, result);
      });
    });
  };

  return RedisStore;
};
