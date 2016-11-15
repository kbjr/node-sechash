'use strict';

/**
 * sechash
 *
 * Secure password hashing using salt and keystretching
 *
 * @author     James Brumond
 * @version    0.2.0
 * @copyright  Copyright 2012 James Brumond
 * @license    Dual licensed under MIT and GPL
 */

var crypto  = require('crypto');
var Promise = require('any-promise');

var defaultOptions = {
	algorithm: 'sha1',
	iterations: 2000,
	includeMeta: true,
	intervalLength: 500,
	salt: function() {
		return hash(this.algorithm, String(Math.random())).substring(0, 6);
	}
};

// ----------------------------------------------------------------------------
//  Public functions

exports.basicHash = function(alg, str) {
	return hash(alg, str);
};

exports.testBasicHash = function(alg, str, testHash) {
	return (hash(alg, str) === testHash);
};

exports.strongHashSync = function(str, opts) {
	opts = getOptions(opts);
	for (var i = 0; i < opts.iterations; i++) {
		str = hash(opts.algorithm, str + opts.salt);
	}
	return opts.meta + str;
};

exports.strongHash = function(str, opts, callback) {
	if (typeof opts === 'function') {
		callback = opts;
		opts = null;
	}
	opts = getOptions(opts);

	var promise = new Promise(function(resolve, reject) {
		asyncFor(opts.iterations, opts.intervalLength,
			function() {
				str = hash(opts.algorithm, str + opts.salt);
			},
			function() {
				resolve(opts.meta + str)
			}
		);
	});

	return asCallback(promise, callback);
};

exports.testHashSync = function(str, hash, opts) {
	opts = getOptions(opts, hash);
	return (exports.strongHashSync(str, opts) === hash);
};

exports.testHash = function(str, hash, opts, callback) {
	if (typeof opts === 'function') {
		callback = opts;
		opts = null;
	}
	opts = getOptions(opts, hash);

	var promise = new Promise(function(resolve, reject) {
		exports.strongHash(str, opts, function(err, result) {
			if (err) return reject(err);
			resolve(hash === result);
		});
	});

	return asCallback(promise, callback);
};



// ------------------------------------------------------------------
//  Helpers
function asCallback(promise, callback) {
	if (typeof callback !== 'function') return promise;

	return promise.then(function(result) {
		callback(null, result);
	}, function(reason) {
		callback(reason);
	});
}

function hash(alg, str) {
	var hashsum = crypto.createHash(alg);
	hashsum.update(str);
	return hashsum.digest('hex');
}

function getOptions(opts, hash) {
	var result = { };
	Object.keys(defaultOptions).forEach(function(key) {
		result[key] = defaultOptions[key];
	});
	Object.keys(opts || { }).forEach(function(key) {
		result[key] = opts[key];
	});
	if (typeof result.salt === 'function') {
		result.salt = result.salt();
	}
	if (result.includeMeta) {
		result.meta = result.salt + ':' + result.algorithm + ':' + result.iterations + ':'
	} else {
		result.meta = '';
	}
	if (hash && hash.indexOf(':') >= 0) {
		hash = hash.split(':');
		result.salt = hash[0];
		result.algorithm = hash[1];
		result.iterations = Number(hash[2]);
	}
	return result;
}

function asyncFor(count, intervalLength, func, callback) {
	function runLoop() {
		for (var i = 0; (i < intervalLength && count); i++, count--) {
			func(count, i);
		}
		if (count) {
			process.nextTick(runLoop);
		} else {
			callback();
		}
	}
	runLoop();
}

/* End of file sechash.js */
