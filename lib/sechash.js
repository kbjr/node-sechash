/**
 * sechash
 *
 * Secure password hashing using salt and keystretching
 *
 * @author     James Brumond
 * @version    0.1.2
 * @copyright  Copyright 2011 James Brumond
 * @license    Dual licensed under MIT and GPL
 */
module.exports = (function() {
	var self = { };
	
	// Load the native encryption library
	var crypto = require('crypto');
	
	// Low-level hashing utility
	var hash = function(alg, str) {
		var hashsum = crypto.createHash(alg);
		// Add the string data
		hashsum.update(str);
		return hashsum.digest('hex');
	};
	
	// Defaults optional arguments for strongHash(Sync)
	var getOptions = function(algorithm, salt, iterations) {
		if (salt == null) {
			salt = hash(algorithm, String(Math.random())).substring(0, 6);
		}
		if (iterations == null) {
			iterations = 3000;
		}
		return {
			salt: salt,
			iterations: iterations
		};
	};

// ----------------------------------------------------------------------------
//  Public functions
	
	/**
	 * Hash a string
	 *
	 * @access  public
	 * @param   string    the hashing algorithm
	 * @param   string    the string to hash
	 * @return  string
	 */
	self.basicHash = function(alg, str) {
		return hash(alg, str);
	};
	
	/**
	 * Test a simple hash
	 *
	 * @access  public
	 * @param   string    the hashing algorithm
	 * @param   string    the string to test
	 * @param   string    the hash to test
	 * @return  boolean
	 */
	self.testBasicHash = function(alg, str, testHash) {
		return (hash(alg, str) === testHash);
	};
	
	/**
	 * Hash a string with salt and key stretching
	 *
	 * @access  public
	 * @param   string    the hashing algorithm
	 * @param   string    the string to hash
	 * @param   string    the salt value
	 * @param   number    the number of hash iterations
	 * @return  string
	 */
	self.strongHashSync = function(algorithm, str, salt, iterations) {
		var opts = getOptions(algorithm, salt, iterations);
		// Do the hashing
		for (var i = 0; i < opts.iterations; i++) {
			str = hash(algorithm, str + opts.salt);
		}
		// Build the final result
		return opts.salt + ':' + algorithm + ':' + opts.iterations + ':' + str;
	};
	
	/**
	 * Hash a string with salt and key stretching
	 *
	 * @access  public
	 * @param   string    the hashing algorithm
	 * @param   string    the string to hash
	 * @param   string    the salt value
	 * @param   number    the number of hash iterations
	 * @param   function  the callback
	 * @return  void
	 */
	self.strongHash = function(algorithm, str, salt, iterations, after) {
		// Handle shorthand execution
		if (typeof salt === 'function') {
			after = salt;
			salt = null;
		}
		if (typeof iterations === 'function') {
			after = iterations;
			iterations = null;
		}
		// Check for a callback
		if (typeof after !== 'function') {
			throw new TypeError('No valid callback given');
		}
		// Generate any missing params
		var opts = getOptions(algorithm, salt, iterations);
		// Do the hashing
		var count = opts.iterations;
		function runHashingLoop() {
			for (var i = 0; (i < 500 && count > 0); i++, count--) {
				str = hash(algorithm, str + opts.salt);
			}
			// Continue after a short while if there is more left
			if (count > 0) {
				process.nextTick(runHashingLoop);
			}
			// Otherwise, finish up
			else {
				after(null, opts.salt + ':' + algorithm + ':' + opts.iterations + ':' + str);
			}
		}
		runHashingLoop();
	};
	
	/**
	 * Test if a string matches a given hash
	 *
	 * @access  public
	 * @param   string    the string to test
	 * @param   string    the hash to test against
	 * @return  boolean
	 */
	self.testHashSync = function(str, testHash) {
		var data = testHash.split(':');
		// Check for a 4 segment hash
		if (data.length !== 4) {
			throw new Error('Invalid hash string given');
		}
		// Test the hash
		data[2] = Number(data[2]);
		return (self.strongHashSync(data[1], str, data[0], data[2]) === testHash);
	};
	
	/**
	 * Test if a string matches a given hash
	 *
	 * @access  public
	 * @param   string    the string to test
	 * @param   string    the hash to test against
	 * @param   function  the callback
	 * @return  void
	 */
	self.testHash = function(str, testHash, after) {
		var data = testHash.split(':');
		// Check for a 4 segment hash
		if (data.length !== 4) {
			after(new Error('Invalid hash string given'), null);
		}
		// Test the hash
		data[2] = Number(data[2]);
		self.strongHash(data[1], str, data[0], data[2], function(err, hashStr) {
			if (err) {
				after(err, null);
			} else {
				after(null, (hashStr === testHash));
			}
		});
	};
	
// ----------------------------------------------------------------------------
//  Simple automated test functions
	
	self._testSync = function() {
		var startTime = now();
		
		var startingString = 'Hello World';
		console.log('Original String: "' + startingString + '"');
		
		var hash = self.strongHashSync('md5', startingString);
		console.log('Hashed String: "' + hash + '"');
		
		console.log('Time to Run: ' + (now() - startTime) + 'ms');
		
		function now() {
			return (new Date()).getTime();
		}
	};
	
	self._testAsync = function() {
		var startTime = now();
		
		var startingString = 'Hello World';
		console.log('Original String: "' + startingString + '"');
		
		self.strongHash('md5', startingString, function(err, hash) {
			console.log('Hashed String: "' + hash + '"');
			
			console.log('Time to Run: ' + (now() - startTime) + 'ms');
		});
		
		function now() {
			return (new Date()).getTime();
		}
	};
	
	return self;
}());
