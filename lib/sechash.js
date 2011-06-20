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
	 * Hash a string with salt and key stretching
	 *
	 * @access  public
	 * @param   string    the hashing algorithm
	 * @param   string    the string to hash
	 * @param   string    the salt value
	 * @param   number    the number of hash iterations
	 * @return  string
	 */
	self.strongHash = function(algorithm, str, salt, iterations) {
		// Default the optional arguments
		if (salt == null) {
			salt = hash(algorithm, String(Math.random())).substring(0, 3);
		}
		if (iterations == null) {
			iterations = Math.round(Math.random() * 9000) + 1000;
		}
		// Do the hashing
		var result = str;
		for (var i = 0; i < iterations; i++) {
			result = hash(algorithm, result + salt);
		}
		// Build the final result
		return salt + ':' + algorithm + ':' + iterations + ':' + result;
	};
	
	/**
	 * Test if a string matches a given hash
	 *
	 * @access  public
	 * @param   string    the string to test
	 * @param   string    the hash to test against
	 * @return  boolean
	 */
	self.testHash = function(str, testHash) {
		var data = testHash.split(':');
		// Check for a 4 segment hash
		if (data.length !== 4) {
			throw new Error('Invalid hash string given');
		}
		// Test the hash
		data[2] = Number(data[2]);
		return (self.strongHash(str, data[0], data[1], data[2]) === testHash);
	};
	
// ----------------------------------------------------------------------------
//  A simple automated test function
	
	self._test = function() {
		var startTime = now();
		
		var startingString = 'Hello World';
		console.log('Original String: "' + startingString + '"');
		
		var hash = self.strongHash(startingString);
		console.log('Hashed String: "' + hash + '"');
		
		var result = self.testHash(startingString, hash);
		console.log('Hash Test Successful: ' + result);
		
		console.log('Time to Run: ' + (now() - startTime) + 'ms');
		
		function now() {
			return (new Date()).getTime();
		}
	};
	
	return self;
}());
