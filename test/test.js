'use strict';
var sechash = require('../lib/sechash');
var assert = require('assert');

describe('sechash', function() {
	describe('basic', function() {
		var FIXTURES = [{
			algorithm: "sha1",
			hash: "0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33"
		}, {
			algorithm: "md5",
			hash: "acbd18db4cc2f85cedef654fccc4a4d8"
		}, {
			algorithm: "sha256",
			hash: "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
		}, {
			algorithm: "sha512",
			hash: "f7fbba6e0636f890e56fbbf3283e524c6fa3204ae298382d624741d0dc6638326e282c41be5e4254d8820772c5518a2c5a8c0c7f7eda19594a7eb539453e1ed7"
		}];

		FIXTURES.forEach(function(fixture) {
			describe(fixture.algorithm, function() {
				it('basicHash should hash', function() {
					var basicHash = sechash.basicHash(fixture.algorithm, 'foo');

					assert.strictEqual(basicHash, fixture.hash);
				});

				it('testBasicHash should pass', function() {
					var result = sechash.testBasicHash(fixture.algorithm, 'foo', fixture.hash);

					assert.strictEqual(result, true);
				});

				it('testBasicHash should fail', function() {
					var result = sechash.testBasicHash(fixture.algorithm, 'bar', fixture.hash);

					assert.strictEqual(result, false);
				});

			});
		});
	});

	describe('strong', function() {
		var FIXTURES = [{
			algorithm: "sha1",
			hash: "0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33"
		}, {
			algorithm: "md5",
			hash: "acbd18db4cc2f85cedef654fccc4a4d8"
		}, {
			algorithm: "sha256",
			hash: "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
		}, {
			algorithm: "sha512",
			hash: "f7fbba6e0636f890e56fbbf3283e524c6fa3204ae298382d624741d0dc6638326e282c41be5e4254d8820772c5518a2c5a8c0c7f7eda19594a7eb539453e1ed7"
		}];

		describe('sync', function() {
			FIXTURES.forEach(function(fixture) {
				describe(fixture.algorithm, function() {

					it('using default options', function() {
						var opts = {
							algorithm: fixture.algorithm
						};

						var string = 'Your String';
						var hash = sechash.strongHashSync(string);
						assert.strictEqual(sechash.testHashSync(string, hash), true);
						assert.strictEqual(sechash.testHashSync(string, hash + '1'), false);
						assert.strictEqual(sechash.testHashSync(string, '1' + hash), false);
						assert.strictEqual(sechash.testHashSync('Another string', hash), false);
					});

					it('using non-default options', function() {
						var opts = {
					    algorithm: fixture.algorithm,
					    iterations: 2000,
					    salt: 'some salt string'
						};

						var string = 'Your String';
						var hash = sechash.strongHashSync(string);
						assert.strictEqual(sechash.testHashSync(string, hash), true);
						assert.strictEqual(sechash.testHashSync(string, hash + '1'), false);
						assert.strictEqual(sechash.testHashSync(string, '1' + hash), false);
						assert.strictEqual(sechash.testHashSync('Another string', hash), false);
					});

				});
			});
		});

		describe('callback-based', function() {
			FIXTURES.forEach(function(fixture) {
				describe(fixture.algorithm, function() {

					function performCallbackTests(opts, done) {
						var string = 'Your String';
						sechash.strongHash(string, function(err, hash) {
							if (err) return done(err);

							sechash.testHash(string, hash, function(err, result) {
								if (err) return done(err);

								assert.strictEqual(result, true);

								sechash.testHash(string, hash + '1', function(err, result) {
									if (err) return done(err);

									assert.strictEqual(result, false);

									sechash.testHash(string, '1' + hash, function(err, result) {
										if (err) return done(err);

										assert.strictEqual(result, false);

										sechash.testHash('Another string', hash, function(err, result) {
											if (err) return done(err);

											assert.strictEqual(result, false);

											done();
										});

									});

								});
							})
						});
					}

					it('using default options', function(done) {
						var opts = {
							algorithm: fixture.algorithm
						};

						return performCallbackTests(opts, done);
					});

					it('using default options', function(done) {
						var opts = {
							algorithm: fixture.algorithm,
							iterations: 2000,
							salt: 'some salt string'
						};

						return performCallbackTests(opts, done);
					});

					it('includeMeta on', function(done) {
						var opts = {
							algorithm: fixture.algorithm,
							includeMeta: true
						};

						return performCallbackTests(opts, done);
					});

					it('includeMeta off', function(done) {
						var opts = {
							algorithm: fixture.algorithm,
							includeMeta: false
						};

						return performCallbackTests(opts, done);
					});
				});
			});
		});

	});

});
