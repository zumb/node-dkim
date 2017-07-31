var assert = require( 'assert' )
var DKIM = require( '..' )
var dns = require('dns');

describe( 'DKIM', function() {

  describe( '.getKey()', function() {

    context( 'when key record exists', function() {

      it( 'parse & return the key', function( done ) {
        dns.resolve = function(domain, type, callback) {
          callback(null, ["k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDYFnr/FncHM2LkH7CgK4/9FWdpb+XHMaQ11vOfbD9hmhZgYtNOu8cQhECD0j8MpSwPELll3zz+jxEaAJnej5RJpqcWv4N1TbZ/kRItE1jQ8HiLhlQcVibuetcXiYD0sRccbAwNgQ9XVTf0FhH3Ek7ABkz8PCZaebWvFsNlqNWqxwIDAQAB"]);
        };
        DKIM.getKey( 'gmail.com', '20120113', function( error, key ) {
          assert.ifError( error )
          assert.equal( key instanceof DKIM.Key, true )
          assert.equal( key.type, 'rsa' )
          done()
        })
      })

    })

    context( 'when key record does not exist', function() {

      it( 'PERMFAIL if domain has no record', function( done ) {
        dns.resolve = function(domain, type, callback) {
          callback({ code: dns.NOTFOUND}, null);
        };
        DKIM.getKey( 'aa', function( error, key ) {
          assert.equal( key, null )
          assert.equal( error instanceof Error, true )
          assert.equal( error.code, DKIM.PERMFAIL )
          done()
        })
      })

      it( 'PERMFAIL if TXT record is not a valid key', function( done ) {
        dns.resolve = function(domain, type, callback) {
          callback(null, ['invalid']);
        };
        DKIM.getKey( 'gmail.com', function( error, key ) {
          assert.ok( key != null, 'key not present' )
          assert.equal( error instanceof Error, true )
          assert.equal( error.code, DKIM.PERMFAIL )
          done()
        })
      })

      it( 'TEMPFAIL if query fails to respond', function(done) {
        dns.resolve = function(domain, type, callback) {
          callback({code: dns.TIMEOUT }, null);
        };
        DKIM.getKey( 'gmail.com', function( error, key ) {
          assert.equal( error instanceof Error, true )
          assert.equal( error.code, DKIM.TEMPFAIL )
          done()
        })
      })

    })

  })

})
