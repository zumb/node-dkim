var assert = require( 'assert' )
var DKIM = require( '..' )

describe( 'DKIM', function() {

  describe( '.processHeader()', function() {

    context( '"relaxed" method', function() {

      it( 'normalizes RFC 6376 Example 1', function() {
        var headers = [ 'A: X', 'B : Y\t\r\n\tZ  ', '' ]
        var result = DKIM.processHeader( headers, 'relaxed' )
        assert.equal( result, 'a:X\r\nb:Y Z\r\n' )
      })

    })

    context( '"simple" method', function() {

      it( 'normalizes RFC 6376 Example 2', function() {
        var headers = [ 'A: X', 'B : Y\t\r\n\tZ  ', '' ]
        var result = DKIM.processHeader( headers, 'simple' )
        assert.equal( result, headers.join( '\r\n' ) )
      })

    })

    context( 'signature use subset of headers in specific order', function () {

      it('returns only the subset', function () {
        var headers = [ 'A: X', 'B : Y', 'C:Z' ]
        var result = DKIM.processHeader( headers, ['C', 'B'], 'relaxed' )
        assert.equal(result, ['c:Z', 'b:Y'].join('\r\n'));
      })

    })

    context( 'signature uses dkim-signature header', function() {
      it('returns dkim-signature without signature', function() {
        var headers = [ 'DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=test.com;\r\n q=dns/txt; s=test; bh=JoUnmFfUn+vm4KlP33Un/omM8cqeDtMRKBn4rKaJq0U=;\r\n h=from;\r\n b=s/lCXtqmjnh6+6Cnx3Gsr3bN5LeoNcYslDDDWtMVbWR8CHO0dFhRpGE3UIjmOarQKlcT/p7gb' ]
        var result = DKIM.processHeader( headers, ['dkim-signature'], 'relaxed' )
        assert.equal(result, 'dkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=test.com; q=dns/txt; s=test; bh=JoUnmFfUn+vm4KlP33Un/omM8cqeDtMRKBn4rKaJq0U=; h=from; b=');
      })
    })

  })



})
