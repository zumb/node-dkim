/**
 * Canonicalize the message header according to
 * methods defined in RFC[XXXX]
 * @memberOf DKIM
 * @param {Buffer|String} header
 * @param {Array} signHeaders
 * @param {String} method - (simple|relaxed)
 * @return {String}
 * @throws {Error} If canonicalization method is unsupported
 */
function processHeader( headers, signHeaders, method ) {

  if( typeof signHeaders === 'string' ) {
    method = signHeaders
    signHeaders = null
  }

  method = method || 'simple'

  if( method !== 'simple' && method !== 'relaxed' ) {
    throw new Error( 'Canonicalization method "' + method + '" not supported' )
  }

  if( signHeaders != null ) {
    signHeaders = signHeaders.map( function( header ) {
      return header.toLowerCase()
    })
    headers = signHeaders.map( function( header ) {
      let content = headers.find(item => item.trim().toLowerCase().indexOf(header) === 0);
      if (header === 'dkim-signature') {
        content = content.substr(0, content.indexOf(' b=') + 3);
      }
      return content;
    })
  }

  if( method === 'simple' ) {
    return headers.join( '\r\n' )
  }

  // TODO: Something's not right here...
  // relaxed signatures still don't verify
  if( method === 'relaxed' ) {
    return headers.map( function( line ) {

      var lines = {}
      var colon = line.indexOf( ':' )
      var value = line.slice( colon )

      // Convert all header field names to lowercase
      var key = line.slice( 0, colon ).toLowerCase()

      // Unfold all header field continuation lines
      value = value.replace( /\r\n(?=[\x20\x09])/g, '' )
      // Convert all sequences of one or more WSP characters to a single SP
      value = value.replace( /[\x20\x09]+/g, ' ' )
      // Delete all WSP characters at the end of each unfolded header field
      value = value.replace( /[\x20\x09]+$/g, '' )

      // Delete any WSP characters remaining before and after the colon
      return ( key + value ).replace( /[\x20\x09]*[:][\x20\x09]*/, ':' )

    }).join( '\r\n' )
  }

}

module.exports = processHeader
