#
# Author: David T. Nguyen
# Email: dave122@gmail.com
# Description: Validates whether authentication cookies dropped by
#   Facebook, Twitter, and LinkedIn during client-side authentication
#   is valid based on the applications consumer_secret (private_key).
#   Useful for when your app does client-side authentication and you want
#   to log the user in server side.
#
# Instructions: 
#
# Inputs: 
#   consumer_secret   :   The private key for the application
#   cooke             :   String value stored in cookie, as is.
#
# Output:
#   returns true if cookie is valid
#   returns false if cookie is false
#

require "json"
require "cgi"
require "digest/sha1"
require "digest/md5"
require 'openssl'

module SocialCookieValidator

  LINKEDIN_COOKIE_VERSION = "1";
  LINKEDIN_SIGNATURE_METHOD = "HMAC-SHA1"

  
  # For more technical information
  # http://developers.facebook.com/docs/guides/web/#personalization
  def validate_facebook_cookie( consumer_secret, cookie )
    
    # Parse the cookie to a more useable form
    params = Hash[*CGI.parse(cookie.gsub(/^"|"$/, '')).sort.flatten]

    # Get the cookie signature
    sig = params["sig"]
    
    # Generates the signature base
    signature_base = ''
    params.sort.each do |pair|
      key, value = pair
      signature_base = signature_base + "#{key}=#{value}" if key != "sig"
    end
    
    # returns whether or not signature matches the consumer secret
    return sig == Digest::MD5.hexdigest(signature_base + consumer_secret )
  
  end

  def extract_uid_from_facebook_cookie(cookie)
    # Parse the cookie to a more useable form
    params = Hash[*CGI.parse(cookie.gsub(/^"|"$/, '')).sort.flatten]
    params["uid"]
  end

  # For more informationi:
  # http://dev.twitter.com/anywhere/begin
  def validate_twitter_cookie( consumer_secret, cookie )
    
    # Parse the cookie to a more useable form
    params = cookie.split(':')

    # raise any errors we might find
    raise "error in twitter signature" if params.size() != 2
    
    # Get the cookie signature
    sig = params[1];
    
    # Generates the signature base
    signature_base = params[0]
    
    # returns whether or not signature matches the consumer secret
    return sig == Digest::SHA1.hexdigest( signature_base + consumer_secret )
  
  end

  def extract_uid_from_twitter_cookie(cookie)
    # Parse the cookie to a more useable form
    params = cookie.split(':')
    # raise any errors we might find
    raise "error in twitter signature" if params.size() != 2
    params[0]    
  end

  # For more information:
  # http://developer.linkedin.com/docs/DOC-1252
  def validate_linkedin_cookie( consumer_secret, cookie )
    
    # Parse the cookie to a more useable form
    params = JSON::parse(cookie)

    # raise any errors we might find
    raise "unsupported linkedin cookie version" if params["signature_version"] != "1"
    raise "unsupported encryption scheme" if params["signature_method"] != LINKEDIN_SIGNATURE_METHOD

    # Get the cookie signature
    sig = params["signature"]

    # Generates the signature base
    signature_base = ''
    params["signature_order"].each do |field|
      signature_base = signature_base + params[field]
    end
    
    return sig == Base64.encode64(OpenSSL::HMAC.digest('sha1',consumer_secret, signature_base)).chomp() 
    
  end

  def extract_uid_from_linkedin_cookie(cookie)
    # Parse the cookie to a more useable form
    params = JSON::parse(CGI::unescape(cookie))
    return params["member_id"]
  end

end
