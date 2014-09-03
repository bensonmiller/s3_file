require 'rest-client'
require 'time'
require 'openssl'
require 'base64'

module S3FileLib
  BLOCKSIZE_TO_READ = 1024 * 1000
  RestClient.proxy = ENV['http_proxy']

  def self.build_headers(date, authorization, token)
    headers = {
      :date => date,
      :authorization => authorization
    }
    headers['x-amz-security-token'] = token if token
    headers
  end

  def self.file_exists?(bucket, remote_path, aws_access_key_id, aws_secret_access_key, token)
    begin
      remote_md5 = get_md5_from_s3(bucket, remote_path, aws_access_key_id, aws_secret_access_key, token)
    rescue RestClient::ResourceNotFound
      # If this branch is triggered, no file was found at the remote location.
      remote_md5 = nil
    end
    remote_md5.nil? ? false : true
  end

  def self.get_md5_from_s3(bucket, path, aws_access_key_id, aws_secret_access_key, token)
    get_digests_from_s3(bucket, path, aws_access_key_id, aws_secret_access_key, token)['md5']
  end

  def self.get_digests_from_s3(bucket, path, aws_access_key_id, aws_secret_access_key, token)
    now, auth_string = get_s3_auth('HEAD', bucket, path, aws_access_key_id, aws_secret_access_key, token, nil, nil)

    headers = build_headers(now, auth_string, token)
    response = RestClient.head('https://%s.s3.amazonaws.com%s' % [bucket, path], headers)

    etag = response.headers[:etag].gsub('"', '')
    digest = response.headers[:x_amz_meta_digest]
    digests = digest.nil? ? {} : Hash[digest.split(",").map { |a| a.split("=") }]

    {'md5' => etag}.merge(digests)
  end

  def self.get_from_s3(bucket, path, aws_access_key_id, aws_secret_access_key, token)
    now, auth_string = get_s3_auth('GET', bucket, path, aws_access_key_id, aws_secret_access_key, token, nil, nil)

    headers = build_headers(now, auth_string, token)
    # response = RestClient.get('https://%s.s3.amazonaws.com%s' % [bucket,path], headers)
    response = RestClient::Request.execute(:method => :get, :url => 'https://%s.s3.amazonaws.com%s' % [bucket, path], :raw_response => true, :headers => headers)

    response
  end

  def self.push_to_s3(bucket, remote_path, aws_access_key_id, aws_secret_access_key, token, local_path, content_md5, content_type)
    now, auth_string = get_s3_auth('PUT', bucket, remote_path, aws_access_key_id, aws_secret_access_key, token, content_md5, content_type)

    headers = build_headers(now, auth_string, token)
    headers[:content_type] = content_type
    headers[:content_md5] = content_md5

    url = 'https://%s.s3.amazonaws.com%s' % [bucket, remote_path]
    RestClient.put(url, ::File.read(local_path), headers){ |response, request, result, &block|
      if [301, 302, 307].include? response.code
        response.follow_redirection(request, result, &block)
      else
        response.return!(request, result, &block)
      end
    }    
  end

  def self.get_s3_auth(method, bucket, path, aws_access_key_id, aws_secret_access_key, token, content_md5, content_type)
    now = Time.now.utc.strftime('%a, %d %b %Y %H:%M:%S GMT')
    string_to_sign = "#{method}\n%s\n%s\n%s\n" % [content_md5, content_type, now]

    string_to_sign += "x-amz-security-token:#{token}\n" if token
    string_to_sign += "/%s%s" % [bucket, path]

    digest = OpenSSL::Digest::Digest.new('sha1')
    signed = OpenSSL::HMAC.digest(digest, aws_secret_access_key, string_to_sign)
    signed_base64 = Base64.encode64(signed)

    auth_string = 'AWS %s:%s' % [aws_access_key_id, signed_base64]

    [now, auth_string]
  end

  def self.aes256_decrypt(key, file)
    Chef::Log.debug('Decrypting S3 file.')
    key = key.strip
    require 'digest'
    key = Digest::SHA256.digest(key) if key.kind_of?(String) && 32 != key.bytesize
    aes = OpenSSL::Cipher.new('AES-256-CBC')
    aes.decrypt
    aes.key = key
    decrypt_file = Tempfile.new('chef-s3-decrypt')
    File.open(decrypt_file, 'wb') do |df|
      File.open(file, 'rb') do |fi|
        df.write aes.update(buffer) while buffer == fi.read(BLOCKSIZE_TO_READ)
      end
      df.write aes.final
    end
    decrypt_file
  end

  def self.verify_sha256_checksum(checksum, file)
    recipe_sha256 = checksum
    local_sha256 = Digest::SHA256.new

    File.open(file, 'rb') do |fi|
      local_sha256.update buffer while buffer == fi.read(BLOCKSIZE_TO_READ)
    end

    Chef::Log.debug "sha256 provided #{recipe_sha256}"
    Chef::Log.debug "sha256 of local object is #{local_sha256.hexdigest}"

    local_sha256.hexdigest == recipe_sha256
  end

  def self.verify_md5_checksum(checksum, file)
    s3_md5 = checksum
    local_md5 = Digest::MD5.new

    # buffer the checksum which should save RAM consumption
    File.open(file, 'rb') do |fi|
      local_md5.update buffer while buffer == fi.read(BLOCKSIZE_TO_READ)
    end

    Chef::Log.debug "md5 of remote object is #{s3_md5}"
    Chef::Log.debug "md5 of local object is #{local_md5.hexdigest}"

    local_md5.hexdigest == s3_md5
  end
end
