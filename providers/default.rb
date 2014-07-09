require 'digest/md5'
require 'rest-client'
require 'json'

use_inline_resources

action :create do
  download = true

  # handle key specified without leading slash
  remote_path = ::File.join('', new_resource.remote_path)

  # Decryption key, provided if necessary
  decryption_key = new_resource.decryption_key

  # we need credentials to be mutable
  s3auth = S3Credentials::get_s3_credentials(new_resource.aws_access_key_id, new_resource.aws_secret_access_key, new_resource.token)
  token = s3auth[:token]
  aws_access_key_id = s3auth[:aws_access_key_id]
  aws_secret_access_key = s3auth[:aws_secret_access_key]

  if ::File.exists?(new_resource.path)
    if decryption_key.nil?
      if new_resource.decrypted_file_checksum.nil?
        s3_md5 = S3FileLib::get_md5_from_s3(new_resource.bucket, remote_path, aws_access_key_id, aws_secret_access_key, token)

        if S3FileLib::verify_md5_checksum(s3_md5, new_resource.path)
          Chef::Log.debug 'Skipping download, md5sum of local file matches file in S3.'
          download = false
        end
      #we have a decryption key so we must switch to the sha256 checksum
      else
        if S3FileLib::verify_sha256_checksum(new_resource.decrypted_file_checksum, new_resource.path)
          Chef::Log.debug 'Skipping download, sha256 of local file matches recipe.'
          download = false
        end
      end
      # since our resource is a decrypted file, we must use the
      # checksum provided by the resource to compare to the local file
    else
      unless new_resource.decrypted_file_checksum.nil?
        if S3FileLib::verify_sha256_checksum(new_resource.decrypted_file_checksum, new_resource.path)
          Chef::Log.debug 'Skipping download, sha256 of local file matches recipe.'
          download = false
        end
      end
    end
  end

  if download
    response = S3FileLib::get_from_s3(new_resource.bucket, remote_path, aws_access_key_id, aws_secret_access_key, token)

    # not simply using the file resource here because we would have to buffer
    # whole file into memory in order to set content this solves
    # https://github.com/adamsb6/s3_file/issues/15
    unless decryption_key.nil?
      begin
        decrypted_file = S3FileLib::aes256_decrypt(decryption_key,response.file.path)
      rescue OpenSSL::Cipher::CipherError => e

        Chef::Log.error("Error decrypting #{name}, is decryption key correct?")
        Chef::Log.error("Error message: #{e.message}")

        raise e
      end

      ::FileUtils.mv(decrypted_file.path, new_resource.path)
    else
      ::FileUtils.mv(response.file.path, new_resource.path)
    end
  end

  f = file new_resource.path do
    action :create
    owner new_resource.owner || ENV['user']
    group new_resource.group || ENV['user']
    mode new_resource.mode || '0644'
  end

  new_resource.updated_by_last_action(download || f.updated_by_last_action?)
end
