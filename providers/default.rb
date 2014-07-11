require 'digest/md5'
require 'rest-client'
require 'json'

use_inline_resources

def whyrun_supported?
  true
end

action :create do
  download = true

  # Decryption key, provided if necessary
  decryption_key = new_resource.decryption_key

  # Credentials are set through the load_current_resource method
  token = @current_resource.token
  aws_access_key_id = @current_resource.aws_access_key_id
  aws_secret_access_key = @current_resource.aws_secret_access_key

  # The remote_path param is also set intelligently through load_current_resource
  remote_path = @current_resource.remote_path

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
  else
    # Setting the 'remote_must_exist' to false will prevent exceptions
    # if the specified key (file) doesn't exist on S3.
    unless new_resource.remote_must_exist
      download = false
      Chef::Log.warn("Skipping creation of s3_file. Attribute 'remote_must_exist' is set to false and no file found in S3 bucket '#{new_resource.bucket}' at path '#{remote_path}'.")
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
    only_if { ::File.exist?(new_resource.path) }
  end

  new_resource.updated_by_last_action(download || f.updated_by_last_action?)
end


action :upload do

  # Credentials are set through the load_current_resource method
  token = @current_resource.token
  aws_access_key_id = @current_resource.aws_access_key_id
  aws_secret_access_key = @current_resource.aws_secret_access_key

  # The remote_path param is also set intelligently through load_current_resource
  remote_path = @current_resource.remote_path

  if @current_resource.exists_in_s3
    remote_md5 = S3FileLib::get_md5_from_s3(new_resource.bucket,
                                            remote_path,
                                            aws_access_key_id,
                                            aws_secret_access_key,
                                            token)

    if S3FileLib.verify_md5_checksum(remote_md5, new_resource.path)
      Chef::Log.debug("Skipping upload; md5 of #{new_resource.path} matches file at S3 bucket: #{new_resource.bucket}::#{remote_path}.")
      do_upload = false
    else
      Chef::Log.debug("File at #{new_resource.path} does not match MD5 of file at S3 bucket: #{new_resource.bucket}. Will upload file to #{remote_path}.")
      do_upload = true
    end
  else # @current_resource does not exist
    Chef::Log.debug("No file found at S3 bucket: #{@current_resource.bucket}, with path #{@current_resource.remote_path}. Will upload file #{@current_resource.path}.")
    do_upload = true
  end

  if do_upload
    converge_by("Upload file #{new_resource.path} to S3 bucket '#{new_resource.bucket}', with path '#{remote_path}'") do
      local_md5_base64 = Digest::MD5.file(new_resource.path).base64digest
      response = S3FileLib.push_to_s3(new_resource.bucket,
                                      remote_path,
                                      aws_access_key_id,
                                      aws_secret_access_key,
                                      token,
                                      new_resource.path,
                                      local_md5_base64,
                                      new_resource.content_type)
    end
  end

end

def load_current_resource
  @current_resource = Chef::Resource::S3File.new(@new_resource.name)
  @current_resource.name(@new_resource.name)
  @current_resource.bucket(@new_resource.bucket)
  @current_resource.path(@new_resource.path)

  filename = ::File.basename(@current_resource.path)
  remote_path = @new_resource.remote_path
  remote_path = "/#{remote_path}" unless remote_path.chars.first == '/'
  @current_resource.remote_path(remote_path)

  # Intelligent setting of credentials
  s3auth = S3Credentials::get_s3_credentials(@new_resource.aws_access_key_id, @new_resource.aws_secret_access_key, @new_resource.token)
  @current_resource.token(s3auth[:token])
  @current_resource.aws_access_key_id(s3auth[:aws_access_key_id])
  @current_resource.aws_secret_access_key(s3auth[:aws_secret_access_key])

  # If we're uploading, determine whether the upload target already exists on S3.
  if %w{upload}.include?(@action.to_s)
    if S3FileLib::file_exists?(@current_resource.bucket,
                               @current_resource.remote_path,
                               @current_resource.aws_access_key_id,
                               @current_resource.aws_secret_access_key,
                               @current_resource.token)
      @current_resource.exists_in_s3 = true
    end
  end
end
