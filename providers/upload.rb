require 'digest/md5'
require 'rest-client'

def whyrun_supported?
  true
end

use_inline_resources

action :upload do

  if @current_resource.exists
    remote_md5 = S3FileLib::get_md5_from_s3(@current_resource.bucket,
                                            @current_resource.remote_path,
                                            @current_resource.aws_access_key_id,
                                            @current_resource.aws_secret_access_key,
                                            @current_resource.token)

    if S3FileLib.verify_md5_checksum(remote_md5, @current_resource.path)
      Chef::Log.info("File at #{@current_resource.path} matches MD5 of file at S3 bucket: #{@current_resource.bucket}::#{@current_resource.remote_path}. Nothing to do.")
      do_upload = false
    else
      Chef::Log.info("File at #{@current_resource.path} does not match MD5 of file at S3 bucket: #{@current_resource.bucket}. Will upload file to #{@current_resource.remote_path}.")
      do_upload = true
    end
  else # @current_resource does not exist
    Chef::Log.info("No file found at S3 bucket: #{@current_resource.bucket}, with path #{@current_resource.remote_path}. Will upload file #{@current_resource.path}.")
    do_upload = true
  end

  if do_upload
    converge_by("Upload file #{@current_resource.path} to S3 bucket '#{@current_resource.bucket}', with path '#{@current_resource.remote_path}'") do
      local_md5_base64 = Digest::MD5.file(@current_resource.path).base64digest
      response = S3FileLib.push_to_s3(@current_resource.bucket,
                                      @current_resource.remote_path,
                                      @current_resource.aws_access_key_id,
                                      @current_resource.aws_secret_access_key,
                                      @current_resource.token,
                                      @current_resource.path,
                                      local_md5_base64,
                                      @current_resource.content_type)
    end
  end

end

def load_current_resource
  @current_resource = Chef::Resource::S3FileUpload.new(@new_resource.name)
  @current_resource.name(@new_resource.name)
  @current_resource.bucket(@new_resource.bucket)
  @current_resource.path(@new_resource.path)

  # Some notes about the remote_path logic:
  # - If remote_path doesn't start with a '/' character, one is added.
  # - If remote_path ends with a '/' character, it is assumed to be a directory
  #   and the filename is appended to remote_path.
  # - If remote_path doesn't end with a '/', it is assumed to be the target filename
  #   that should be updated and remains unmodified.
  #
  filename = ::File.basename(@current_resource.path)
  remote_path = @new_resource.remote_path
  remote_path = "/#{remote_path}" unless remote_path.chars.first == '/'
  remote_path = "#{remote_path}#{filename}" if remote_path.chars.to_a.last == '/'
  @current_resource.remote_path(remote_path)

  # Intelligent setting of credentials
  s3auth = S3Credentials::get_s3_credentials(new_resource.aws_access_key_id, new_resource.aws_secret_access_key, new_resource.token)
  @current_resource.token(s3auth[:token])
  @current_resource.aws_access_key_id(s3auth[:aws_access_key_id])
  @current_resource.aws_secret_access_key(s3auth[:aws_secret_access_key])

  @current_resource.content_md5(@new_resource.content_md5)
  @current_resource.content_type(@new_resource.content_type)

  if S3FileLib::file_exists?(@current_resource.bucket,
                             @current_resource.remote_path,
                             @current_resource.aws_access_key_id,
                             @current_resource.aws_secret_access_key,
                             @current_resource.token)
    @current_resource.exists = true
  end
end
