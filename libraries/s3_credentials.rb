require 'rest-client'
require 'json'


module S3Credentials

  # Returns "best" S3 credentials based on presence (or absence) of
  # access key information in the parameters that are passed.
  # Params:
  # +aws_access_key_id+:: Standard AWS Access Key ID (can be nil)
  # +aws_secret_access_key+:: Standard AWS secret access key (can be nil)
  # +token+:: AWS access token (can be nil)
  #
  # If all parameters are nil, this method will attempt to extract
  # credentials from an EC2 Instance Profile. If that fails, exceptions everywhere.
  def self.get_s3_credentials(aws_access_key_id, aws_secret_access_key, token)
    if aws_access_key_id.nil? && aws_secret_access_key.nil? && token.nil?
      return get_credentials_from_instance_profile()
    else
      return {:aws_access_key_id => aws_access_key_id, :aws_secret_access_key => aws_secret_access_key, :token => token}
    end
  end

  # Helper method to extract S3 credentials from EC2 Instance Profile.
  # Params: +none+
  #
  # If not on EC2 or no Instance Profiles are found, raises an exception.
  def self.get_credentials_from_instance_profile()
    instance_profile_base_url = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
    begin
      instance_profiles = RestClient.get(instance_profile_base_url)
    rescue RestClient::ResourceNotFound, Errno::ETIMEDOUT # we can either 404 on an EC2 instance, or timeout on non-EC2
      raise ArgumentError.new 'No credentials provided and no instance profile on this machine.'
    end
    instance_profile_name = instance_profiles.split.first
    instance_profile = JSON.load(RestClient.get(instance_profile_base_url + instance_profile_name))

    aws_access_key_id = instance_profile['AccessKeyId']
    aws_secret_access_key = instance_profile['SecretAccessKey']
    token = instance_profile['Token']

    return {:token => token, :aws_access_key_id => aws_access_key_id, :aws_secret_access_key => aws_secret_access_key}
  end
end
