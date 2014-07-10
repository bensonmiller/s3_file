actions :create, :upload
default_action :create if defined?(default_action) # Chef > 10.8

attribute :path, :kind_of => String, :name_attribute => true
attribute :remote_path, :kind_of => String
attribute :bucket, :kind_of => String
attribute :aws_access_key_id, :kind_of => String, :default => nil
attribute :aws_secret_access_key, :kind_of => String, :default => nil
attribute :token, :kind_of => String, :default => nil
attribute :owner, :kind_of => String, :default => nil
attribute :group, :kind_of => String, :default => nil
attribute :mode, :kind_of => [String, Integer], :default => nil
attribute :decryption_key, :kind_of => String, :default => nil
attribute :decrypted_file_checksum, :kind_of => String, :default => nil

# Needed to support :upload action
attribute :content_md5, :kind_of => String, :default => nil
attribute :content_type, :kind_of => String, :default => 'binary/octet-stream'
# TODO: Integrate encryption for file upload
# attribute :encryption_key, :kind_of => String, :default => nil
# attribute :encrypted_file_checksum, :kind_of => String, :default => nil

attr_accessor :exists_in_s3

# Needed for Chef versions < 0.10.10
def initialize(*args)
  super
  @action = :create
end
