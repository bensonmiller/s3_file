actions :upload
default_action :upload if defined?(default_action) # Chef > 10.8

def initialize(*args)
  super
  @resource_name = :s3_file_upload
  @action = :upload
end

attribute :path, :kind_of => String, :name_attribute => true
attribute :remote_path, :kind_of => String
attribute :bucket, :kind_of => String
attribute :aws_access_key_id, :kind_of => String, :default => nil
attribute :aws_secret_access_key, :kind_of => String, :default => nil
attribute :token, :kind_of => String, :default => nil
attribute :content_md5, :kind_of => String, :default => nil
attribute :content_type, :kind_of => String, :default => 'binary/octet-stream'
# attribute :encryption_key, :kind_of => String, :default => nil
# attribute :encrypted_file_checksum, :kind_of => String, :default => nil
attr_accessor :exists
